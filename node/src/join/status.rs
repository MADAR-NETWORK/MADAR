//! Pure logic: from a snapshot of chain state for one account to the user's phase, next steps, and the permission gates for each action. No network and no keys.

use serde::Serialize;

/// What is read from the chain about one account.
#[derive(Debug, Clone, Default)]
pub struct ChainView {
    pub current_session: u32,
    /// In `Admission.Validators` (declared member).
    pub member: bool,
    /// In `Session.Validators` (actual authority now).
    pub active: bool,
    pub expiry: Option<u32>,
    pub banned: bool,
    pub exit_pending: bool,
    /// The account has session keys registered on chain (`Session.NextKeys`).
    pub keys_registered: bool,
    /// Does the node serving the RPC own the matching private keys? `None` = not checked/unavailable.
    pub keys_held_by_node: Option<bool>,
    /// A candidate in the open round or in a closed set awaiting the draw.
    pub candidate: bool,
}

/// Membership and grace durations (from the Runtime constants compiled into this executable).
#[derive(Debug, Clone, Copy)]
pub struct Params {
    pub term: u32,
    pub grace: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Banned,
    /// No membership, no candidacy and no keys (the account most likely does not exist on chain yet).
    NotStarted,
    Candidate,
    /// Has registered keys but is not a candidate now (lost the draw or membership expired).
    KeysOnly,
    Member,
    MemberInGrace,
    Exiting,
}

#[derive(Debug, Clone, Serialize)]
pub struct JoinStatus {
    pub phase: Phase,
    pub current_session: u32,
    pub expiry_session: Option<u32>,
    /// The first session at which membership is removed unless renewed (expiry + grace).
    pub removal_session: Option<u32>,
    pub renewable: bool,
    pub keys_registered: bool,
    pub keys_held_by_node: Option<bool>,
    pub active_authority: bool,
    pub summary: String,
    pub next_steps: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn interpret(v: &ChainView, p: Params) -> JoinStatus {
    let removal = v.expiry.map(|e| e.saturating_add(p.grace));
    // Renewal is accepted only if validity would actually be extended (`AlreadyRenewed` otherwise).
    let renewable = v.member
        && !v.exit_pending
        && v.expiry
            .map_or(false, |e| e < v.current_session.saturating_add(p.term));
    let phase = if v.banned {
        Phase::Banned
    } else if v.member && v.exit_pending {
        Phase::Exiting
    } else if v.member && v.expiry.map_or(false, |e| v.current_session >= e) {
        Phase::MemberInGrace
    } else if v.member {
        Phase::Member
    } else if v.candidate {
        Phase::Candidate
    } else if v.keys_registered {
        Phase::KeysOnly
    } else {
        Phase::NotStarted
    };

    let mut warnings = Vec::new();
    if v.keys_registered && v.keys_held_by_node == Some(false) {
        warnings.push("The session keys registered on chain are not in the Keystore of the node whose RPC is being queried — this node cannot sign. Register new keys (register-keys) on the correct node.".to_string());
    }
    if matches!(
        phase,
        Phase::Candidate | Phase::Member | Phase::MemberInGrace
    ) && !v.keys_registered
    {
        warnings.push("No session keys registered: a seat win will not be accepted without them. Run register-keys now.".to_string());
    }
    if matches!(phase, Phase::Member | Phase::MemberInGrace)
        && v.active
        && v.keys_held_by_node == Some(false)
    {
        warnings.push("You are an active authority but the node does not own the matching keys — you will miss block production and voting.".to_string());
    }

    let (summary, next_steps): (String, Vec<String>) = match phase {
        Phase::Banned => (
            "The key is permanently banned (Equivocation offence) and cannot join or renew.".into(),
            vec!["Use a new account (a new key) if you want to join again.".into()],
        ),
        Phase::NotStarted => (
            "Not started yet: no candidacy, no membership and no session keys for this account.".into(),
            vec![
                "1) join apply — solves the admission puzzle and submits it (this first transaction creates the account on chain; no fees).".into(),
                "2) join register-keys — on the node that will run as Validator, right after step 1 (before the draw).".into(),
                "3) Wait for the draw: the account is not accepted until at least two rotations after the round closes; follow up with join status.".into(),
            ],
        ),
        Phase::Candidate => (
            "You are a candidate: your puzzle was accepted in a round awaiting closing/the draw.".into(),
            if v.keys_registered {
                vec!["Wait for the draw (at least two rotations after closing) and follow up with join status. If you do not win, rerun join apply in a later round.".into()]
            } else {
                vec!["join register-keys now (a winner without keys is not accepted).".into(), "Then wait for the draw and follow up with join status.".into()]
            },
        ),
        Phase::KeysOnly => (
            "Your keys are registered but you are not a candidate now (not selected in the draw, or your membership expired).".into(),
            vec!["join apply — a new puzzle for the current round (the registered keys remain valid).".into()],
        ),
        Phase::Member => (
            format!(
                "Member{}. Your validity expires at session {} and you are removed at {} unless you renew.",
                if v.active { " and an active authority now" } else { " (active authority starts once the session queue rolls over)" },
                v.expiry.map_or("?".into(), |e| e.to_string()),
                removal.map_or("?".into(), |e| e.to_string())
            ),
            if renewable {
                vec!["join renew — you can renew now (extends validity).".into()]
            } else {
                vec!["No renewal needed now (validity is long enough); it becomes renewable after more sessions pass.".into()]
            },
        ),
        Phase::MemberInGrace => (
            format!(
                "**Grace period**: your validity expired (session {}) and your membership is removed at session {} unless you renew.",
                v.expiry.map_or("?".into(), |e| e.to_string()),
                removal.map_or("?".into(), |e| e.to_string())
            ),
            vec!["join renew — now, before removal.".into()],
        ),
        Phase::Exiting => (
            "Voluntary exit registered: it takes effect at the next session rotation, and your authority ends after two rotations.".into(),
            vec!["No action needed. To rejoin later, use join apply once the exit has completed.".into()],
        ),
    };

    JoinStatus {
        phase,
        current_session: v.current_session,
        expiry_session: v.expiry,
        removal_session: removal,
        renewable,
        keys_registered: v.keys_registered,
        keys_held_by_node: v.keys_held_by_node,
        active_authority: v.active,
        summary,
        next_steps,
        warnings,
    }
}

/// Permission gates: prevent submitting a transaction that would be rejected or cause harm, with an understandable message.
pub fn gate_apply(s: &JoinStatus) -> Result<(), String> {
    match s.phase {
        Phase::Banned => Err("The key is permanently banned.".into()),
        Phase::Member | Phase::MemberInGrace => Err("You are already a member — use join renew to renew.".into()),
        Phase::Exiting => Err("Your voluntary exit is registered; wait for it to complete, then try again.".into()),
        Phase::Candidate => Err("You are already a candidate in the current round (a second puzzle for the same round is not accepted).".into()),
        Phase::NotStarted | Phase::KeysOnly => Ok(()),
    }
}

pub fn gate_renew(s: &JoinStatus) -> Result<(), String> {
    match s.phase {
        Phase::Banned => Err("The key is permanently banned.".into()),
        Phase::Exiting => Err("Your voluntary exit is registered; no renewal.".into()),
        Phase::Member | Phase::MemberInGrace if s.renewable => Ok(()),
        Phase::Member | Phase::MemberInGrace => {
            Err("No renewal needed now: your validity is still long enough (early renewal is rejected). Try again after more sessions pass.".into())
        },
        _ => Err("You are not a member — use join apply to join.".into()),
    }
}

pub fn gate_exit(s: &JoinStatus) -> Result<(), String> {
    match s.phase {
        Phase::Member | Phase::MemberInGrace => Ok(()),
        Phase::Exiting => Err("Your exit is already registered.".into()),
        _ => Err("Voluntary exit is for current members only.".into()),
    }
}

pub fn gate_register_keys(s: &JoinStatus) -> Result<(), String> {
    match s.phase {
        Phase::Banned => Err("The key is permanently banned.".into()),
        Phase::NotStarted => Err("The account does not exist on chain yet: run join apply first (solving the puzzle is what creates the account).".into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: Params = Params { term: 4, grace: 2 };
    fn v() -> ChainView {
        ChainView {
            current_session: 10,
            ..Default::default()
        }
    }

    #[test]
    fn a_fresh_account_is_guided_through_apply_then_keys_then_waiting() {
        let s = interpret(&v(), P);
        assert_eq!(s.phase, Phase::NotStarted);
        assert!(
            s.next_steps[0].contains("join apply") && s.next_steps[1].contains("register-keys")
        );
        assert!(gate_apply(&s).is_ok());
        assert!(
            gate_register_keys(&s).unwrap_err().contains("apply"),
            "the account only exists after the puzzle"
        );
        assert!(gate_renew(&s).is_err() && gate_exit(&s).is_err());
    }

    #[test]
    fn a_candidate_without_keys_is_warned_and_cannot_apply_twice() {
        let s = interpret(
            &ChainView {
                candidate: true,
                ..v()
            },
            P,
        );
        assert_eq!(s.phase, Phase::Candidate);
        assert!(s.warnings.iter().any(|w| w.contains("register-keys")));
        assert!(gate_apply(&s).is_err());
        assert!(gate_register_keys(&s).is_ok());
        let ok = interpret(
            &ChainView {
                candidate: true,
                keys_registered: true,
                ..v()
            },
            P,
        );
        assert!(ok.warnings.is_empty());
    }

    #[test]
    fn membership_phases_follow_term_and_grace_and_renewal_is_gated() {
        let mem = |cur, exp| ChainView {
            current_session: cur,
            member: true,
            expiry: Some(exp),
            keys_registered: true,
            ..Default::default()
        };
        let long = interpret(&mem(10, 14), P);
        assert_eq!(long.phase, Phase::Member);
        assert!(
            !long.renewable && gate_renew(&long).unwrap_err().contains("early"),
            "expiry 14 >= 10+4: renewal would be refused"
        );
        let soon = interpret(&mem(11, 14), P);
        assert!(soon.renewable && gate_renew(&soon).is_ok());
        let grace = interpret(&mem(14, 14), P);
        assert_eq!(grace.phase, Phase::MemberInGrace);
        assert_eq!(grace.removal_session, Some(16));
        assert!(grace.summary.contains("Grace period") && gate_renew(&grace).is_ok());
        assert!(gate_apply(&grace).unwrap_err().contains("renew"));
    }

    #[test]
    fn exit_ban_and_key_ownership_warnings() {
        let exiting = interpret(
            &ChainView {
                member: true,
                exit_pending: true,
                expiry: Some(20),
                ..v()
            },
            P,
        );
        assert_eq!(exiting.phase, Phase::Exiting);
        assert!(gate_exit(&exiting).is_err() && gate_renew(&exiting).is_err());
        let banned = interpret(
            &ChainView {
                banned: true,
                member: true,
                ..v()
            },
            P,
        );
        assert_eq!(banned.phase, Phase::Banned, "a ban outranks everything");
        assert!(
            gate_apply(&banned).is_err()
                && gate_renew(&banned).is_err()
                && gate_register_keys(&banned).is_err()
        );
        let wrong = interpret(
            &ChainView {
                keys_registered: true,
                keys_held_by_node: Some(false),
                ..v()
            },
            P,
        );
        assert_eq!(wrong.phase, Phase::KeysOnly);
        assert!(wrong.warnings.iter().any(|w| w.contains("Keystore")));
        assert!(
            gate_apply(&wrong).is_ok(),
            "keys-only accounts re-apply for the current round"
        );
    }

    #[test]
    fn statuses_serialize_for_a_future_ui_without_secrets_or_internal_types() {
        let json = serde_json::to_string(&interpret(&v(), P)).unwrap();
        assert!(json.contains("\"phase\":\"not_started\"") && json.contains("next_steps"));
    }
}
