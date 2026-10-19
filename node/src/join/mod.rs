//! Operator join tool (`madar-node join …`, review #29/B10): joining as a Validator, registering session keys, checking candidacy/membership status,
//! renewal and exit — with no test code and no Dev keys.
//!
//! **Deliberate internal separation** (not entangled with running the node; does not import `service`/`command`):
//! - `status`  : pure logic (chain state → phase + next steps + permission gates) with no network and no keys; it is "the protocol from the user's perspective".
//! - `rpc`     : JSON-RPC transport bounded by a timeout and a size cap behind `Transport` (replaceable in tests).
//! - `chain`   : reads chain state via storage keys derived from the Runtime's own types (no manual hashing) and decodes it.
//! - `puzzle`  : solves the Admission puzzle with the actual Pallet functions.
//! - `tx`      : builds and submits the signed transaction.
//! - `account` : the encrypted account file (same format as `madar-keystore`: Argon2id + ChaCha20-Poly1305) and the passphrase.
//! - `cli`     : the only module that knows clap, messages and confirmations; replacing it with another interface does not touch the above.
//! - `sessionkeys`: generates the session keys in the node's Keystore **with the node stopped** (`gen-keys`) and proves their ownership locally
//!   (`register-keys --keys`), with no unsafe RPC.
//! - `backup`  : an encrypted backup of the operator account with a password the user chooses (`export` / `import`).
//!
//! **Secrets:** never printed, logged, or passed as command-line arguments: the account's secret phrase is encrypted in a file, the passphrase comes from a hidden prompt or a file
//! (`--passphrase-file`), and the private session keys never leave the node's Keystore (they are generated inside it: via the local RPC in the older path, or
//! directly into its files with `gen-keys` while the node is stopped).

pub mod account;
pub mod backup;
pub mod chain;
pub mod cli;
pub mod puzzle;
pub mod rotation;
pub mod rpc;
pub mod sessionkeys;
pub mod status;
pub mod tx;

pub use cli::JoinCmd;

pub fn run(cmd: JoinCmd) -> Result<(), String> {
    cli::run(cmd)
}
