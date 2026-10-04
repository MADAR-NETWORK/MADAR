# Madar TxCheck

Reads a Substrate / Polkadot SDK transaction **before** it is signed, explains in plain words what it will
really do, and warns about risks: scam sites and look-alike domains, reported scam addresses, full-control
proxies, unlimited approvals, ownership transfers, transactions disguised as messages (`signRaw`), wrong
network, never-expiring transactions, large tips, admin-only calls and raw XCM. Batches, proxies and
multisigs are unpacked and explained call by call.

- Decodes with each chain's own runtime metadata (v14–v16), fetched over RPC and cached per runtime version.
- Every API answer is signed with Ed25519 over the exact response body (`X-Madar-Signature`, `X-Madar-Key`);
  answers carry `call_hash` so a verdict cannot be reused for another transaction.
- Never sees keys. Does not store or log requests.
- Scam lists: [polkadot-js/phishing](https://github.com/polkadot-js/phishing), refreshed every 6 hours.

Public API, live demo and downloads: https://madar-network.com/txcheck/

```sh
madar-txcheck init                  # write madar-txcheck.toml
madar-txcheck check request.json    # one check, printed
madar-txcheck serve                 # API: POST /v1/check, GET /v1/health, GET /v1/key
```

Request: `{"chain": "polkadot", "payload": <SignerPayloadJSON> | "call": "0x…" | "raw": {"data": "0x…"}, "origin": "https://…", "lang": "en"|"ar"}`
Answer: `verdict` (`ok` / `caution` / `danger`), `headline`, `actions`, `findings[{level, code, message}]`, `calls`, `call_hash`.

`packaging/madar-txcheck.service` is a hardened systemd unit. License: Apache-2.0.
