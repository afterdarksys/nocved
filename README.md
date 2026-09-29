# nocved

Continuous host behaviour sensor (`nocved`) and central store (`nocve-store`)
for the AfterDark fleet. Built after incident 2026-09-29 (leaked root
passwords, secret hunting, `.bash_history -> /dev/null`, auth.log scrubbing,
proxyware containers named like systemd daemons, XMRig in `/opt/.cache`).
Read `DESIGN.md` first: threat model, event model, chain/HMAC, rollout, and
what it does NOT protect against.

Status: MVP, never deployed, nothing committed.

## Layout

| Path | What |
|---|---|
| `crates/nocve-proto` | event schema, hash chain + HMAC, key tokens, cmdline masking, `data/indicators.json` |
| `crates/nocved` | sensor: sources (`process`, `net`, `authlog`, `docker`, `packages`, `persistence`), spool, shipper |
| `crates/nocve-store` | store: HTTP API, chain verification, alerts, SQLite, key/admin CLI |
| `crates/nocve-store/tests/incident_replay.rs` | end-to-end replay of the incident over 127.0.0.1 |
| `crates/nocve-store/tests/chain_tamper.rs` | modified/dropped/replayed/reordered/wrong-key negatives |
| `deploy/` | `nocved.service`, `nocve-store.service`, `install.sh`, `config.example.json`, Ansible skeleton |
| `scripts/measure.sh` | CPU/RSS sampling on a test host |

## Commands

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo build --release --locked
cargo deny check
```

The toolchain is pinned to 1.97.1 (`rust-toolchain.toml`). On this Mac the
Homebrew `cargo` in `/usr/local/bin` shadows rustup; use
`rustup run 1.97.1 cargo ...` to get the pinned compiler.

## Store operations

```bash
nocve-store admin mint --label ryan --db /var/lib/nocve-store/nocve.db   # admin token, shown once
nocve-store keys mint --host ns2 --db /var/lib/nocve-store/nocve.db      # host key, shown once
nocve-store keys revoke --host ns2
nocve-store serve --db /var/lib/nocve-store/nocve.db --bind 127.0.0.1:8750

curl -H "Authorization: Bearer $ADMIN" https://nocve.afterdarksys.com/v1/alerts
curl -H "Authorization: Bearer $ADMIN" https://nocve.afterdarksys.com/v1/hosts
curl -H "Authorization: Bearer $ADMIN" "https://nocve.afterdarksys.com/v1/hosts/ns2/events?since=0&kind=ssh.auth"
```

## Sensor install (on a test host first)

```bash
./install.sh --binary ./nocved-linux-amd64 --sha256 <hex> \
  --url https://nocve.afterdarksys.com --key-stdin < /dev/tty
nocved check --config /etc/nocved/config.json   # polls every source once, sends nothing
```
