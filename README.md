# nocved

Continuous host behaviour sensor (`nocved`) and central store (`nocve-store`)
for the AfterDark fleet. Built after incident 2026-09-29 (leaked root
passwords, secret hunting, `.bash_history -> /dev/null`, auth.log scrubbing,
proxyware containers named like systemd daemons, XMRig in `/opt/.cache`).
Read `DESIGN.md` first: threat model, event model, chain/HMAC, rollout, and
what it does NOT protect against.

Status: MVP, never deployed. Committed on `main` through the auditd execve
source (`65b9d25`). The 2026-10-01 security-review fixes (C1, H1-H3, M1-M8, most
LOW items) are in the working tree, not committed yet. The forward-secure key
ratchet and HMAC request signing are still deferred (DESIGN.md sections 8, 17).
Also uncommitted: the cross-repo end-to-end fixes (feed skip counters in the
heartbeat and coverage, IPv6 `local_ip`/`local_port`, the feed rotation hold)
and the darksignal alert forwarder (`nocve-store forward`).

## Layout

| Path | What |
|---|---|
| `crates/nocve-proto` | event schema, hash chain + HMAC, key tokens, cmdline masking, `data/indicators.json` |
| `crates/nocved` | sensor: sources (`process`, `net`, `authlog`, `docker`, `packages`, `persistence`, `auditd`), spool, shipper |
| `crates/nocve-store` | store: HTTP API, chain verification, alerts, SQLite, key/admin CLI |
| `crates/nocve-store/tests/incident_replay.rs` | end-to-end replay of the incident over 127.0.0.1 |
| `crates/nocve-store/tests/chain_tamper.rs` | modified/dropped/replayed/reordered/wrong-key negatives |
| `crates/nocve-store/tests/review_fixes.rs` | negatives for the 2026-10 review: malformed paths, quotas, alert rate limits, attested rewrite, heartbeat replay, alert cursor, key rotation |
| `crates/nocve-store/tests/forward.rs` | alert forwarder against a fake darksignal socket: frame, cursor restart, refusal, backoff, oversize |
| `crates/nocve-store/src/forward.rs` | `nocve-store forward`: alerts to the local darksignal socket (DESIGN.md section 15) |
| `crates/nocved/src/feed.rs` | optional read-only envelope feed for cveguard (off by default, DESIGN.md section 21) |
| `deploy/` | `nocved.service`, `nocve-store.service`, `nocve-store-forward.service`, `install.sh`, `config.example.json`, `audit/nocved.rules`, Ansible skeleton |
| `crates/nocve-proto/src/cli.rs` | CLI output contract: JSON envelope, error line, status files |
| `crates/nocved/tests/cli.rs`, `crates/nocve-store/tests/cli.rs` | `--json`, error, help and status tests for both binaries |
| `docs/output-contract.md` | After Dark CLI output contract (v1) |
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
nocve-store keys revoke --host ns2                    # every key of ns2 minted up to now
nocve-store keys revoke --host ns2 --key-id OLD_ID    # rotation: OLD_ID and older; keeps the new key
nocve-store serve --db /var/lib/nocve-store/nocve.db --bind 127.0.0.1:8750 \
  [--host-daily-bytes N] [--host-daily-rows N] [--host-daily-alerts N] [--alert-burst N]

# Poll alerts by the store's own id (store-assigned, monotonic). `since` filters on
# occurred_at_ms, which is the sensor clock for event alerts: do not page with it.
curl -H "Authorization: Bearer $ADMIN" "https://nocve.afterdarksys.com/v1/alerts?after_id=0"
curl -H "Authorization: Bearer $ADMIN" "https://nocve.afterdarksys.com/v1/alerts?after_id=$NEXT&host=ns2"
curl -H "Authorization: Bearer $ADMIN" https://nocve.afterdarksys.com/v1/hosts
curl -H "Authorization: Bearer $ADMIN" "https://nocve.afterdarksys.com/v1/hosts/ns2/events?since=0&kind=ssh.auth"
curl https://nocve.afterdarksys.com/healthz           # unauthenticated liveness: {"ok":true}
```

## Alert forwarder (darksignal, store mode)

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin nocve-store   # fixed uid for darksignal
nocve-store forward --db /var/lib/nocve-store/nocve.db \
  --darksignal-socket /run/darksignal-store/darksignal.sock \
  --cursor /var/lib/nocve-store/forward.cursor [--host NAME] [--status PATH]
nocve-store status            # reads /var/lib/nocve-store/forward.status.json
```

Run it as `deploy/nocve-store-forward.service` (`User=nocve-store`,
`SupplementaryGroups=darksignal-producers`, no network). Every alert is sent
once, in id order, as one length-prefixed frame whose `body` is the row
`GET /v1/alerts` returns. Ack `0x01` or `0x00` (refused, counted) advances the
0600 cursor; no ack backs off up to 5 min and retries the same alert. In
darksignal's store-mode config, add
`"nocve-store": {"exe": "/usr/local/bin/nocve-store", "uid": <id -u nocve-store>}`
to `producers` and set `socket_gid` to the `darksignal-producers` gid.
DESIGN.md section 15 has the details.

`/healthz` is the only unauthenticated GET. It says the HTTP workers answer; it
does not check the database or any host. Every `/v1/...` GET needs the admin
token, which is checked before the path is parsed. `/v1/alerts` returns
`next_after_id`; pass it back as `after_id`. `host=NAME` returns that host's
alerts plus fleet-wide ones (`host: null`, e.g. `fleet.password_sweep`).

## Sensor install (on a test host first)

```bash
./install.sh --binary ./nocved-linux-amd64 --sha256 <hex> \
  --url https://nocve.afterdarksys.com --key-stdin < /dev/tty
nocved check --config /etc/nocved/config.json   # polls every source once, sends nothing
nocved status --config /etc/nocved/config.json  # local status file, `stale` if the sensor stopped writing
```

`install.sh` also installs `deploy/audit/nocved.rules` (an `execve` audit
rule) into `/etc/audit/rules.d/` when auditd is present and loads it with
`augenrules --load`; `--no-audit-rules` skips it. Without that rule the
auditd source reports coverage `partial`. The unit is `Type=notify` with
`WatchdogSec=60`: a poll loop that stops ticking is restarted by systemd.

## CLI output and exit codes

Both binaries follow the After Dark CLI output contract
(`docs/output-contract.md`). Every command takes `--json` (or
`--format json`; `--format text` is the default): stdout then carries
exactly one compact JSON object, newline-terminated, that starts with
`{"schema_version":1,"kind":"<tool>.<command>","tool":"<tool>","tool_version":"<semver>", ...}`.
Logs, progress and warnings go to stderr. No command is machine-primary:
all default to human text. `-h`/`--help` on any command (and `<tool> help
[command]`) prints usage, flags and exit codes and exits 0; `--version` and
`version` print the version.

| Command | Default | `kind` (`--json`) | Exit codes |
|---|---|---|---|
| `nocved run` | daemon (stdout empty) | none; status file below | 1 runtime/config, 2 usage |
| `nocved check` | human | `nocved.check` | 0, 1, 2 |
| `nocved status` | human | `nocved.status` | 0 (also when stale), 1, 2 |
| `nocved version` | human | `nocved.version` | 0, 2 |
| `nocve-store serve` | daemon (stdout empty) | none; status is `GET /healthz` | 1 runtime, 2 usage |
| `nocve-store forward` | daemon (stdout empty) | none; status file below | 1 runtime/config, 2 usage |
| `nocve-store keys mint` | raw token, one line | `nocve-store.keys.mint` (`secret`, `key_id`, `host`, `active_keys`, `warning`) | 0, 1, 2 |
| `nocve-store keys revoke` | human | `nocve-store.keys.revoke` (`revoked`) | 0, 1 (incl. refused), 2 |
| `nocve-store keys list` | human | `nocve-store.keys.list` (`keys`) | 0, 1, 2 |
| `nocve-store admin mint` | raw token, one line | `nocve-store.admin.mint` (`secret`, `token_id`, `label`) | 0, 1, 2 |
| `nocve-store admin revoke` | human | `nocve-store.admin.revoke` (`revoked`) | 0, 1, 2 |
| `nocve-store status` | human | `nocve-store.status` | 0 (also when stale), 1, 2 |
| `nocve-store version` | human | `nocve-store.version` | 0, 2 |
| `help`, `--help` (both) | human | `<tool>.help` (`usage`) | 0 |

Exit codes: 0 success; 1 runtime failure (I/O, database, socket, refused
revoke) and also configuration errors (bad or unreadable config or key);
2 usage error (unknown command or option, missing or invalid value). Before
the contract every failure exited 1; usage errors now exit 2, nothing else
moved. Configuration errors keep 1, not the contract's default 2.

Minted credentials: text mode is unchanged (the raw token alone on stdout,
the key id and rotation warning on stderr), so `deploy/ansible/nocved.yml`
(`nv_minted.stdout | trim`) keeps working. With `--json` the token is only in
the `secret` field and nothing is written to stderr. No secret is ever
written to stderr, to a status file or into an error message.

Errors: in `--json` mode every failure, usage errors included, is one line
on stderr and stdout stays empty:

```json
{"schema_version":1,"kind":"error","tool":"nocve-store","command":"keys.mint","category":"usage","message":"keys mint needs --host","exit_code":2}
```

`command` is the dotted command (`check`, `keys.mint`, ...) or `null` for an
unknown one; `category` is `usage`, `config`, `io`, `refused` or `integrity`
here. In text mode the error is one line, `<tool>: <message>`. Control and
bidi characters in messages are escaped (`\u{1b}`).

Status files (rewritten atomically, 0600, at least every 30 s and on a clean
stop; `kind`, `updated_at_ms`, `interval_ms` plus the daemon's counters):

| Daemon | File | Reader |
|---|---|---|
| `nocved run` | `<state_dir>/status.json` (`/var/lib/nocved/status.json`): state, pid, host, `last_tick_ms`, `last_heartbeat_ok_ms`, `last_ship_ok_ms`, `spool_events`, `spool_bytes`, `dropped_total`, `coverage` | `nocved status [--config PATH]` |
| `nocve-store forward` | `--status PATH`, default `forward.status.json` next to `--cursor` (`/var/lib/nocve-store/forward.status.json`): state, cursor, `accepted`, `refused`, `retried`, `truncated`, `oversized`, `backoff_ms`, `last_progress_ms`, `last_error` | `nocve-store status [--forward-status PATH]` |
| `nocve-store serve` | none | `curl http://127.0.0.1:8750/healthz` |

The readers take no lock and change nothing. They add `stale` (true when
`updated_at_ms` is more than 3 x `interval_ms`, 90 s, old) and `age_ms`. A
SIGTERM from systemd ends `nocved run` without the final `stopped` write
(there is no signal handler), so a stopped sensor shows up as stale
`running`.
