# nocved design

Status: MVP, not deployed. Author: agent build for Ryan, 2026-09-29.
Motivating incident: `.planning/incidents/2026-09-29-root-password-proxyware/FINDINGS.md`
(afterdarksys.com repo). Every behaviour in that incident must reach the
central store within seconds, before the attacker can hide it.

## 1. Purpose and non-goals

`nocved` is a small, continuous host behaviour sensor. It watches a handful of
cheap, high-signal sources (processes, outbound connections, SSH auth log,
Docker, package installs, persistence locations), turns what it sees into
events with *hints* (signals), hash-chains and MACs them, and pushes them
off-host over HTTPS to `nocve-store`. The store verifies every event, keeps the
history, raises alerts, and is what `aftercve` queries during an investigation.

It is not an EDR, not a blocker, and it never changes host state. It has no
containment actions and no listening port on the host.

## 2. Threat model

Threats: an attacker with root on a fleet host (exactly the 2026-09-29 case:
leaked root passwords, 7 hosts in 20 minutes) who will try to hide what they
did: `.bash_history -> /dev/null`, `sed -i` on `auth.log`, processes and
containers named like kernel threads and system daemons, killing things that
look like monitoring.

**The sensor runs on a host that may already be rooted.** Everything local is
untrusted: the binary, its config, its key, its state and its spool can all be
read, replaced or deleted by root. So the design goal is not "the sensor
cannot be defeated" (it can) but:

1. **Get evidence off-host fast.** Default poll intervals are 2-30 s and the
   shipper pushes as soon as there is something to send. Once an event is in
   the store, nothing on the host can change it.
2. **Make defeating the sensor loud.** Killing it stops heartbeats and the
   store raises `sensor.silent`. Wiping its state starts a new chain epoch and
   the store raises `chain.reset`. Deleting spooled events leaves a sequence
   gap and the store raises `chain.gap`. Rewriting spooled events fails the
   chain or the MAC. Silence is itself an alert.
3. **Never become the leak.** The sensor never ships file contents, environment
   values or unmasked command lines (section 9).

What it protects against:

- Silent after-the-fact editing of local logs: events already shipped are
  immutable in the store; `sed -i` on auth.log is itself detected
  (`authlog.replaced`), and the sensor keeps reading the unlinked inode that
  rsyslog keeps writing to, so the lines the attacker "deleted" still arrive.
- Network tampering / injection between sensor and store: TLS plus a per-event
  HMAC over a hash chain.
- Replay, reordering, dropping, or rewriting of events in transit or in the
  local spool (section 6).
- A sensor that quietly stops: heartbeats and `sensor.silent`.

What it does NOT protect against (read this before trusting it):

- **An attacker who is root before the event** can read the per-host key and
  forge plausible events and heartbeats from that point on. The chain proves
  what the sensor said and in what order, not that it told the truth.
  Forward-secure key evolution (section 17) narrows this to "after the
  compromise"; it is deferred.
- **Kernel rootkits** that hide processes, sockets or files from `/proc` hide
  them from nocved too. `aftercve`'s cross-view comparison (section 14) is the
  counter, and it is still bounded by the shared kernel.
- **Short-lived processes** (< poll interval, default 2 s) are missed by
  `/proc` polling. The auditd execve tail records them when `audit.log` is
  being written (section 11). An eBPF source remains the later path on 6.1.
- **Store compromise.** The store holds the derived MAC key for each host
  (section 7). Someone who reads the store DB can forge MACs for that host's
  chain; they still cannot push without the bearer secret, whose preimage the
  store never stores. Ed25519 per-host signing keys would remove this; see
  section 17.
- A root attacker who also blocks egress to the store before doing anything
  else only gets "sensor silent" – which is the alert we want.
- Containers in their own network namespace are covered (per-netns
  `/proc/<pid>/net/*` reads), but processes inside user namespaces or gVisor-like
  sandboxes may report paths relative to their own root.

## 3. Architecture

```text
host (untrusted)                                  store host (trusted)
+------------------------------------+            +------------------------------+
| nocved (root, systemd, no port)    |  HTTPS     | Traefik (TLS termination)    |
|  sources --> chain+MAC --> spool --+----------->|   -> nocve-store 127.0.0.1   |
|  (poll)      (proto)       (disk)  |  POST only |      SQLite WAL (history,    |
|  heartbeat every 30 s -------------+----------->|      chain state, alerts)    |
+------------------------------------+            +--------------+---------------+
                                                                 | GET (admin token)
                                                     aftercve / operators / alerting
```

- `nocve-proto` (library): event schema, severity/signal model, canonical
  encoding rule, hash chain + HMAC, key token format, secret masking, shared
  indicator data (`data/indicators.json`).
- `nocved` (binary + library): sources, chainer, bounded spool, shipper
  thread, heartbeat, config loader with the host-inventory permission rules.
- `nocve-store` (binary + library): HTTP API, key/admin-token management CLI,
  chain verification, store-side correlation, alerting, retention.

**aftercve queries the store, not the local daemon.** The local daemon has no
query interface on purpose: during an incident its answers would come from the
compromised host. The store's copy was fixed at the time of shipping.

## 4. Sensor internals

One main thread polls sources on their own intervals and appends chained
envelopes to the spool; one shipper thread drains the spool to the store; the
heartbeat is sent by the shipper thread. A slow or unreachable store never
blocks polling.

```rust
pub trait Source {
    fn id(&self) -> &'static str;
    fn interval(&self) -> Duration;
    fn poll(&mut self, now_ms: i64, out: &mut Vec<Event>);
    fn health(&self) -> SourceHealth; // status + detail, reported in heartbeats
}
```

Every source is bounded: per-poll event cap (overflow becomes one
`source.truncated` event), bounded line length, bounded read per poll, bounded
tracking tables. Every source self-reports coverage in the aftercve vocabulary
(`completed | partial | skipped | unsupported | failed`) with a reason; the
heartbeat carries it, `GET /v1/hosts` shows it. "Unsupported" is honest: on
macOS, or on a Debian 12 host without rsyslog (journald only), the auth source
says so instead of looking healthy.

All sources read through a configurable filesystem root (default `/`) so
every parser is tested from fixtures on any OS.

### Sources in the MVP

| Source | Interval | Reads | Emits |
|---|---|---|---|
| `process` | 2 s | `/proc/<pid>/{stat,status,cmdline,exe,cwd,cgroup}` | `process.start`, `process.exit`, `process.cpu` |
| `net` | 5 s | `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` per network namespace, `/proc/*/fd` inode map (when a new public destination, or a TCP listener that appeared after the namespace baseline, is unattributed) | `net.connect` (first time a process-exe talks to a public destination, TTL 1 h); `net.listen` (TCP listener that appears after the first successful sample of that namespace; that first sample is recorded and emits nothing) |
| `authlog` | 2 s | `/var/log/auth.log`, `/var/log/secure` | `ssh.auth`, `ssh.session`, `log.tamper` |
| `docker` | 5 s | `/var/run/docker.sock`: `GET /events?since&until` (finite window), `/containers/json`, `/containers/{id}/json` | `container.seen`, `container.create`, `container.start` |
| `packages` | 5 s | `/var/log/dpkg.log`, `/var/log/apt/history.log` | `package.change`, `package.transaction`, `log.tamper` |
| `persistence` | 30 s | stat + SHA-256 (never file bytes) of cron, anacrontab, at spools (`/var/spool/at`, `/var/spool/cron/atjobs`), systemd unit dirs including `/etc/systemd/user`, `/var/lib/systemd/linger`, and `{home}/.config/systemd/user`, `ld.so.preload` and `ld.so.conf.d`, `authorized_keys`, sshd, account files, sudoers, PAM, shell init (`profile`, `bash.bashrc`, zsh env/rc, `profile.d`), D-Bus system policy, polkit, udev rules, tmpfiles, modprobe; lstat of shell history. An entry cap, a nested-directory cap, or an unreadable directory is partial coverage. Vendor unit trees and `/run` stay with aftercve's one-shot snapshot. | `persistence.baseline`, `persistence.change`, `history.devnull` |
| `auditd` | 2 s | `/var/log/audit/audit.log` | `audit.exec`, `log.tamper` |

Sensor meta events: `sensor.start` (version, boot id, coverage), and
`sensor.events_dropped` (spool overflow count, section 8).

### Signals (hints, not verdicts)

A signal is `{rule, severity, summary}` attached to an event. Final judgement is
in the store (correlation, alert thresholds) and in aftercve. Rules for the
incident (the rule id is stable, versioned by name):

| Incident behaviour | Rule | Sev |
|---|---|---|
| root logs in with a password | `ssh.root_password_login` | high |
| ... with no failure from that IP in the sensor's window (credential known) | `ssh.password_first_try` | high |
| same source IP logs in with a password on >= 3 hosts in 30 min (store) | `fleet.password_sweep` | critical |
| `session opened` for an sshd pid with no `Accepted` line | `authlog.orphan_session` | high |
| auth.log truncated / replaced in place (`sed -i`) / silent while sshd sessions are live | `authlog.truncated`, `authlog.replaced`, `authlog.silent_with_sessions` | high |
| `apt-get install unzip p7zip-full fd-find` | `pkg.secret_hunting_toolkit` (>= 2 tools in one transaction), `pkg.secret_hunting_tool` (one tool; high for trufflehog/gitleaks/masscan/proxychains-class) | high / medium |
| dpkg.log or apt history truncated, replaced in place, deleted, or turned into a symlink | `pkglog.truncated`, `pkglog.replaced`, `pkglog.deleted`, `pkglog.symlink` | high |
| `.bash_history -> /dev/null` | `history.devnull` | high |
| exe under a hidden or temp dir (`/opt/.cache`, `/tmp`, `/dev/shm`, dot-dirs) not on the allowlist | `proc.exe_hidden_dir` | medium |
| name looks like a kernel thread / system daemon but exe outside system dirs (`irqbalance-core`, `rcu-sched-worker`, `kcompactd0` in `/opt/.cache`) | `proc.masquerade` | high |
| exe deleted from disk while running | `proc.exe_deleted` | medium (high if hidden dir) |
| XMRig-style command line (`stratum+tcp://`, `--donate-level`, `-o pool:port`) | `proc.miner_cmdline` | critical |
| sustained CPU > 80 % of a core for 60 s | `proc.high_cpu` | medium; high if the exe is hidden/masquerading |
| connection to a configured mining-pool IP or port | `net.miner_pool_ip` / `net.miner_pool_port` | critical / high |
| TCP listener that was not in the namespace's first sample (pool rules are not applied; UDP listeners are not events) | `net.listen` | medium |
| container named like a system daemon (`dbus-daemon`, `systemd-networkd`, `kworker-events`) | `docker.masquerade_name` | high |
| container image is proxyware/miner (`bitping/*`, `traffmonetizer/*`, `xmrig`) | `docker.proxyware_image` / `docker.miner_image` | critical |
| container inspect says `Privileged` true, or `NetworkMode` is exactly `host` | `docker.privileged` / `docker.host_network` | high |
| new or changed persistence file | `persist.changed` | medium; high for `ld.so.preload` and `ld.so.conf.d`, `authorized_keys`, sudoers, account files, sshd, PAM, D-Bus system policy, polkit, udev, modprobe |
| short-lived exec recorded as `audit.exec` (same process rules as a live process) | `proc.miner_cmdline`, `proc.masquerade`, `proc.exe_hidden_dir` | critical / high / medium |
| audit.log truncated, replaced in place, deleted, or turned into a symlink | `auditlog.truncated`, `auditlog.replaced`, `auditlog.deleted`, `auditlog.symlink` | high |

Negative requirements baked into tests: Playwright's Chromium under
`/root/.cache/ms-playwright/` (allowlisted) does not get any miner/masquerade
signal even at high CPU; a normal `apt upgrade` gets no package signal.

The indicator lists (masquerade names, miner/proxyware images, secret-hunting
packages, pool ports and IPs, hidden-dir allowlist) are one shared data file,
`crates/nocve-proto/data/indicators.json`, compiled in and optionally
overridden by `indicators_file` in the config. Mining pools are matched by IP
and port only; **nocved resolves no names** (a DNS lookup from the sensor would
be both a leak and an attacker-controllable input). Operators add pool IPs to
the IOC list.

## 5. Event model

```json
{"observed_at_ms":1758306579000,"source":"authlog","kind":"ssh.auth",
 "outcome":"accepted","method":"password","user":"root","src_ip":"104.28.205.21",
 "src_port":51234,"sshd_pid":1234,"key_fp":null,"log_time":"Sep 19 18:29:39",
 "signals":[{"rule":"ssh.root_password_login","severity":"high","summary":"..."}]}
```

- `kind` is a dotted string; kinds are a closed Rust enum in the sensor, but
  the store treats the payload as opaque JSON plus a small typed header
  (`kind`, `observed_at_ms`, `signals`), so a newer sensor never breaks an older
  store.
- Times are Unix milliseconds from the sensor clock (untrusted). The store
  records its own `received_at_ms` next to every event; aftercve should
  compare both.
- Raw log timestamps are kept verbatim (`log_time`) because syslog lines have
  no year and may be in local time.

## 6. Tamper evidence: hash chain + HMAC

Per host, per *epoch* (a random 128-bit id chosen when the sensor starts with
no state):

```text
genesis        = SHA256("nocve-genesis-v1" || lp(host) || epoch)
link[n]        = SHA256("nocve-link-v1" || lp(host) || epoch || be64(seq) || prev || lp(payload))
mac[n]         = HMAC-SHA256(mac_key, "nocve-mac-v1" || link[n])
prev for n+1   = link[n]
lp(x)          = be32(len(x)) || x
```

**Canonical encoding rule:** the `payload` is the exact UTF-8 JSON text the
sensor serialised once. Verifiers hash and MAC those bytes and never
re-encode. That removes every canonicalisation ambiguity (key order, number
formatting, unknown fields) without a canonical-JSON dependency.

Store verification of `POST /v1/events` (a batch must be one epoch, strictly
contiguous sequence numbers, <= 500 envelopes, <= 1 MiB):

| Condition | Result |
|---|---|
| bearer secret unknown / revoked | 401, nothing stored |
| envelope `host` differs from the key's host | 403 |
| batch not contiguous / mixed epochs | 400 `batch_not_contiguous` |
| MAC does not verify (modified event, wrong key) | 422 `bad_mac`, alert `chain.bad_mac` |
| `seq < next_seq`, same link hash as stored | idempotent duplicate (a retry after a lost response), 200 |
| `seq < next_seq`, different link hash | 409 `rewrite`, alert `chain.rewrite` |
| `seq < next_seq` inside a recorded gap (late / reordered) | 409 `out_of_order`, alert `chain.out_of_order` |
| `seq == next_seq` but `prev != head` | 409 `chain_mismatch`, alert `chain.mismatch` |
| `seq > next_seq` (events missing) | accepted, gap `[next_seq, seq-1]` recorded, alert `chain.gap` |
| new epoch, starts at seq 0 from genesis | accepted; alert `chain.reset` if the host had an earlier epoch |
| new epoch not starting at 0 / not from genesis | accepted as gap from 0, alert `chain.gap` |

Gaps are accepted rather than rejected on purpose: rejecting would make the
sensor retry forever and we would lose the events that did arrive. Evidence is
kept; the anomaly is recorded.

The sensor never creates a gap itself: events are chained only when they are
written to the spool, and a full spool drops events *before* chaining and later
reports the count in a chained `sensor.events_dropped` event. So any gap at the
store means someone removed spooled events (or the disk failed).

Heartbeats (`POST /v1/heartbeat`) are not in the chain; each carries a strictly
increasing counter (per epoch), the sensor's chain head `(seq, link)`, spool
depth, drop count and source coverage, all MACed. The store rejects a
non-increasing counter (409 `replay`) and alerts when the sensor's claimed head
is *behind* what the store already has (`chain.rollback`: the sensor's state
was restored or forged). "Sensor has events the store has not seen" is normal
backlog and is shown, not alerted.

**Silence:** the store runs a checker every 10 s; a host with no event and no
heartbeat for `silent_after_secs` (default 120 s = 4 missed heartbeats) gets
one `sensor.silent` alert (high), and `sensor.resumed` (medium) when it comes
back. `GET /v1/hosts` computes the silent flag live.

## 7. Keys and tokens

- Host key token: `nvk1.<key_id 16 hex>.<secret 64 hex>`; 256-bit secret and
  64-bit id from the OS CSPRNG (`getrandom`). Minted by
  `nocve-store keys mint --host NAME`, printed once to stdout, never logged.
- The store keeps `key_id`, `host`, `SHA256("nocve-auth-v1" || secret)` and
  the derived MAC key `HMAC-SHA256(secret, "nocve-mac-key-v1")`. Lookup is by
  `key_id`; the secret hash comparison is constant-time (`subtle`). SHA-256
  (not Argon2id) is correct here: the secret is 256 random bits, not a
  password, so there is nothing to brute-force and a slow KDF would only add
  DoS surface. (SECURITY-RULES rule 3 is about passwords.)
- Admin tokens: `nva1.<id>.<secret>`, same storage, separate table, required
  for every GET. Minted with `nocve-store admin mint`.
- Revocation: `keys revoke --key-id` / `--host`; immediate (checked per
  request).
- The sensor sends the token only in `Authorization: Bearer`; never in the URL,
  argv or logs. Logs show a SHA-256 fingerprint of the key id at most.

## 8. Transport, spool, backpressure

- HTTPS push only. The sensor opens no port. URL must be `https://`, except
  `http://127.0.0.1|[::1]|localhost` for tests. System CA store
  (`rustls-platform-verifier`), no redirects, no proxy (environment proxy
  variables ignored), 10 s global timeout, response bodies capped at 64 KiB.
- Spool: append-only JSONL of chained envelopes in `/var/lib/nocved/spool`
  plus `state.json` (epoch, next seq, head, heartbeat counter, acked seq), all
  0600, written atomically (temp + fsync + rename). Default cap 8 MiB; events
  with severity >= high may use a 25 % reserve above the cap. When full, new
  events are dropped before chaining and counted (section 6).
- Shipping: batches of up to 500 envelopes / 1 MiB; on failure exponential
  backoff 1 s .. 60 s with CSPRNG jitter; 429 honours `Retry-After`; a 409 or
  422 batch is moved to a bounded `rejected.jsonl` (kept for aftercve) and
  shipping continues, so one bad batch cannot wedge the sensor.
- Store side: body limit 1 MiB (checked from `Content-Length` before reading
  and enforced while reading), per-host token bucket (default 5 req/s, burst
  20), global unauthenticated bucket, payload <= 64 KiB per event.

## 9. Privacy and secret hygiene

- Never shipped: file contents, environment values (`/proc/<pid>/environ` is
  never opened), key material, shadow hashes.
- Persistence files: SHA-256 digest, size, mode, uid, mtime only.
- Command lines are masked by `nocve_proto::mask` before they leave the
  process that read them: values of `--password/--token/--secret/--key/...`
  flags (both `--flag=v` and `--flag v`), `KEY=value` assignments whose key
  looks secret, URL userinfo (`scheme://user:pass@`), `Authorization:`/`Bearer`
  values, `-p<value>` for mysql-style tools, and anything shaped like a known
  token (`ghp_`, `github_pat_`, `xox?-`, `sk-`, `AKIA`, `eyJ` JWTs, `iak_`,
  `nvk1.`, `nva1.`). Masked values become `<masked>`. Each argument is capped at
  512 bytes, the whole line at 4 KiB. The `chpasswd` pattern from the incident
  (`echo 'root:...' | chpasswd`) runs in a shell whose cmdline is masked by
  the `user:secret` rule for `chpasswd`-style arguments.
- The miner-cmdline detector looks at the unmasked line in memory only, and
  ships the masked form.
- Log lines are parsed into fields; raw auth.log lines are not shipped (they can
  contain passwords typed as usernames, a classic).
- `audit.exec` carries the decoded argv after `mask_argv`. The raw audit line
  and `PROCTITLE` hex stay on the host.

## 10. Resource budget

Target < 1 % of one core and < 50 MB RSS on a host with ~500 processes and
~100 containers.

- process: one `stat` read per pid per 2 s; `cmdline/exe/cwd/status/cgroup`
  only for new pids. Tracking table capped at 65 536 pids.
- net: one read of `net/tcp{,6}`/`udp{,6}` per network namespace per 5 s;
  destination dedupe table capped at 16 384 entries with 1 h TTL; TCP listen
  keys (namespace, protocol, local address, port) capped at 16 384 with no
  eviction — a full table is partial coverage and further listeners are not
  emitted; the first successful sample records listeners and emits none;
  private, loopback and link-local destinations ignored by default (the
  incident's pool connection was to a public IP); the fd inode scan runs at
  most once per 10 s and only when a new public destination, or a TCP listener
  that appeared after the baseline, is unattributed.
- logs: tail reads capped at 1 MiB per poll per file.
- docker: finite `/events?since&until` window per poll, 2 s socket timeout,
  inspect at most 50 containers per poll.
- persistence: stat every 30 s; SHA-256 only when size/mtime/ctime/inode
  changed, files capped at 1 MiB (larger files report `size_only`).
- auditd: tails `/var/log/audit/audit.log`, capped at 1 MiB per poll. At most
  32 audit ids are assembled at once. Only the newest incomplete id is held
  across polls. A full table is partial coverage. Overflow ids that were not
  fully assembled are not emitted. A complete group evicted only because the
  table is full is emitted, and the full table still forces partial coverage.
- Measurement: `scripts/measure.sh` (run on a test VM, never on prod first)
  samples `/proc/<pid>/stat` utime+stime and `VmRSS` for 10 minutes. On this
  Mac, only the release binary size and the fixture replay were measured
  (see README).

## 11. Kernel 4.19 vs 6.1: degradation and the eBPF seam

- Debian 10 / 4.19 has no reliable eBPF (BTF absent, CO-RE unavailable).
  `/proc` polling, log tailing, and the auditd execve tail work on 4.19 and
  6.1. Kind `audit.exec` with source `auditd` stays distinct from
  `process.start`, so aftercve crossview (which matches `process.start` and
  `process.exit`) keeps tracking processes the sensor still sees.
- Debian 12 / 6.1: BTF is present, so a later `ebpf` source (exec, connect,
  file-open on persistence paths) can be added behind the same `Source`
  trait. It emits the same event kinds with `source: "ebpf"`, and the process
  source keeps running as a cross-check: an exec seen by eBPF and never by
  `/proc` polling (or vice versa) is itself interesting.
- Debian 12 without rsyslog: auth events live only in journald. The auth
  source reports `unsupported` with reason `no auth.log (journald only)`; a
  journald source (`journalctl -f -o json` child with bounded output, or
  reading journal files) is deferred.

## 12. Privileges and systemd hardening

nocved runs as root with a reduced capability bounding set because it must:

- read `/proc/<pid>/{exe,cwd,fd}` of every user's processes: these are
  ptrace-access-checked (`PTRACE_MODE_READ_FSCREDS`), which for other users'
  processes needs `CAP_SYS_PTRACE`; `CAP_DAC_READ_SEARCH` covers reading
  `/proc/<pid>/fd` directories and root-only logs/configs.
- read `/var/log/auth.log` (0640 root:adm), `/etc/shadow` (hash only),
  `/root/.ssh/authorized_keys`: `CAP_DAC_READ_SEARCH`.
- connect to `/var/run/docker.sock` (root:docker 0660): root uid suffices.

Capabilities: `CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE`,
`AmbientCapabilities=` empty, `NoNewPrivileges=yes`, `ProtectSystem=strict`,
`ReadWritePaths=/var/lib/nocved`, `ProtectHome=read-only`,
`PrivateTmp=yes`, `ProtectKernelTunables/Modules/Logs=yes`,
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SystemCallFilter=@system-service`,
`MemoryMax=128M`, `CPUQuota=5%`, `Nice=10`. `ProcSubset=all` and
`ProtectProc=default` are required (the sensor must see all pids).
`CAP_SYS_PTRACE` lets nocved read other processes' memory in principle; nocved
never opens `/proc/<pid>/mem` or `environ`. A future unprivileged mode can
drop it and lose exe/cwd/fd attribution for other users' processes (coverage
then reports `partial`).

Docker socket access is equivalent to root. nocved uses only GET on
`/events`, `/containers/json` and `/containers/{id}/json` (enforced by a
fixed path allowlist in the client), and HTTP/1.0 so the daemon closes each
response.

## 13. Relationship to host-inventory and aftercve

| Tool | Cadence | Question it answers | Trust |
|---|---|---|---|
| host-inventory | daily cron | What is this host? (CMDB facts) | self-reported facts |
| **nocved** | seconds | What happened on this host, in order? | chained, off-host history |
| aftercve | on demand | Is this host compromised right now, and how? | deep forensic snapshot |

nocved reuses host-inventory's operational patterns: per-host key in a
root-only 0600 file read with `O_NOFOLLOW` and fd-based permission checks,
key only in a header, https-only except loopback, system CA pool, no
redirects/proxy, atomic 0600 writes, `install.sh` with mandatory `--sha256`,
Ansible playbook, key minted on the controller and written with `no_log`.

## 14. How aftercve consumes the store

- `GET /v1/hosts/{host}/events?since&until&kind&limit` (admin token) returns
  envelopes: `seq`, `epoch`, `prev`, `link`, `payload`, `received_at_ms`, plus
  the store's verdict (`mac_verified: true`, gap list). aftercve can re-verify
  the hash chain end to end without the MAC key.
- **Cross-view comparison.** aftercve builds "processes the sensor saw start
  and never saw exit" from history and compares with its live `/proc`
  snapshot using its existing `investigation::visibility::compare` (two
  samples each side, persistent vs transient differences):
  - history-only pids (persistent): the process is hidden now (rootkit) or the
    exit was missed (sensor stopped: check silence alerts for the window);
  - live-only pids that started after the sensor did: something hid from the
    sensor's view at the time;
  - same idea for sockets (`net.connect` destinations vs live sockets) and for
    persistence digests (store baseline vs files on disk now: a file changed
    while the sensor was silent).
- aftercve reports store-derived observations with provenance
  `nocve-store` and trust `off-host history, chain-verified` distinct from
  live-host observations. The client is deferred to the aftercve agent.

## 15. Store

- `tiny_http` server, worker threads, binds `127.0.0.1:8750` by default; TLS
  terminated by Traefik (file provider route, like other services).
- SQLite (bundled, WAL, `synchronous=NORMAL`, foreign keys on), one
  connection behind a mutex: the fleet is ~10 hosts.
- Tables: `hosts` (chain state, last seen, coverage, silent flag), `keys`,
  `admin_tokens`, `events`, `gaps`, `alerts`.
- Store-side correlation at insert time: `fleet.password_sweep` (same source IP,
  password login on >= 3 distinct hosts within 30 min: critical).
- Alerts = events whose max signal severity >= high, chain anomalies, silence.
  `GET /v1/alerts?since&min_severity&limit` returns them ordered by
  `(occurred_at_ms, id)`.
- Retention: events older than `retention_days` (default 90) deleted hourly;
  alerts and gaps kept for `alert_retention_days` (default 400).

## 16. Rollout

1. Store on a trusted, non-fleet box (decision for Ryan, section 18). Mint an
   admin token and one key per host.
2. Canary: one Debian 12 host and one Debian 10 host with `--check` then the
   service; measure CPU/RSS for 24 h with `scripts/measure.sh`.
3. Fleet via `deploy/ansible/nocved.yml` (`serial: 1`), frozen hosts through
   the vpscfgfarm break-glass runbook process, not directly.
4. Only after a week of tuning: wire `/v1/alerts` into paging.

## 17. Deferred

- eBPF source for 6.1 hosts.
- journald auth source for rsyslog-less Debian 12 hosts.
- Forward-secure MAC key ratchet (`k[e+1] = HMAC(k[e], "ratchet")` per hour,
  old keys erased) so a later root compromise cannot forge earlier events.
- Ed25519 per-host signatures so a store DB leak cannot forge history.
- aftercve store client and cross-view commands (another agent).
- Alert delivery (email/webhook), UI.
- Per-host policy tuning (e.g. hosts that legitimately use password SSH).

## 18. Decisions for Ryan before first deployment

- Store host: must not be one of the 7 compromised hosts. Candidates: apps2
  (not accessed in the incident, already hardened) or a fresh box.
- Domain: suggested `nocve.afterdarksys.com` behind Traefik with the wildcard
  cert, reachable from the fleet; admin GETs ideally restricted by IP.
- Retention: events 90 days, alerts 400 days (defaults) – confirm.
- Silence threshold: 120 s default; the daily 05:10 ns1/ns2 reboots will raise
  `sensor.silent` + `sensor.resumed` each day unless tolerated.
- Whether `ssh.root_password_login` should be critical fleet-wide now that
  password auth is off everywhere (any such login is then a regression).
- Pool IP list ownership (who updates `indicators.json`).

## 19. MVP implementation notes

- Extra rules beyond section 4: `authlog.hidden_line` (a line read from an
  auth-log inode that had been unlinked, i.e. a line the attacker removed from
  view), `authlog.deleted`, `authlog.symlink`, `persist.ld_preload_present`
  (baseline), `sensor.events_dropped`. Store-side: `chain.stale_epoch` (an old
  epoch replayed), `chain.heartbeat_replay`.
- One alert per event: the store takes the event's highest-severity signal
  (first one on ties) as the alert rule and keeps all signals in `detail`.
- `invalid user NAME` usernames are shipped as `<invalid>` (they are
  attacker-supplied and are sometimes a mistyped password).
- Kernel threads (PF_KTHREAD / ppid 2) are not reported; a user process that
  merely *names* itself like one is (`proc.masquerade`).
- The sensor fsyncs only when a poll produced events; idle ticks do no disk I/O.
- `nocved check` polls every source once and prints coverage; it sends nothing.
- Measured on the build Mac (release binary, fixture root with 600 processes,
  12 000 fds, 600 sockets, three 200 000-line logs): the first, worst-case poll
  (every process is new) used 0.87 s CPU and 4.6 MB max RSS. Binary sizes:
  nocved 2.5 MB, nocve-store 2.6 MB. Steady-state CPU must be measured on a
  Linux test VM with `scripts/measure.sh` (macOS has no procfs).

## 20. Dependencies (all pinned in Cargo.lock; `cargo deny check`)

| Crate | Where | Why |
|---|---|---|
| serde, serde_json | all | event schema, config, wire format |
| sha2, hmac | proto | chain hash, MAC, key derivation (RustCrypto, audited family) |
| subtle | proto, store | constant-time comparison (SECURITY-RULES rule 2) |
| getrandom | proto, sensor | OS CSPRNG for keys, epochs, jitter (rule 1) |
| hex | proto | hex encoding of hashes/keys |
| libc | sensor | `O_NOFOLLOW`, `sysconf(_SC_CLK_TCK)` |
| ureq (rustls + platform-verifier) | sensor | small blocking HTTPS client; system CA store; no async runtime |
| tiny_http | store | small synchronous HTTP/1.1 server; TLS is Traefik's job |
| rusqlite (bundled) | store | embedded SQLite with WAL, no system lib dependency |
| tempfile (dev) | tests | fixture roots |

No async runtime, no CLI framework, no logging framework (plain stderr lines,
journald captures them).
