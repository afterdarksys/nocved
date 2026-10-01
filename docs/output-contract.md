# After Dark CLI output contract (v1)

Applies to every binary in the suite: `nocved`, `nocve-store`, `darksignal`,
`afterguard`, `afteralert`, `afterseal`, `aftercve`, `darkapple`. Goal: a
human can read every command, and automation only ever has to parse JSON.

## 1. Selecting output

- Every command accepts `--json`. With `--json`, stdout carries exactly one
  JSON document (compact, one line, newline-terminated) and nothing else.
  Commands whose result is a stream (daemons) are exempt; see section 6.
- `--format json` is an accepted alias for `--json`; `--format text` selects
  human output. Commands that already render other formats (for example
  `--format html`) keep them.
- Default is human text, except **machine-primary** commands, which default
  to JSON because their main consumer is a timer, pipeline or agent. Each
  repo lists its machine-primary commands in its README table (section 8).
  A machine-primary command still accepts `--json` (no-op) and must offer
  `--format text` with a short human rendering.
- Diagnostics, progress and warnings go to stderr, never to stdout in
  `--json` mode.
- Secrets: a command that mints a credential (for example `nocve-store keys
  mint`, `admin mint`) puts the secret in a `secret` field in JSON mode and
  prints nothing else with it. Never log secrets to stderr.

## 2. Success envelope

Every JSON document on stdout is an object with these fields first:

```json
{"schema_version":1,"kind":"<tool>.<command>","tool":"<tool>","tool_version":"<semver>", ...payload}
```

- `kind` is dotted lowercase: `darksignal.check`, `nocve-store.keys.list`,
  `aftercve.quick_hunt`. Existing aftercve `kind` values are kept unchanged.
- `schema_version` is an integer, bumped only for incompatible payload
  changes. New optional fields do not bump it.
- Existing payload fields keep their names. Existing version fields
  (`"schema":"darkapple.status.v1"`, `"v":2`) stay as extra fields.
- Times are Unix milliseconds in fields ending `_ms`.

## 3. Errors

- In `--json` mode (or a machine-primary command's default JSON mode), every
  failure, including argument/usage errors, writes exactly one JSON line to
  **stderr** and nothing to stdout:

```json
{"schema_version":1,"kind":"error","tool":"<tool>","command":"<command or null>","category":"<category>","message":"<human sentence>","exit_code":N}
```

- `category` is one of: `usage`, `config`, `io`, `refused`, `integrity`,
  `verification`, `transport`, `budget`, `internal`. Repos may add a more
  specific `detail` object; they may not change the six base fields.
- aftercve's existing shapes (`{"valid":false,"category","message"}` and
  `{"error","message","exit_code"}`) are replaced by this shape; keep their
  old keys as extra fields for one release if a test or doc depends on them.
- In text mode the error is one line: `<tool>: <message>`.
- Messages never contain secrets, tokens, or raw untrusted bytes (escape
  control and bidi characters).

## 4. Exit codes

**Do not renumber any existing documented or tested exit code.** Every repo
keeps its current codes; this table is the default for codes that are not
yet assigned and the vocabulary for documenting them:

| code | meaning |
| --- | --- |
| 0 | success |
| 1 | runtime failure (I/O, internal) |
| 2 | usage or configuration error |
| 3 | integrity stop or permanent refusal |
| 10 | completed with incomplete coverage |
| 11-19 | findings or delivery states (tool-specific) |
| 20-29 | verification and crypto (tool-specific) |
| 40-49 | remote, store or transport (tool-specific) |

If a repo's existing code conflicts with this table, keep the existing code,
document it, and list the conflict in your report. Do not change it.
`--help` / `-h` exits 0. An unknown argument is a usage error.

## 5. Help

Every binary and subcommand supports `--help` / `-h`: prints usage, every
flag, and the command's exit codes to stdout, exits 0. `<tool> help` and
`<tool> --version` / `<tool> version` work. Hand-rolled parsers must add
this; do not switch argument-parsing libraries unless the repo already uses
one.

## 6. Daemons and status

- Every long-running command (`run`, `serve`, `forward`, `ship` loops) writes
  an atomic (write temp + rename, mode 0600 or 0640 as the repo already
  uses) `status.json` in its state directory at least every 30 s and on
  shutdown, in the section 2 envelope with `kind: "<tool>.status"` and
  `updated_at_ms`, plus the counters the daemon already tracks.
- Every daemon tool has a `status` command (`<tool> status --config PATH`,
  human by default, `--json` for the envelope) that reads that file and
  reports `stale: true` when `updated_at_ms` is older than 3x the write
  interval. Reading status never needs the daemon's write lock and never
  mutates state.
- Existing status files (afterguard, darkapple) adopt the envelope by adding
  the four envelope fields; existing fields stay.

## 7. Compatibility rules

- No change to wire protocols, frames, acks, ledgers, databases, HTTP APIs
  or file formats other than adding envelope fields to status/report JSON.
- Existing scripts, systemd units, tests and docs that parse output must be
  updated in the same change if a default changes.
- No new dependencies unless unavoidable (serde_json is already present in
  every repo). No AI attribution anywhere.

## 8. Documentation

Each repo README gets one `## CLI output and exit codes` section with: the
`--json` rule, a table of commands (human default or machine-primary,
`kind`, exit codes), the error shape, and the status file location. Copy this
contract into the repo as `docs/output-contract.md` unchanged.

## 9. Tests

- One test per binary that runs **every** subcommand with `--json` (using
  temp config/state; skip only commands that need root or a live peer, and
  say which) and asserts: stdout parses as one JSON object, envelope fields
  present and correct `kind`, exit code as documented.
- One test per binary for the JSON error path: usage error and a config
  error produce one JSON line on stderr with the six fields, empty stdout,
  matching `exit_code`.
- `--help` test: exit 0, mentions every subcommand.
- Status: daemon status file written with the envelope; `status --json`
  reports `stale` correctly (inject time or write an old file).
- Mutation-check at least: envelope omitted, error written to stdout, wrong
  exit code. Each must fail a test.
