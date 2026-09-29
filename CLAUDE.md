# CLAUDE.md

nocved: continuous host behaviour sensor + central store (Rust 1.97.1
workspace). Complements `~/development/aftercve` (deep forensics) and
host-inventory (daily CMDB facts). Design and threat model: `DESIGN.md`.

## Rules

- Never run anything against real fleet hosts; tests use fixture roots, a fake
  Docker socket, and 127.0.0.1 only.
- `~/development/ads-fable-utils/SECURITY-RULES.md` is binding: OS CSPRNG,
  constant-time compares, fail closed, no secret logging, `Threats:` notes,
  negative tests. No `unwrap`/`expect` outside tests (enforced by clippy lints).
- Never ship file contents or environment values; command lines go through
  `nocve_proto::mask`.
- The sensor never chains an event it may later drop (no self-made gaps).
- Ask Ryan before committing.

## Commands

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo build --release --locked
cargo deny check
```
