#!/bin/sh
# install.sh: install, update or remove nocved on one Linux host.
# Run as root ON the host. Idempotent. Mirrors host-inventory's install.sh.
#
#   First install (key on stdin, never argv: argv is visible in ps and journals):
#     ./install.sh --binary ./nocved-linux-amd64 --sha256 <hex> \
#         --url https://nocve.afterdarksys.com --key-stdin < /dev/tty
#     (paste the nvk1.… key minted with `nocve-store keys mint --host NAME`, Enter)
#
#   Upgrade the binary only:   ./install.sh --binary ./nocved-linux-amd64 --sha256 <hex>
#   Replace the key only:      ./install.sh --key-stdin
#   Remove (keep config+key):  ./install.sh --uninstall
#   Remove everything:         ./install.sh --uninstall --purge   (also the spool/state)
#
# Options:
#   --binary PATH          binary to install (default: nocved-linux-<arch> next to this script)
#   --sha256 HEX           REQUIRED with a binary: refuse to install unless it has this hash
#   --url URL              https base URL of nocve-store
#   --host-override NAME   report as NAME instead of the kernel hostname
#   --key-stdin            read the host key (one line) from stdin
#   --unit PATH            systemd unit to install (default: nocved.service next to this script)
#   --no-start             install but do not enable/start the service
#   --audit-rules PATH     auditd execve rule to install (default: audit/nocved.rules
#                          next to this script; installed only if auditd is present)
#   --no-audit-rules       do not install the auditd execve rule
#   --uninstall [--purge]
#
# Threats: the binary runs as root; nothing is installed unless its SHA-256
# matches --sha256. The key never touches argv or an external command.
set -eu
umask 077

BIN_DST=/usr/local/bin/nocved
ETC_DIR=/etc/nocved
CFG=$ETC_DIR/config.json
KEY=$ETC_DIR/key
UNIT_DST=/etc/systemd/system/nocved.service
STATE_DIR=/var/lib/nocved
HERE=$(cd "$(dirname "$0")" && pwd)

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "install.sh: $*"; }

binary='' sha='' url='' host_override='' unit_src=$HERE/nocved.service
audit_src=$HERE/audit/nocved.rules audit_rules=1
AUDIT_DST=/etc/audit/rules.d/50-nocved.rules
key_stdin=0 no_start=0 uninstall=0 purge=0

# Restore terminal echo however we exit (the key prompt turns it off).
restore_tty() { if [ -t 0 ]; then stty echo 2>/dev/null || true; fi; }
trap restore_tty EXIT
trap 'restore_tty; exit 130' INT TERM HUP

need() { [ $# -ge 2 ] || die "$1 needs a value"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --binary) need "$@"; binary=$2; shift 2 ;;
    --sha256) need "$@"; sha=$2; shift 2 ;;
    --url) need "$@"; url=$2; shift 2 ;;
    --host-override) need "$@"; host_override=$2; shift 2 ;;
    --unit) need "$@"; unit_src=$2; shift 2 ;;
    --audit-rules) need "$@"; audit_src=$2; shift 2 ;;
    --no-audit-rules) audit_rules=0; shift ;;
    --key-stdin) key_stdin=1; shift ;;
    --no-start) no_start=1; shift ;;
    --uninstall) uninstall=1; shift ;;
    --purge) purge=1; shift ;;
    --key|--key=*) die "the key is never passed as an argument; use --key-stdin" ;;
    -h|--help) sed -n '2,29p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root"
sha256_of() { sha256sum "$1" | cut -d' ' -f1; }

# ---------------------------------------------------------------- uninstall
if [ "$uninstall" -eq 1 ]; then
  if [ -f "$UNIT_DST" ]; then
    systemctl disable --now nocved.service 2>/dev/null || true
    rm -f "$UNIT_DST"
    systemctl daemon-reload
  fi
  rm -f "$BIN_DST"
  say "removed $UNIT_DST and $BIN_DST"
  if [ "$purge" -eq 1 ]; then
    rm -f "$CFG" "$KEY" "$ETC_DIR"/.config.json.new "$ETC_DIR"/.key.new
    if [ -d "$ETC_DIR" ]; then rmdir "$ETC_DIR" || die "$ETC_DIR not empty; left in place"; fi
    # Named files only: never a recursive delete.
    rm -f "$STATE_DIR/state.json" "$STATE_DIR/spool.jsonl" "$STATE_DIR/rejected.jsonl" \
      "$STATE_DIR/spool.rekeyed.jsonl" \
      "$STATE_DIR/cveguard-feed/events.jsonl" "$STATE_DIR/cveguard-feed/events.jsonl.1"
    if [ -d "$STATE_DIR/cveguard-feed" ]; then rmdir "$STATE_DIR/cveguard-feed" || true; fi
    if [ -d "$STATE_DIR" ]; then rmdir "$STATE_DIR" || say "$STATE_DIR not empty; left in place"; fi
    say "removed config, key and state (the store will see a new chain epoch on reinstall)"
  else
    say "kept $ETC_DIR and $STATE_DIR (use --purge to remove)"
  fi
  exit 0
fi
[ "$purge" -eq 0 ] || die "--purge only goes with --uninstall"

# ---------------------------------------------------------------- validation
valid() { case "$1" in *$3*) die "invalid $2 (unsupported characters)" ;; esac; }
if [ -n "$url" ]; then
  case "$url" in https://?*) ;; *) die "--url must start with https://" ;; esac
  valid "$url" url '[!A-Za-z0-9.:/_~-]'
  case "$url" in *@*|*\?*|*#*) die "--url must not contain credentials, a query or a fragment" ;; esac
fi
if [ -n "$host_override" ]; then
  valid "$host_override" host-override '[!A-Za-z0-9._-]'
  [ ${#host_override} -le 253 ] || die "host-override too long"
fi
if [ -n "$sha" ]; then
  [ ${#sha} -eq 64 ] || die "--sha256 must be 64 hex characters"
  valid "$sha" sha256 '[!0-9a-f]'
fi

# ---------------------------------------------------------------- binary
if [ -z "$binary" ] && { [ -n "$sha" ] || [ ! -x "$BIN_DST" ]; }; then
  case "$(uname -m)" in
    x86_64) binary=$HERE/nocved-linux-amd64 ;;
    aarch64|arm64) binary=$HERE/nocved-linux-arm64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
  esac
fi
if [ -n "$binary" ]; then
  [ -f "$binary" ] || die "binary not found: $binary"
  [ -n "$sha" ] || die "--sha256 is required to install a binary (see dist/SHA256SUMS)"
  got=$(sha256_of "$binary")
  [ "$got" = "$sha" ] || die "sha256 mismatch for $binary: got $got, want $sha"
  if [ -f "$BIN_DST" ] && [ "$(sha256_of "$BIN_DST")" = "$sha" ]; then
    say "binary unchanged ($BIN_DST)"
  else
    rm -f "$BIN_DST.new"
    install -m 0755 -o root -g root "$binary" "$BIN_DST.new"
    # Verify the copy that is about to become the binary, BEFORE it replaces
    # the running one (the source could change between hash and copy).
    if [ "$(sha256_of "$BIN_DST.new")" != "$sha" ]; then
      rm -f "$BIN_DST.new"
      die "sha256 mismatch for the copied binary; $BIN_DST left unchanged"
    fi
    mv -f "$BIN_DST.new" "$BIN_DST"
    say "installed $BIN_DST"
  fi
  [ "$(sha256_of "$BIN_DST")" = "$sha" ] || die "installed binary does not have sha256 $sha"
fi
[ -x "$BIN_DST" ] || die "$BIN_DST missing; pass --binary"
"$BIN_DST" version

# ---------------------------------------------------------------- config
install -d -m 0700 -o root -g root "$ETC_DIR"
chmod 0700 "$ETC_DIR"
if [ -n "$url$host_override" ]; then
  [ -n "$url" ] || die "--url is required whenever config values are given (the file is rewritten whole)"
  body="{\"store_url\":\"$url\",\"key_file\":\"$KEY\""
  [ -z "$host_override" ] || body="$body,\"host\":\"$host_override\""
  body="$body}"
  if [ -f "$CFG" ] && [ "$(cat "$CFG")" = "$body" ]; then
    say "config unchanged ($CFG)"
  else
    printf '%s\n' "$body" > "$ETC_DIR/.config.json.new"
    chown root:root "$ETC_DIR/.config.json.new"
    chmod 0600 "$ETC_DIR/.config.json.new"
    mv -f "$ETC_DIR/.config.json.new" "$CFG"
    say "wrote $CFG"
  fi
fi
[ -f "$CFG" ] || die "no config at $CFG; pass --url"
chown root:root "$CFG"; chmod 0600 "$CFG"

# ---------------------------------------------------------------- key
if [ "$key_stdin" -eq 1 ]; then
  tty=0
  if [ -t 0 ]; then
    tty=1
    printf 'Paste the nocved host key (input hidden), then Enter: ' >&2
    stty -echo 2>/dev/null || true
  fi
  key=
  IFS= read -r key || true
  if [ "$tty" -eq 1 ]; then stty echo 2>/dev/null || true; echo >&2; fi
  # builtins only below: the key never reaches an external command's argv
  [ ${#key} -eq 86 ] || { key=; die "not a nocved host key (want nvk1.<16 hex>.<64 hex>)"; }
  case "$key" in nvk1.*) ;; *) key=; die "not a nocved host key (want nvk1. prefix)" ;; esac
  case "${key#nvk1.}" in *[!0-9a-f.]*) key=; die "key has characters outside lowercase hex" ;; esac
  printf '%s\n' "$key" > "$ETC_DIR/.key.new"
  key=
  chown root:root "$ETC_DIR/.key.new"
  chmod 0600 "$ETC_DIR/.key.new"
  mv -f "$ETC_DIR/.key.new" "$KEY"
  say "wrote $KEY"
fi
[ -f "$KEY" ] || die "no key at $KEY; run: $0 --key-stdin"
chown root:root "$KEY"; chmod 0600 "$KEY"

# ---------------------------------------------------------------- verify
# check validates config/key permissions and polls every source once; sends nothing.
"$BIN_DST" check --config "$CFG" || die "check failed; fix the errors above (nothing was sent)"
say "check ok"

# ---------------------------------------------------------------- auditd rule
# Without an execve rule the auditd source sees no EXECVE records and reports
# coverage partial. Installed only where auditd is present; never removed.
if [ "$audit_rules" -eq 1 ] && [ -d /etc/audit/rules.d ]; then
  [ -f "$audit_src" ] || die "audit rule not found: $audit_src (or pass --no-audit-rules)"
  if [ -f "$AUDIT_DST" ] && cmp -s "$audit_src" "$AUDIT_DST"; then
    say "audit rule unchanged ($AUDIT_DST)"
  else
    install -m 0640 -o root -g root "$audit_src" "$AUDIT_DST"
    if command -v augenrules >/dev/null 2>&1; then
      augenrules --load >/dev/null || say "WARNING: augenrules --load failed; auditd coverage will report partial"
    fi
    say "installed $AUDIT_DST"
  fi
elif [ "$audit_rules" -eq 1 ]; then
  say "no /etc/audit/rules.d (auditd not installed); the auditd source will report unsupported"
fi

# ---------------------------------------------------------------- systemd
install -d -m 0700 -o root -g root "$STATE_DIR"
[ -f "$unit_src" ] || die "unit not found: $unit_src"
if [ -f "$UNIT_DST" ] && cmp -s "$unit_src" "$UNIT_DST"; then
  say "unit unchanged ($UNIT_DST)"
else
  install -m 0644 -o root -g root "$unit_src" "$UNIT_DST"
  systemctl daemon-reload
  say "installed $UNIT_DST"
fi
if [ "$no_start" -eq 0 ]; then
  systemctl enable nocved.service >/dev/null
  systemctl restart nocved.service
  sleep 2
  systemctl is-active --quiet nocved.service || die "nocved failed to start: journalctl -u nocved -n 50"
  say "nocved running"
fi
say "done"
