#!/bin/sh
# measure.sh: sample nocved CPU and RSS on a TEST host for N seconds.
#   sudo ./measure.sh [SECONDS]   (default 600)
# Reads /proc only; changes nothing. Prints average CPU % of one core and max RSS.
set -eu
secs=${1:-600}
pid=$(systemctl show -p MainPID --value nocved 2>/dev/null || true)
[ -n "$pid" ] && [ "$pid" != 0 ] || pid=$(pgrep -xo nocved) || { echo "nocved not running" >&2; exit 1; }
hz=$(getconf CLK_TCK)
ticks() { awk '{print $14 + $15}' "/proc/$pid/stat"; }
t0=$(ticks); max_rss=0; i=0
while [ "$i" -lt "$secs" ]; do
  rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")
  [ "$rss" -gt "$max_rss" ] && max_rss=$rss
  sleep 1; i=$((i + 1))
done
t1=$(ticks)
echo "pid=$pid seconds=$secs cpu_pct=$(awk -v d=$((t1 - t0)) -v hz="$hz" -v s="$secs" 'BEGIN{printf "%.3f", d / hz / s * 100}') max_rss_kb=$max_rss"
echo "budget: cpu_pct < 1.0, max_rss_kb < 51200"
