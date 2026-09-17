#!/system/bin/sh
# Can also be run manually as root; no setenforce, mount, deletion, or reboot.
set -u
umask 077
[ "$(id -u)" = 0 ] || { echo 'Root required' >&2; exit 1; }
awk '$5 == "/metadata" {found=1} END {exit !found}' /proc/self/mountinfo || {
    echo '/metadata is not mounted; refusing to write elsewhere' >&2; exit 1;
}
root=/metadata/c17-bootlogs
[ ! -L "$root" ] || exit 1
if [ ! -e "$root" ]; then mkdir -m 0700 "$root" || exit 1; fi
[ -d "$root" ] && [ "$(stat -c %u "$root")" = 0 ] || exit 1
chmod 0700 "$root" || exit 1
available=$(df -k /metadata | awk 'NR == 2 {print $4}')
case "$available" in ''|*[!0-9]*) exit 1;; esac
[ "$available" -ge 15360 ] || { echo 'Need 15 MiB free to retain a 12 MiB safety margin; skipping logs' >&2; exit 1; }
used=$(du -sk "$root" | awk '{print $1}')
case "$used" in ''|*[!0-9]*) exit 1;; esac
[ "$used" -le 3072 ] || { echo '6 MiB archive budget would be exceeded; copy old logs off first' >&2; exit 1; }
count=$(find "$root" -mindepth 1 -maxdepth 1 -type d | wc -l)
[ "$count" -lt 4 ] || { echo '4 captures retained; archive them manually first' >&2; exit 1; }
dest=$(mktemp -d "$root/boot-XXXXXXXXXXXX") || exit 1
token=${dest##*/}
errors="$dest/$token-errors.txt"
{
    date -u
    uname -a
    getenforce
    getprop ro.build.fingerprint
    getprop ro.gsid.image_running
    getprop ro.boot.bootreason
    cat /proc/sys/kernel/random/boot_id
    cat /proc/uptime
    cat /proc/cmdline
    for node in /sys/module/ramoops/parameters/*; do
        [ -f "$node" ] || continue
        printf '\n%s=' "$node"
        cat "$node"
    done
} >"$dest/$token-info.txt" 2>>"$errors"
found=0
remaining=2359296
for node in /sys/fs/pstore/*; do
    [ -f "$node" ] && [ ! -L "$node" ] || continue
    name=${node##*/}
    case "$name" in *[!a-zA-Z0-9_.-]*) continue;; esac
    [ "$remaining" -gt 0 ] || break
    limit=1048576
    [ "$remaining" -ge "$limit" ] || limit=$remaining
    head -c "$limit" "$node" >"$dest/$token-$name" 2>>"$errors" && found=$((found + 1))
    size=$(wc -c <"$dest/$token-$name")
    remaining=$((remaining - size))
done
timeout 5 dmesg 2>>"$errors" | tail -c 262144 >"$dest/$token-current-dmesg.txt"
timeout 5 logcat -L -b all -d -t 1000 2>>"$errors" | tail -c 131072 >"$dest/$token-previous-logcat.txt"
timeout 5 logcat -b all -d -t 1000 2>>"$errors" | tail -c 131072 >"$dest/$token-current-logcat.txt"
printf 'pstore_files=%s\nOnly existing logs were copied. Empty outputs or errors are NOT evidence of a successful capture.\n' "$found" >"$dest/$token-result.txt"
# Bound files are closed before syncing; never clear the pstore originals.
sync -f "$dest" 2>>"$errors" || true
echo "$dest"
