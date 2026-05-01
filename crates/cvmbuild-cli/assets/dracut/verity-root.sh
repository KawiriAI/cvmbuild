#!/usr/bin/sh
# cvmbuild dm-verity root activation — runs in the initrd at pre-mount
#
# Reads roothash= from the kernel cmdline, opens /dev/vda1 (data) +
# /dev/vda2 (hash) via veritysetup, and creates /dev/mapper/root for
# the rest of the dracut mount flow to consume (the kernel cmdline
# carries `root=/dev/mapper/root`).
#
# Always uses --panic-on-corruption: a corrupted block trips the
# kernel into a panic instead of silently returning bad data, which
# is the only correct behavior in a confidential VM.

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

ROOTHASH=$(getarg roothash=)
[ -z "$ROOTHASH" ] && die "verity-root: roothash= missing from cmdline"

modprobe dm-mod 2>/dev/null || true
modprobe dm-verity 2>/dev/null || true

DATA_DEV=/dev/vda1
HASH_DEV=/dev/vda2

# Wait up to 5s for the block devices to appear (udev is async).
for dev in "$DATA_DEV" "$HASH_DEV"; do
    n=0
    while [ ! -b "$dev" ] && [ $n -lt 50 ]; do
        sleep 0.1
        n=$((n + 1))
    done
    [ ! -b "$dev" ] && die "verity-root: $dev not found"
done

DM_DISABLE_UDEV=1 veritysetup open \
    --panic-on-corruption \
    "$DATA_DEV" root "$HASH_DEV" "$ROOTHASH" \
    || die "verity-root: veritysetup failed (exit $?)"

# DM_DISABLE_UDEV=1 skipped the kernel uevent. Trigger one manually so
# /dev/mapper/root gets registered in udev's database, otherwise dracut's
# wait-for-root path (libudev-based) will block.
for sysdev in /sys/block/dm-*; do
    [ -f "$sysdev/dm/name" ] || continue
    if [ "$(cat "$sysdev/dm/name")" = "root" ]; then
        echo change >"$sysdev/uevent" 2>/dev/null || true
        break
    fi
done

udevadm settle --timeout=5 2>/dev/null || true
