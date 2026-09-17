#!/system/bin/sh
# One-shot archive only; never block boot on log collection.
MODDIR=${0%/*}
/system/bin/sh "$MODDIR/collect.sh" >/dev/null 2>&1 &
