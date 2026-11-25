#!/bin/sh
# Reproduction for t_d4c45592: after a crash leaves
# /etc/panasms/module-sources.pending.json, the installed package's prerm
# (run by dpkg for "upgrade"/"remove" before another version is unpacked)
# must refuse the package change, as it does for a pending .transaction.
# Run from the repository root.
set -u
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/var/lib/panasms-modules" "$root/etc/panasms/module-keys"
printf '{}' > "$root/etc/panasms/module-sources.pending.json"
# Keep only the module gate of prerm (lines up to the first maintenance check).
sed -e "s#/var/lib/panasms-modules#$root/var/lib/panasms-modules#g" \
    -e "s#/etc/panasms#$root/etc/panasms#g" \
    -e "s#/usr/lib/panasms/panasms-system-helper#false#g" packaging/prerm > "$root/prerm"
err=$(PANASMS_MAINTENANCE=1 PANASMS_HELPER_ROOT="$root" timeout 20 sh "$root/prerm" upgrade 2.0 2>&1 >/dev/null)
case "$err" in
  *'Recover pending module transactions'*) echo "prerm upgrade refused (ok)"; exit 0;;
esac
echo "prerm upgrade did not refuse a pending source intent; stderr: $err"
exit 1
