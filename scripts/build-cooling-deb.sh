#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
version=${PANASMS_COOLING_VERSION:-0.2.0}
dpkg --validate-version "$version"
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
mkdir -p "$stage/DEBIAN" "$stage/usr/lib/panasms-cooling" "$stage/usr/lib/systemd/system" "$stage/usr/sbin" dist
install -m644 cooling/hardware.py cooling/pwm-enable.dts cooling/controller.py "$stage/usr/lib/panasms-cooling/"
install -m644 cooling/panasms-cooling.service "$stage/usr/lib/systemd/system/"
install -m755 cooling/panasms-cooling-configure "$stage/usr/sbin/"
install -m755 cooling/preinst "$stage/DEBIAN/preinst"
install -m755 cooling/postinst "$stage/DEBIAN/postinst"
install -m755 cooling/prerm "$stage/DEBIAN/prerm"
cat > "$stage/DEBIAN/control" <<CONTROL
Package: panasms-cooling
Version: $version
Architecture: all
Maintainer: PaNasMs local development
Depends: python3, python3-libgpiod, smartmontools, raspi-utils, device-tree-compiler, systemd
Description: Independent configurable disk cooling controller for PaNasMs
CONTROL
dpkg-deb --root-owner-group --build "$stage" "dist/panasms-cooling_${version}_all.deb"
