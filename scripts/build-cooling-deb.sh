#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
version=${PANASMS_COOLING_VERSION:-0.2.0}
arch=$(dpkg --print-architecture)
dpkg --validate-version "$version"
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
mkdir -p "$stage/DEBIAN" "$stage/usr/lib/panasms-cooling" "$stage/usr/lib/systemd/system" "$stage/usr/sbin" "$stage/usr/share/doc/panasms-cooling" dist
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o "$stage/usr/lib/panasms-cooling/panasms-cooling" ./cmd/panasms-cooling
for tool in pinctrl dtmerge; do
 cmake -S "third_party/raspberrypi-utils/$tool" -B "$stage/build-$tool" -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release
 target=$tool
 [ "$tool" != dtmerge ] || target=dtoverlay
 cmake --build "$stage/build-$tool" --target "$target" --parallel 2
 install -m755 "$stage/build-$tool/$target" "$stage/usr/lib/panasms-cooling/"
done
dtc -@ -I dts -O dtb -o "$stage/usr/lib/panasms-cooling/pwm-enable.dtbo" cooling/pwm-enable.dts
install -m644 cooling/panasms-cooling.service "$stage/usr/lib/systemd/system/"
install -m755 cooling/panasms-cooling-configure "$stage/usr/sbin/"
install -m644 LICENSE "$stage/usr/share/doc/panasms-cooling/LICENSE"
install -m644 NOTICE "$stage/usr/share/doc/panasms-cooling/copyright"
install -m644 third_party/raspberrypi-utils/LICENCE "$stage/usr/share/doc/panasms-cooling/raspberrypi-utils.LICENCE"
install -m644 third_party/raspberrypi-utils/README.md "$stage/usr/share/doc/panasms-cooling/hardware-helpers.md"
install -m755 cooling/preinst "$stage/DEBIAN/preinst"
install -m755 cooling/postinst "$stage/DEBIAN/postinst"
install -m755 cooling/prerm "$stage/DEBIAN/prerm"
rm -r "$stage/build-pinctrl" "$stage/build-dtmerge"
mkdir -p "$stage/debian"
printf 'Source: panasms-cooling\nSection: admin\nPriority: optional\nMaintainer: PaNasMs\n\nPackage: panasms-cooling\nArchitecture: any\nDescription: PaNasMs cooling\n' > "$stage/debian/control"
shared_deps=$(cd "$stage" && dpkg-shlibdeps -O -eusr/lib/panasms-cooling/pinctrl -eusr/lib/panasms-cooling/dtoverlay)
shared_deps=$(printf '%s\n' "$shared_deps" | sed -n 's/^shlibs:Depends=//p')
[ -n "$shared_deps" ] || { echo 'Runtime library dependencies missing' >&2; exit 1; }
rm "$stage/debian/control"
rmdir "$stage/debian"
cat > "$stage/DEBIAN/control" <<CONTROL
Package: panasms-cooling
Version: $version
Architecture: $arch
Maintainer: PaNasMs local development
Depends: $shared_deps, smartmontools, systemd
Description: Independent configurable disk cooling controller for PaNasMs
CONTROL
dpkg-deb --root-owner-group --build "$stage" "dist/panasms-cooling_${version}_${arch}.deb"
