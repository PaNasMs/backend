#!/bin/bash
set -euo pipefail
usage() { echo 'Usage: sudo scripts/install-prototype.sh [--build-user USER] [--disk-fan] --assets /path/to/frontend/dist'; }
admin=${SUDO_USER:-} assets= disk_fan=0
while (($#)); do
 case "$1" in
  --build-user) admin=${2:?missing user}; shift 2;;
  --assets) assets=${2:?missing assets}; shift 2;;
  --disk-fan) disk_fan=1; shift;;
  -h|--help) usage; exit 0;;
  *) usage >&2; exit 2;;
 esac
done
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
if [[ -z $admin || $admin == root ]]; then
 admin=$(python3 -c 'import grp,pwd,os; gid=grp.getgrnam("sudo").gr_gid; print(next((u.pw_name for u in pwd.getpwall() if u.pw_uid != 0 and gid in os.getgrouplist(u.pw_name,u.pw_gid)), ""))')
fi
[[ $admin =~ ^[a-z_][a-z0-9_-]*$ && $admin != root && $admin != ostojaos ]] || { echo 'An existing sudo user is required for the unprivileged build.' >&2; exit 1; }
id -nG "$admin" | tr ' ' '\n' | grep -qx sudo || { echo 'User is not in sudo.' >&2; exit 1; }
for legacy in /etc/pinas /var/lib/pinas /var/lib/pinas-agent /var/lib/pinas-modules /etc/pinas-cooling /usr/lib/pinas /usr/lib/pinas-cooling; do
 if [ -e "$legacy" ] || [ -L "$legacy" ]; then
  echo "Existing PiNAS installation found at $legacy. Migrate its configuration and data before installing OstojaOS; nothing has been changed." >&2
  exit 1
 fi
done
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
assets=$(realpath -e -- "$assets")
[[ -f $assets/index.html && -f $repo/go.mod ]] || { echo 'Backend source and built frontend assets required.' >&2; exit 1; }
. /etc/os-release
[[ $ID == debian || ${ID_LIKE:-} == *debian* ]] || { echo 'Debian-family OS required.' >&2; exit 1; }
arch=$(dpkg --print-architecture)
case "$arch" in
 arm64) go_sha=3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec;;
 amd64) go_sha=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445;;
 *) echo "Unsupported architecture: $arch" >&2; exit 1;;
esac
if ! dpkg-query -W -f='${Status}' ostojaos-prototype 2>/dev/null | grep -q 'install ok installed'; then
 if [[ -n $(ss -H -ltn '( sport = :80 )') ]]; then echo 'Port 80 is already occupied.' >&2; exit 1; fi
fi
printf 'Installing OstojaOS for %s on %s (%s). Existing storage is never formatted or recreated; Linux users are reused.\n' "$admin" "$(hostname)" "$arch"
export DEBIAN_FRONTEND=noninteractive
python3 "$repo/packaging/ostojaos-inspect-hardware"
apt-get update
apt-get install -y --no-install-recommends build-essential libpam0g-dev pkg-config ca-certificates curl python3 python3-pil openssl
scratch=$(mktemp -d /var/tmp/ostojaos-build.XXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
install -d "$scratch/backend" "$scratch/ui"
tar -C "$repo" --exclude='./dist' --exclude='./bin' --exclude='./.git' --exclude='__pycache__' -cf - . | tar -C "$scratch/backend" -xf -
cp -R -- "$assets/." "$scratch/ui/"
go_archive="go1.27.1.linux-${arch}.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "https://go.dev/dl/$go_archive" -o "$scratch/go.tar.gz"
printf '%s  %s\n' "$go_sha" "$scratch/go.tar.gz" | sha256sum --check --status
tar -C "$scratch" -xzf "$scratch/go.tar.gz"
chown -R "$admin:$(id -gn "$admin")" "$scratch"
runuser -u "$admin" -- env PATH="$scratch/go/bin:/usr/bin:/bin" GOPATH="$scratch/gopath" GOCACHE="$scratch/gocache" GOTOOLCHAIN=local GOMAXPROCS=4 bash -c '
 set -euo pipefail
 cd "$1/backend"
 go mod verify
 go test -buildvcs=false -tags pam ./...
 go vet -tags pam ./...
 python3 -m unittest discover -s tests -p "*_test.py"
 scripts/build-deb.sh "$1/ui"
 scripts/build-cooling-deb.sh
' bash "$scratch"
install -d -o "$admin" -g "$(id -gn "$admin")" "$repo/dist"
package="$repo/dist/ostojaos-prototype_0.2.1_${arch}.deb"
install -o "$admin" -g "$(id -gn "$admin")" -m 0644 "$scratch/backend/dist/ostojaos-prototype_0.2.1_${arch}.deb" "$package"
if [[ $disk_fan == 1 ]]; then
 install -m 0644 "$scratch/backend/dist/ostojaos-cooling_0.2.0_all.deb" "$repo/dist/ostojaos-cooling_0.2.0_all.deb"
 apt-get install -y --reinstall "$repo/dist/ostojaos-cooling_0.2.0_all.deb"
 ostojaos-cooling-configure
fi
apt-get install -y --reinstall "$package"
ostojaos-inspect-hardware > /var/lib/ostojaos-installer/hardware.json
ostojaos-configure
for attempt in {1..30}; do
 if curl --fail --silent http://localhost:80/api/v1/health > "$scratch/health.json"; then break; fi
 sleep 1
done
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["status"]=="ok"' "$scratch/health.json"
systemctl is-active ostojaos-core.service ostojaos-agent.service
printf '\nInstalled. Package: %s\nFull removal: sudo ostojaos-uninstall --purge\nBuild prerequisites are retained; no autoremove is run.\n' "$package"
