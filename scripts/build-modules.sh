#!/bin/sh
set -eu
[ "$#" = 1 ] || { echo 'Usage: build-modules.sh MODULES_SOURCE_DIRECTORY'; exit 1; }
modules=$(CDPATH= cd -- "$1" && pwd)
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"
for id in files terminal cloud-sync; do
 mkdir -p "$modules/$id/dist/bin"
 (cd "$modules/$id" && go build -buildvcs=false -trimpath -tags pam -o dist/bin/server ./cmd/server)
done
mkdir -p "$modules/files/dist/backend"
cp "$modules/files/backend/files.py" "$modules/files/dist/backend/operations.py"
cp "$modules/files/backend/thumbnails.py" "$modules/files/dist/backend/thumbnails.py"

mkdir -p "$modules/cloud-sync/dist/backend"
cp "$modules/cloud-sync/backend/cloud_sync.py" "$modules/cloud-sync/dist/backend/cloud_sync.py"
cp "$modules/cloud-sync/tools/authorize.py" "$modules/cloud-sync/dist/backend/authorize.py"
