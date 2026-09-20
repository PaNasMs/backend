# PaNasMs backend

The Linux server for **Pavlo's NAS Management System**. The current 0.2.1
prototype combines a Go HTTP/WebSocket core, a privileged Go agent and Python
system-management adapters. The deployed target is Raspberry Pi OS ARM64.

## Architecture

- **Core** serves the SPA, HTTP API, sessions, user preferences, wallpaper,
  notifications and metrics. It runs as the restricted `panasms` service user.
- **Agent** authenticates through PAM and executes authorized system operations
  through a local Unix socket. It stores persistent jobs separately from core.
- **System adapters** integrate Linux tools and services; Linux remains the source
  of truth for users, disks, mounts, RAID and network configuration.
- **Installable modules** run as separate services. Files, Terminal and Cloud Sync
  have their own repositories and signed packages; their code is not installed
  as part of the core package.
- **Cooling** has an independent package and service, so removing the panel does
  not stop the disk cooling controller.

The implementation uses `net/http`, chi, coder/websocket, `database/sql` with
SQLite, PAM through cgo, and systemd. SQLite schema initialization and migrations
live in the Go store packages; there is no sqlc generation step.

## Implemented system areas

Linux users/groups, profiles and SSH keys; home relocation; disks and mdadm RAID;
partitions, filesystems, LUKS and mounts; SMART checks and schedules; disk standby;
CPU/disk cooling; external NFS/SMB mounts; NetworkManager Ethernet/Wi-Fi, access
points and connection sharing; system services, journal, updates and power
operations; module installation and the signed online catalog.

Network changes use confirmation and rollback. Storage and account operations
use server-side validation and the management plan/run workflow. UI visibility
is not an authorization boundary. Dedicated firewall and LVM management remain
outside the current interface.

## Source map

| Path | Contents |
| --- | --- |
| [cmd](cmd) | Core and agent entry points |
| [internal](internal) | API, identity, persistence, jobs, metrics and module integration |
| [management](management) | Python Linux adapters and module installation/catalog logic |
| [api/openapi.yaml](api/openapi.yaml) | OpenAPI contract; management operations are not fully described yet |
| [api/events.md](api/events.md) | Event WebSocket protocol |
| [packaging](packaging) | Debian hooks, systemd units, PAM policy and administration tools |
| [cooling](cooling) | Independent disk cooling controller |
| [scripts](scripts) | Build and installation migration tools |
| [tests](tests) | Python adapter tests; Go tests live beside their packages |

## Build and test

Use Linux, Go 1.26 or newer, Python 3, a C compiler and PAM development headers
(`libpam0g-dev` on Debian). CGO is required for PAM and SQLite.

```sh
make check
make check-race
make build
```

`make check` runs Go tests with PAM, Go vet and Python unit tests. `make build`
produces `bin/panasms-core` and `bin/panasms-agent`.

Build the [frontend](https://github.com/PaNasMs/frontend) first, then package its
static output on the target architecture:

```sh
sh scripts/build-deb.sh ../frontend/dist
sh scripts/build-cooling-deb.sh
```

Outputs are `dist/panasms-prototype_0.2.1_<architecture>.deb` and
`dist/panasms-cooling_0.2.0_all.deb`. The package script expects a native Go build;
ARM64 is the tested deployment target. Go binaries can be built without frontend
sources, but the prototype Debian package requires prebuilt SPA assets.

## Installation and operation

On the target Debian-based machine, install the generated prototype package with
`apt install ./<package>.deb` so OS dependencies are resolved, then run
`sudo panasms-configure`. It requires an existing non-root user in the Linux
`sudo` group; it does not create an administrator. Review hardware support before
installing/configuring the optional cooling package.

The packaged prototype serves HTTP on port 80. The core binary also accepts TLS
certificate/key flags. Runtime configuration is in `/etc/panasms/panasms.env`;
core state is in `/var/lib/panasms`, and agent jobs/state in `/var/lib/panasms-agent`.
Inspect `panasms-core`, `panasms-agent` and, if installed, `panasms-cooling` with
`systemctl` and `journalctl`.

`sudo panasms-uninstall --plan` previews removal. `--remove` removes the panel;
`--purge` additionally removes panel-owned state. User data, Linux accounts,
RAID and mounts are retained. The separate cooling package is retained.
Review the plan before using either removal mode.

The one-time `scripts/migrate-ostojaos.py` helper applies only to its explicitly
validated legacy installation and supplied backup artifacts. It is not a general
installer or a substitute for future upgrade migrations.

## Related repositories and license

[Workspace](https://github.com/PaNasMs/panasms) ·
[Frontend](https://github.com/PaNasMs/frontend) ·
[Module SDK](https://github.com/PaNasMs/module-sdk) ·
[Registry](https://github.com/PaNasMs/module-registry)

Internal planning/deployment documents are not public. Public documentation is
maintained in English. Original code: [PolyForm Noncommercial 1.0.0](LICENSE);
third-party scope: [NOTICE](NOTICE).
