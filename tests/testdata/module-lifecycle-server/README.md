This SDK service is only for the opt-in module lifecycle acceptance fixture. It
is not part of the backend runtime or a distributable module. Its separate Go
module pins the same SDK revision used by the released Files module.

Build the service on the development host from this directory:

```sh
CGO_ENABLED=0 GOTOOLCHAIN=local go build -mod=readonly -o /tmp/go14-fixture-server .
```

Build the acceptance test binary from the backend root:

```sh
CGO_ENABLED=0 GOTOOLCHAIN=local go test -c -o /tmp/go14-acceptance.test ./internal/systemops/modulelifecycle
```

Copy both binaries into a verified root-owned, non-sticky directory in the
guest, for example `/var/lib/panasms-go14-runtime` with mode 0700. Record their
SHA256 values. The host build outputs under `/tmp` are not executable input
paths for the guest: its trusted-parent guard rejects a sticky directory.

Run the test binary with `-test.run '^TestIsolatedModuleLifecycleAcceptance$'
and `-test.timeout=30m`. Only run it as root inside an explicitly
authorized, disconnected disposable VM with a preserved snapshot. Required
environment variables are `PANASMS_MODULE_VM_ACCEPTANCE=1`,
`PANASMS_MODULE_VM_UUID` (the authorized guest's previously verified UUID),
`PANASMS_MODULE_VM_BASELINE` (exact installed core package version),
`PANASMS_MODULE_FIXTURE_SERVER` (root-owned service binary path) and
`PANASMS_MODULE_FIXTURE_SERVER_SHA256`. The fixture refuses existing owned names
before changing its private code/data directories and prefixed systemd services.

The service exercises the SDK maintenance lease with synthetic retry work; it
does not access a cloud provider. Restore the original full VM snapshot after
every acceptance attempt, including successful attempts. This is separate from
installed-package and browser acceptance.

The installed-helper Python fixture requires a real existing administrator
account whose name follows the same 31-character maximum as the native helper.
Readonly helper queries, plans and inspections have a 45-second timeout. Native
mutations deliberately finish at their safe points: a watchdog must not kill
APT, systemd or the helper after activation begins. The partial-copy SIGKILL
case discards progress stderr to prevent a full pipe from hiding its observed
boundary; it verifies the retained journal and actual wait status instead.

On a failed assertion, preserve the fixture tree, journal and owned services
for inspection. Do not run automatic cleanup or recovery before collecting the
failure evidence. Restore the full external VM snapshot before any retry. Even
a successful Python run may leave newly created production parent directories
and a fixture widget entry in `catalog.json`; the full snapshot restore removes
that residue. External preflight must also prove adequate guest and backing
storage capacity, disconnected NICs, no routes or external mounts (including
SMB3), exclusive VM ownership and a usable preserved snapshot.
