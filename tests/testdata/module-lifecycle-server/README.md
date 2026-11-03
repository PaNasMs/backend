This SDK service is only for the opt-in module lifecycle acceptance fixture. It
is not part of the backend runtime or a distributable module. Its separate Go
module pins the same SDK revision used by the released Files module.

Build the service from this directory:

```sh
CGO_ENABLED=0 GOTOOLCHAIN=local go build -mod=readonly -o /tmp/go14-fixture-server .
```

Build the acceptance test binary from the backend root:

```sh
CGO_ENABLED=0 GOTOOLCHAIN=local go test -c -o /tmp/go14-acceptance.test ./internal/systemops/modulelifecycle
```

Only run `TestIsolatedModuleLifecycleAcceptance` as root inside an explicitly
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
