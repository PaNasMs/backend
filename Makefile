.PHONY: check check-race check-accounts-integration build
check:
	go test -buildvcs=false -tags pam ./...
	go vet -tags pam ./...
	python3 -m unittest discover -s tests -p '*_test.py'
check-race:
	go test -buildvcs=false -tags pam -race ./...
build:
	mkdir -p bin
	go build -buildvcs=false -trimpath -o bin/panasms-core ./cmd/panasms-core
	go build -buildvcs=false -trimpath -tags pam -o bin/panasms-agent ./cmd/panasms-agent
	go build -buildvcs=false -trimpath -o bin/panasms-system-helper ./cmd/panasms-system-helper
	go build -buildvcs=false -trimpath -o bin/panasms-keys ./cmd/panasms-keys
	go build -buildvcs=false -trimpath -tags pam -o bin/panasms-password ./cmd/panasms-password
check-accounts-integration: build
	PANASMS_NATIVE_TEST_BIN=$(CURDIR)/bin python3 tests/native_accounts_integration.py
