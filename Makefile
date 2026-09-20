.PHONY: check check-race build
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
