.PHONY: build test vet check fuzz audit reproducible image

build:
	mkdir -p bin
	go build -trimpath -buildvcs=false -o bin/gateway ./cmd/gateway
	go build -trimpath -buildvcs=false -o bin/cgw ./cmd/cgw

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

check: test vet
	@test -z "$$(gofmt -l attestation cmd internal policy protocol sdk)"
	go mod verify

fuzz:
	go test ./policy -run='^$$' -fuzz=FuzzURL -fuzztime=10s
	go test ./protocol -run='^$$' -fuzz=FuzzOpen -fuzztime=10s
	go test ./attestation -run='^$$' -fuzz=FuzzEventLog -fuzztime=10s

audit:
	go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...

reproducible:
	sh scripts/check-reproducible.sh

image:
	docker build --platform linux/amd64 -t confidential-gateway:local .
