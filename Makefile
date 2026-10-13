BIN     := tailscale-protonvpn
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

build:
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/tailscale-protonvpn

test:
	go vet ./...
	go test ./...

# Cross-compile release binaries into dist/ (CI does the same on tags).
dist:
	rm -rf dist && mkdir dist
	for a in amd64 arm64; do \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$a go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BIN)-linux-$$a ./cmd/tailscale-protonvpn ; \
	done
	cd dist && sha256sum $(BIN)-linux-* > checksums.txt

# Build, copy to HOST and (re)install there. The tunnel stays up across reinstalls.
#   make deploy HOST=root@my-server
deploy: build
	@test -n "$(HOST)" || { echo "usage: make deploy HOST=root@my-server"; exit 1; }
	scp -q $(BIN) $(HOST):/tmp/$(BIN)
	ssh $(HOST) '/tmp/$(BIN) install && rm /tmp/$(BIN)'

# Refresh the server list snapshot embedded in the binary.
snapshot:
	curl -fsSL -o internal/controller/snapshot/servers.json https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers/protonvpn.json

.PHONY: build test dist deploy snapshot
