export PATH := $(PATH):`go env GOPATH`/bin
export GO111MODULE=on
LDFLAGS := -s -w

# Cross-build: make frpc GOOS=linux GOARCH=amd64  =>  bin/frpc-linux-amd64
# Omit GOOS/GOARCH for native build (uses current OS/arch)
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

# .exe for Windows
ifeq ($(GOOS),windows)
	BINARY_SUFFIX := .exe
else
	BINARY_SUFFIX :=
endif

FRPS_BIN := bin/frps-$(GOOS)-$(GOARCH)$(BINARY_SUFFIX)
FRPC_BIN := bin/frpc-$(GOOS)-$(GOARCH)$(BINARY_SUFFIX)

.PHONY: web frps-web frpc-web frps frpc

all: env fmt web build

build: frps frpc

env:
	@go version

web: frps-web frpc-web

frps-web:
	$(MAKE) -C web/frps build

frpc-web:
	$(MAKE) -C web/frpc build

fmt:
	go fmt ./...

fmt-more:
	gofumpt -l -w .

gci:
	gci write -s standard -s default -s "prefix(github.com/fatedier/frp/)" ./

vet: web
	go vet ./...

frps:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags "$(LDFLAGS)" -tags frps -o $(FRPS_BIN) ./cmd/frps

frpc:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags "$(LDFLAGS)" -tags frpc -o $(FRPC_BIN) ./cmd/frpc

test: gotest

gotest: web
	go test -v --cover ./assets/...
	go test -v --cover ./cmd/...
	go test -v --cover ./client/...
	go test -v --cover ./server/...
	go test -v --cover ./pkg/...

e2e:
	./hack/run-e2e.sh

e2e-trace:
	DEBUG=true LOG_LEVEL=trace ./hack/run-e2e.sh

e2e-compatibility-last-frpc:
	if [ ! -d "./lastversion" ]; then \
		TARGET_DIRNAME=lastversion ./hack/download.sh; \
	fi
	FRPC_PATH="`pwd`/lastversion/frpc" ./hack/run-e2e.sh
	rm -r ./lastversion

e2e-compatibility-last-frps:
	if [ ! -d "./lastversion" ]; then \
		TARGET_DIRNAME=lastversion ./hack/download.sh; \
	fi
	FRPS_PATH="`pwd`/lastversion/frps" ./hack/run-e2e.sh
	rm -r ./lastversion

alltest: vet gotest e2e
	
clean:
	rm -f ./bin/frpc-*
	rm -f ./bin/frps-*
	rm -rf ./lastversion
