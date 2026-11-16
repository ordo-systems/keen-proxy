# Shared protocol tags. Full adds QUIC; lite must not, so HTTP/3 fails closed.
# See internal/engine/registry_lite.go for the curated registry.
PROTO_TAGS := with_utls,with_wireguard,with_awg,with_gvisor,with_xhttp,with_trusttunnel
TAGS ?= with_quic,$(PROTO_TAGS)
LDFLAGS := -s -w -buildid=
ifneq ($(RELEASE_VERSION),)
LDFLAGS += -X github.com/ordo-systems/keen-proxy/internal/api.releaseVersion=$(RELEASE_VERSION)
LDFLAGS += -X github.com/ordo-systems/keen-proxy/internal/api.releaseRevision=$(RELEASE_REVISION)
endif

# Use the compiler pinned by go.mod, not whichever Go is on PATH.
GO ?= env GOTOOLCHAIN=go$(shell awk '$$1 == "go" {print $$2}' go.mod) go

# Prefer an installed nvm Node 22 toolchain; Vite needs Node 20.19+ or 22.12+.
NODE_BIN ?= $(shell ls -d $(HOME)/.nvm/versions/node/v22.*/bin 2>/dev/null | tail -1)
NPM := PATH="$(NODE_BIN):$$PATH" npm
# Preview identity is separate from the last published installer version.
DEMO_VERSION = $(shell PATH="$(NODE_BIN):$$PATH" node -p "require('./web/src/demo/release.json').version")

.PHONY: test vet web build ui-demo build-router build-router-lite clean integration test-install check-language docs docs-preview

check-language:
	python3 -B -m unittest discover -s test/language -v
	python3 tools/check-language.py

test-install:
	python3 -B -m unittest discover -s test/install -v

test: check-language test-install
	$(GO) test -tags $(TAGS) ./internal/... ./cmd/...
	$(GO) test -tags keenproxy_lite,$(PROTO_TAGS) ./internal/engine/ ./internal/links/

vet:
	$(GO) vet -tags $(TAGS) ./...
	$(GO) vet -tags keenproxy_lite,$(PROTO_TAGS) ./internal/engine/ ./internal/links/

# Embed the production web/dist assets when building with the ui tag.
web:
	cd web && $(NPM) ci --no-audit --no-fund && $(NPM) run build

build: web
	$(GO) build -tags $(TAGS),ui -o bin/keenproxy ./cmd/keenproxy

# Run the local preview without relabeling the normal development binary.
ui-demo: web
	$(GO) build -tags $(TAGS),ui -ldflags "-X github.com/ordo-systems/keen-proxy/internal/api.releaseVersion=v$(DEMO_VERSION)" -o bin/keenproxy-demo ./cmd/keenproxy
	mkdir -p bin/demo && ./bin/keenproxy-demo -ui-demo -config examples/demo.yaml

# Cross-compile Linux router binaries; x86 uses baseline v1 and 32-bit SSE2.
build-router: web
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 $(GO) build -tags $(TAGS),ui -trimpath -ldflags "$(LDFLAGS)" -o dist/keenproxy-linux-amd64 ./cmd/keenproxy
	CGO_ENABLED=0 GOOS=linux GOARCH=386 GO386=sse2 $(GO) build -tags $(TAGS),ui -trimpath -ldflags "$(LDFLAGS)" -o dist/keenproxy-linux-386 ./cmd/keenproxy
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5,softfloat $(GO) build -tags $(TAGS),ui -trimpath -ldflags "$(LDFLAGS)" -o dist/keenproxy-linux-armv5 ./cmd/keenproxy
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -tags $(TAGS),ui -trimpath -ldflags "$(LDFLAGS)" -o dist/keenproxy-linux-arm64 ./cmd/keenproxy
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat $(GO) build -tags $(TAGS),ui -trimpath -ldflags "$(LDFLAGS)" -o dist/keenproxy-linux-mipsle ./cmd/keenproxy
	CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat $(GO) build -tags $(TAGS),ui -trimpath -ldflags "$(LDFLAGS)" -o dist/keenproxy-linux-mipsbe ./cmd/keenproxy

# Use the reduced protocol registry for memory-constrained routers.
# See internal/engine/registry_lite.go for supported protocols.
LITE_TAGS := keenproxy_lite,$(PROTO_TAGS),ui
build-router-lite: web
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 $(GO) build -tags $(LITE_TAGS) -trimpath -ldflags "$(LDFLAGS)" -o dist/keenproxy-lite-linux-amd64 ./cmd/keenproxy
	CGO_ENABLED=0 GOOS=linux GOARCH=386 GO386=sse2 $(GO) build -tags $(LITE_TAGS) -trimpath -ldflags "$(LDFLAGS)" -o dist/keenproxy-lite-linux-386 ./cmd/keenproxy
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5,softfloat $(GO) build -tags $(LITE_TAGS) -trimpath -ldflags "$(LDFLAGS)" -o dist/keenproxy-lite-linux-armv5 ./cmd/keenproxy
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -tags $(LITE_TAGS) -trimpath -ldflags "$(LDFLAGS)" -o dist/keenproxy-lite-linux-arm64 ./cmd/keenproxy
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat $(GO) build -tags $(LITE_TAGS) -trimpath -ldflags "$(LDFLAGS)" -o dist/keenproxy-lite-linux-mipsle ./cmd/keenproxy
	CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat $(GO) build -tags $(LITE_TAGS) -trimpath -ldflags "$(LDFLAGS)" -o dist/keenproxy-lite-linux-mipsbe ./cmd/keenproxy

clean:
	rm -rf bin dist web/dist web/dist-demo site

# Build the documentation site with the browser demo, as the Pages workflow does.
DOCS_VENV := .venv-docs
DOCS_PORT ?= 8097
$(DOCS_VENV)/bin/mkdocs: requirements-docs.txt
	python3 -m venv $(DOCS_VENV)
	$(DOCS_VENV)/bin/pip install -q -r requirements-docs.txt
	touch $@

docs: $(DOCS_VENV)/bin/mkdocs
	DOCS_SITE_URL=http://localhost:$(DOCS_PORT)/ $(DOCS_VENV)/bin/mkdocs build --strict
	cd web && $(NPM) ci --no-audit --no-fund && $(NPM) run build:demo
	mkdir -p site/demo
	cp -R web/dist-demo/. site/demo/

# Serve the built site at http://localhost:$(DOCS_PORT)/ (Russian at /ru/, demo at /demo/).
docs-preview: docs
	python3 -m http.server $(DOCS_PORT) --bind 127.0.0.1 --directory site

# Exercise real interception inside disposable Docker network namespaces.
integration:
	CGO_ENABLED=0 GOOS=linux $(GO) build -tags $(TAGS) -o dist/keenproxy-test ./cmd/keenproxy
	CGO_ENABLED=0 GOOS=linux $(GO) build -tags $(TAGS) -o dist/sbserver-test ./test/netns/sbserver
	CGO_ENABLED=0 GOOS=linux $(GO) build -o dist/mkgeo-test ./test/netns/mkgeo
	docker run --rm --privileged -v $(CURDIR)/dist/keenproxy-test:/work/keenproxy:ro \
		-v $(CURDIR)/dist/sbserver-test:/work/sbserver:ro \
		-v $(CURDIR)/dist/mkgeo-test:/work/mkgeo:ro \
		-v $(CURDIR)/test/netns/run.sh:/work/run.sh:ro debian:bookworm-slim sh -c '\
		apt-get -qq update >/dev/null && apt-get -qq install -y --no-install-recommends \
		iptables iproute2 dnsmasq-base curl dnsutils python3 >/dev/null 2>&1 && sh /work/run.sh'
