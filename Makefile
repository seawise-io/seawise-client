# All Go commands run inside a pinned toolchain image so results do not
# depend on the host. Set GO_DOCKER=0 to use a local Go toolchain instead.

GO_IMAGE ?= golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36
GO_CACHE_VOLUME ?= seawise-gomod
GO_DOCKER ?= 1
PKGS ?= ./...
IMAGE_TAG ?= seawise-client:local
VERSION ?= dev
CMDS ?= seawise seawise-agent

UID := $(shell id -u)
GID := $(shell id -g)

GOFLAGS_REPRO := -trimpath -buildvcs=false
LDFLAGS := -s -w -buildid= -X github.com/seawise/client/internal/constants.Version=$(VERSION)

ifeq ($(GO_DOCKER),1)
RUN := docker run --rm --init \
	--user $(UID):$(GID) \
	-v "$(CURDIR)":/src -w /src \
	-v $(GO_CACHE_VOLUME):/cache \
	-e GOMODCACHE=/cache/mod -e GOCACHE=/cache/build -e HOME=/tmp \
	-e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly \
	$(GO_IMAGE)
else
RUN :=
endif

.PHONY: all test race vet fmt fmt-fix cover build repro image cache-init cache-clean

all: fmt vet race

cache-init:
ifeq ($(GO_DOCKER),1)
	@docker volume inspect $(GO_CACHE_VOLUME) >/dev/null 2>&1 || docker volume create $(GO_CACHE_VOLUME) >/dev/null
	@docker run --rm -v $(GO_CACHE_VOLUME):/cache $(GO_IMAGE) sh -c 'mkdir -p /cache/mod /cache/build && chown -R $(UID):$(GID) /cache'
endif

test: cache-init
	$(RUN) go test -count=1 $(PKGS)

race: cache-init
	$(RUN) env CGO_ENABLED=1 go test -race -count=1 $(PKGS)

vet: cache-init
	$(RUN) go vet $(PKGS)

fmt: cache-init
	@out="$$($(RUN) gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

fmt-fix: cache-init
	$(RUN) gofmt -w .

cover: cache-init
	$(RUN) go test -count=1 -coverprofile=coverage.out $(PKGS)
	$(RUN) go tool cover -func=coverage.out | tail -n 1

build: cache-init
	@for c in $(CMDS); do \
		$(RUN) env CGO_ENABLED=0 go build $(GOFLAGS_REPRO) -ldflags="$(LDFLAGS)" -o dist/$$c ./cmd/$$c || exit 1; \
	done

repro: build
	@cd dist && sha256sum $(CMDS) > first.sha256
	@$(MAKE) --no-print-directory build >/dev/null
	@cd dist && sha256sum -c first.sha256

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE_TAG) .

cache-clean:
	-docker volume rm $(GO_CACHE_VOLUME)
