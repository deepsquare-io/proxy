GO_SRCS := $(shell find . -type f -name '*.go' -a ! \( -name 'zz_generated*' -o -name '*_test.go' \))
GO_TESTS := $(shell find . -type f -name '*_test.go')
TAG_NAME = $(shell git describe --tags --abbrev=0 --exact-match 2>/dev/null)
TAG_NAME_DEV = $(shell git describe --tags --abbrev=0 2>/dev/null)
VERSION_CORE = $(shell echo $(TAG_NAME))
VERSION_CORE_DEV = $(shell echo $(TAG_NAME_DEV))
GIT_COMMIT = $(shell git rev-parse --short=7 HEAD)
VERSION = $(or $(and $(TAG_NAME),$(VERSION_CORE)),$(and $(TAG_NAME_DEV),$(VERSION_CORE_DEV)-dev),$(GIT_COMMIT))

wgo :=  $(shell which wgo)
ifeq ($(wgo),)
wgo := $(shell go env GOPATH)/bin/wgo
endif

golint := $(shell which golangci-lint)
ifeq ($(golint),)
golint := $(shell go env GOPATH)/bin/golangci-lint
endif

migrate := $(shell which migrate)
ifeq ($(migrate),)
migrate := $(shell go env GOPATH)/bin/migrate
endif

sqlc := $(shell which sqlc)
ifeq ($(sqlc),)
sqlc := $(shell go env GOPATH)/bin/sqlc
endif

.PHONY: build
build: bin/dpsproxy-server bin/dpsproxy

.PHONY: bin/dpsproxy-server
bin/dpsproxy-server: $(GO_SRCS)
	go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy-server/main.go

.PHONY: bin/dpsproxy
bin/dpsproxy: $(GO_SRCS)
	go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy/main.go


bin/checksums.txt: $(addprefix bin/,$(bins))
	sha256sum -b $(addprefix bin/,$(bins)) | sed 's/bin\///' > $@

bin/checksums.md: bin/checksums.txt
	@echo "### SHA256 Checksums" > $@
	@echo >> $@
	@echo "\`\`\`" >> $@
	@cat $< >> $@
	@echo "\`\`\`" >> $@

bin/dpsproxy-server-darwin-amd64: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy-server/main.go

bin/dpsproxy-server-darwin-arm64: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy-server/main.go

bin/dpsproxy-server-freebsd-amd64: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy-server/main.go

bin/dpsproxy-server-freebsd-arm64: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy-server/main.go

bin/dpsproxy-server-linux-amd64: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy-server/main.go

bin/dpsproxy-server-linux-arm64: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy-server/main.go

bin/dpsproxy-server-linux-riscv64: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=linux GOARCH=riscv64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy-server/main.go

bin/dpsproxy-server-windows-amd64.exe: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy-server/main.go

bin/dpsproxy-darwin-amd64: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy/main.go

bin/dpsproxy-darwin-arm64: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy/main.go

bin/dpsproxy-freebsd-amd64: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy/main.go

bin/dpsproxy-freebsd-arm64: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy/main.go

bin/dpsproxy-linux-amd64: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy/main.go

bin/dpsproxy-linux-arm64: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy/main.go

bin/dpsproxy-linux-riscv64: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=linux GOARCH=riscv64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy/main.go

bin/dpsproxy-windows-amd64.exe: $(GO_SRCS)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./cmd/dpsproxy/main.go

bins := dpsproxy-server-darwin-amd64 dpsproxy-server-darwin-arm64 dpsproxy-server-freebsd-arm64 dpsproxy-server-freebsd-arm64 dpsproxy-server-linux-amd64 dpsproxy-server-linux-arm64 dpsproxy-server-linux-riscv64 dpsproxy-server-windows-amd64.exe dpsproxy-darwin-amd64 dpsproxy-darwin-arm64 dpsproxy-freebsd-arm64 dpsproxy-freebsd-arm64 dpsproxy-linux-amd64 dpsproxy-linux-arm64 dpsproxy-linux-riscv64 dpsproxy-windows-amd64.exe

.PHONY: build-all
build-all: $(addprefix bin/,$(bins)) bin/checksums.md

.PHONY: run
run: bin/dpsproxy-server
	@bin/dpsproxy-server

.PHONY: watch
watch: $(wgo)
	$(wgo) -xdir "gen/" -xdir "bin/" -xfile ".*\.sql" sh -c 'make run || exit 1' --signal SIGTERM

.PHONY: lint
lint: $(golint)
	$(golint) run ./...

.PHONY: clean
clean:
	rm -rf bin/

.PHONY: sql
sql: $(sqlc)
	$(sqlc) generate

.PHONY: migration
migration: $(migrate)
	$(migrate) create -seq -ext sql -dir database/migrations $(MIGRATION_NAME)

.PHONY: up
up: $(MIGRATIONS) $(migrate)
	$(migrate) -path database/migrations -database sqlite3://db.sqlite3?x-no-tx-wrap=true up

.PHONY: drop
drop: $(migrate)
	$(migrate) -path database/migrations -database sqlite3://db.sqlite3?x-no-tx-wrap=true drop -f

$(migrate):
	go install -tags 'sqlite3' github.com/golang-migrate/migrate/v4/cmd/migrate

$(wgo):
	go install github.com/bokwoon95/wgo@latest

$(golint):
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

$(sqlc):
	go install github.com/sqlc-dev/sqlc/cmd/sqlc

.PHONY: version
version:
	@echo VERSION_CORE=${VERSION_CORE}
	@echo VERSION_CORE_DEV=${VERSION_CORE_DEV}
	@echo VERSION=${VERSION}
