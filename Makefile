BINARY_NAME=bomly
LITE_BUILD_TAGS=bomly_external_syft,bomly_external_grype
GOLANGCI_LINT_VERSION=v1.64.8
GO_LICENSES_VERSION=v1.6.0
LOCAL_BIN=$(CURDIR)/.tools/bin
EXE_SUFFIX=$(if $(filter Windows_NT,$(OS)),.exe,)
GOLANGCI_LINT=$(LOCAL_BIN)/golangci-lint$(EXE_SUFFIX)
GOLANGCI_LINT_STAMP=$(LOCAL_BIN)/.golangci-lint-$(GOLANGCI_LINT_VERSION)

ifeq ($(OS),Windows_NT)
LOCAL_BIN_PATH=$(subst /,\,$(LOCAL_BIN))
GOLANGCI_LINT_STAMP_PATH=$(subst /,\,$(GOLANGCI_LINT_STAMP))
MKDIR_LOCAL_BIN=if not exist "$(LOCAL_BIN_PATH)" mkdir "$(LOCAL_BIN_PATH)"
INSTALL_GOLANGCI_LINT=set "GOBIN=$(LOCAL_BIN)"&& go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
TOUCH_GOLANGCI_LINT_STAMP=type nul > "$(GOLANGCI_LINT_STAMP_PATH)"
else
MKDIR_LOCAL_BIN=mkdir -p "$(LOCAL_BIN)"
INSTALL_GOLANGCI_LINT=GOBIN="$(LOCAL_BIN)" go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
TOUCH_GOLANGCI_LINT_STAMP=touch "$(GOLANGCI_LINT_STAMP)"
endif

.PHONY: build build-full build-lite fmt fmt-check lint install-hooks test run generate docs-config docs-schema docs-schema-md docs-support-matrix smoke licenses

build: build-full build-lite

build-full:
	go build -o bin/$(BINARY_NAME) ./cmd/bomly

build-lite:
	go build -tags "$(LITE_BUILD_TAGS)" -o bin/$(BINARY_NAME)-lite ./cmd/bomly

fmt:
	go run ./internal/tools/gofmtcheck -w

fmt-check:
	go run ./internal/tools/gofmtcheck

$(GOLANGCI_LINT_STAMP):
	$(MKDIR_LOCAL_BIN)
	$(INSTALL_GOLANGCI_LINT)
	$(TOUCH_GOLANGCI_LINT_STAMP)

lint: $(GOLANGCI_LINT_STAMP)
	$(GOLANGCI_LINT) run

install-hooks:
	git config core.hooksPath .githooks

test:
	go test ./...

smoke:
	go test -tags "smoke" ./test/smoke/ -v -count=1 -timeout 15m $(if $(ARGS),$(ARGS),)

run:
	go run ./cmd/bomly $(ARGS)

generate: docs-config docs-schema docs-schema-md docs-support-matrix

docs-config:
	go run ./internal/support/cmd/configref

docs-schema:
	go run ./internal/support/cmd/schemajson

docs-schema-md:
	go run ./internal/support/cmd/schemadocs

docs-support-matrix:
	go run ./internal/support/cmd/supportmatrix

licenses:
	go run github.com/google/go-licenses@$(GO_LICENSES_VERSION) save ./... \
		--save_path=./licenses \
		--ignore github.com/bomly-dev/bomly-cli \
		--ignore github.com/xi2/xz \
		--ignore modernc.org/mathutil \
		--force
