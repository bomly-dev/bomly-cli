BINARY_NAME=bomly
LITE_BUILD_TAGS=bomly_external_syft,bomly_external_grype
GOLANGCI_LINT_VERSION=v2.12.0
GO_LICENSES_VERSION=v1.6.0
GOPATH_BIN=$(shell go env GOPATH)/bin
EXE_SUFFIX=$(if $(filter Windows_NT,$(OS)),.exe,)
GOLANGCI_LINT=$(GOPATH_BIN)/golangci-lint$(EXE_SUFFIX)
FUZZTIME?=60s

.PHONY: build build-full build-lite fmt fmt-check lint install-hooks test smoke fuzz run generate evidence benchmark benchmark-report licenses

build: build-full build-lite

build-full:
	go build -o bin/$(BINARY_NAME)$(EXE_SUFFIX) ./cmd/bomly

build-lite:
	go build -tags "$(LITE_BUILD_TAGS)" -o bin/$(BINARY_NAME)-lite$(EXE_SUFFIX) ./cmd/bomly

fmt:
	go run ./internal/tools/gofmtcheck -w

fmt-check:
	go run ./internal/tools/gofmtcheck

$(GOLANGCI_LINT): Makefile
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run

install-hooks:
	git config core.hooksPath .githooks

test:
	go test ./...

smoke:
	go test -tags "smoke" ./test/smoke/ -v -count=1 -timeout 15m $(if $(ARGS),$(ARGS),)

fuzz:
	FUZZTIME="$(FUZZTIME)" scripts/run-fuzz.sh

evidence:
	go run ./internal/tools/publicevidence $(if $(CASE),-case $(CASE),)

benchmark: build-full
	bin/$(BINARY_NAME)$(EXE_SUFFIX) benchmark $(if $(ARGS),$(ARGS),)

benchmark-samples: build-lite
	go run ./internal/tools/benchmarkrun -output .benchmark-runs/performance -case canonical-sbom-scan -samples 5 -network-state offline -- \
		./bin/$(BINARY_NAME)-lite$(EXE_SUFFIX) scan --sbom --path test/smoke/testdata/sboms/go.spdx.json --detectors sbom --format json

benchmark-report:
	go run ./internal/tools/benchmarkreport

run:
	go run ./cmd/bomly $(ARGS)

generate: build-full
	./bin/$(BINARY_NAME)$(EXE_SUFFIX) internal docs-gen --output docs

licenses:
	go run github.com/google/go-licenses@$(GO_LICENSES_VERSION) save ./... \
		--save_path=./licenses \
		--ignore github.com/bomly-dev/bomly-cli \
		--ignore github.com/xi2/xz \
		--ignore modernc.org/mathutil \
		--force
	# go-licenses cannot classify modernc.org/mathutil, but its BSD-3-Clause
	# terms require shipping the notice with binary distributions: copy the
	# license text explicitly and fail the target if it is missing.
	mkdir -p licenses/modernc.org/mathutil
	cp "$$(go list -m -f '{{.Dir}}' modernc.org/mathutil)/LICENSE" licenses/modernc.org/mathutil/LICENSE
	test -s licenses/modernc.org/mathutil/LICENSE
