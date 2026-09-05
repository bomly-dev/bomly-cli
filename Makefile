BINARY_NAME=bomly
LITE_BUILD_TAGS=bomly_external_syft,bomly_external_grype
GOLANGCI_LINT_VERSION=v2.13.2
GO_LICENSES_VERSION=v1.6.0
GOPATH_BIN=$(shell go env GOPATH)/bin
EXE_SUFFIX=$(if $(filter Windows_NT,$(OS)),.exe,)
GOLANGCI_LINT=$(GOPATH_BIN)/golangci-lint$(EXE_SUFFIX)
FUZZTIME?=60s

.PHONY: build build-full build-lite fmt fmt-check lint install-hooks test smoke fuzz verify run generate evidence benchmark benchmark-report licenses

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

# verify runs everything that gates a push and records that it passed.
#
# The stamp is what .githooks/pre-push reads: a push is refused unless a
# passing stamp exists and is newer than every tracked source file. Keeping
# the run here rather than in the hook means it happens once, deliberately,
# instead of on every push attempt -- a six-minute hook gets bypassed, and a
# bypassed hook enforces nothing.
#
# SMOKE=1 adds the network-driven smoke suite and records that it ran.
# Generated-docs drift is checked too: it is a CI job, and it fails for edits
# that look unrelated to it.
verify:
	@rm -f .verify-stamp
	$(MAKE) fmt-check
	$(MAKE) lint
	go vet ./...
	go vet -tags "$(LITE_BUILD_TAGS)" ./...
	# The smoke suite is behind a build tag, so `go vet ./...` never compiles
	# it. Running it needs the network and several minutes; compiling it costs
	# a second and catches the failure that actually happens -- a smoke file
	# left un-updated by a change everything else absorbed.
	go vet -tags smoke ./test/smoke/...
	go build ./...
	go build -tags "$(LITE_BUILD_TAGS)" ./...
	go test ./...
	$(MAKE) generate
	@git diff --quiet -- docs/ || { \
		echo "verify: generated docs drifted; commit the result of 'make generate'" >&2; \
		git --no-pager diff --stat -- docs/ >&2; \
		exit 1; \
	}
	@if [ "$(SMOKE)" = "1" ]; then $(MAKE) smoke; fi
	@{ \
		echo "VERIFY_STATUS=pass"; \
		echo "VERIFY_AT=$$(date +%s)"; \
		echo "VERIFY_AT_HUMAN=$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		echo "VERIFY_SNAPSHOT=$$(./scripts/verify-snapshot.sh)"; \
		if [ "$(SMOKE)" = "1" ]; then echo "VERIFY_SMOKE=yes"; else echo "VERIFY_SMOKE=no"; fi; \
	} > .verify-stamp
	@echo "verify: passed; stamp written to .verify-stamp"

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
