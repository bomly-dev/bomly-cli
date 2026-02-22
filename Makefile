BINARY_NAME=bomly
BUILD_TAGS=bomly_builtin_syft,bomly_builtin_grype

.PHONY: build build-lite test run generate docs-config docs-schema docs-schema-md docs-support-matrix smoke

build: build-builtin build-lite

build-builtin:
	go build -tags "$(BUILD_TAGS)" -o bin/$(BINARY_NAME) ./cmd/bomly

build-lite:
	go build -o bin/$(BINARY_NAME)-lite ./cmd/bomly

test:
	go test -tags "$(BUILD_TAGS)" ./...

smoke:
	go test -tags "smoke,$(BUILD_TAGS)" ./test/smoke/ -v -count=1 -timeout 15m $(if $(ARGS),$(ARGS),)

run:
	go run -tags "$(BUILD_TAGS)" ./cmd/bomly $(ARGS)

generate: docs-config docs-schema docs-schema-md docs-support-matrix

docs-config:
	cd internal/cli && go run config_gen.go

docs-schema:
	cd internal/viewmodel && go run schema_gen.go

docs-schema-md:
	cd internal/viewmodel && go run schema_docs_gen.go

docs-support-matrix:
	cd internal/scan && go run support_matrix_gen.go