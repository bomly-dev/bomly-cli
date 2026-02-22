BINARY_NAME=bomly
LITE_BUILD_TAGS=bomly_external_syft,bomly_external_grype

.PHONY: build build-full build-lite test run generate docs-config docs-schema docs-schema-md docs-support-matrix smoke

build: build-full build-lite

build-full:
	go build -o bin/$(BINARY_NAME) ./cmd/bomly

build-lite:
	go build -tags "$(LITE_BUILD_TAGS)" -o bin/$(BINARY_NAME)-lite ./cmd/bomly

test:
	go test ./...

smoke:
	go test -tags "smoke" ./test/smoke/ -v -count=1 -timeout 15m $(if $(ARGS),$(ARGS),)

run:
	go run ./cmd/bomly $(ARGS)

generate: docs-config docs-schema docs-schema-md docs-support-matrix

docs-config:
	cd internal/cli && go run config_gen.go

docs-schema:
	cd internal/viewmodel && go run schema_gen.go

docs-schema-md:
	cd internal/viewmodel && go run schema_docs_gen.go

docs-support-matrix:
	cd internal/scan && go run support_matrix_gen.go
