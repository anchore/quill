BIN = quill
TEMP_DIR = ./.tmp
RESULTS_DIR = test/results
COVER_REPORT = $(RESULTS_DIR)/unit-coverage-details.txt
COVER_TOTAL = $(RESULTS_DIR)/unit-coverage-summary.txt

# Command templates #################################
LINT_CMD = $(TEMP_DIR)/golangci-lint run --tests=false --timeout=2m --config .golangci.yaml
GOIMPORTS_CMD = $(TEMP_DIR)/gosimports -local github.com/anchore
RELEASE_CMD = $(TEMP_DIR)/goreleaser release --clean
SNAPSHOT_CMD = $(RELEASE_CMD) --clean --snapshot --skip=publish --skip=sign
CHRONICLE_CMD = $(TEMP_DIR)/chronicle
GLOW_CMD = $(TEMP_DIR)/glow

# Tool versions #################################
QUILL_VERSION = latest
GOLANG_CI_VERSION = v1.64.2
GOBOUNCER_VERSION = v0.4.0
GORELEASER_VERSION = v2.3.2
GOSIMPORTS_VERSION = v0.3.8
CHRONICLE_VERSION = v0.8.0
GLOW_VERSION := v1.5.0

# Formatting variables #################################
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

# Test variables #################################
# the quality gate lower threshold for unit test total % coverage (by function statements)
COVERAGE_THRESHOLD := 25

## Build variables #################################
DIST_DIR = dist
SNAPSHOT_DIR = snapshot
OS=$(shell uname | tr '[:upper:]' '[:lower:]')
SNAPSHOT_BIN=$(realpath $(shell pwd)/$(SNAPSHOT_DIR)/$(OS)-build_$(OS)_amd64_v1/$(BIN))
CHANGELOG := CHANGELOG.md
VERSION=$(shell git describe --dirty --always --tags)

ifeq "$(strip $(VERSION))" ""
 override VERSION = $(shell git describe --always --tags --dirty)
endif

## Variable assertions

ifndef TEMP_DIR
	$(error TEMP_DIR is not set)
endif

ifndef RESULTS_DIR
	$(error RESULTS_DIR is not set)
endif

ifndef DIST_DIR
	$(error DIST_DIR is not set)
endif

ifndef SNAPSHOT_DIR
	$(error SNAPSHOT_DIR is not set)
endif

ifndef REF_NAME
	REF_NAME = $(VERSION)
endif

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef

## Tasks

.PHONY: all
all: clean static-analysis test ## Run all linux-based checks (linting, license check, unit, integration, and linux acceptance tests)
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

.PHONY: test
test: unit cli ## Run all tests (currently unit and cli tests)

$(RESULTS_DIR):
	mkdir -p $(RESULTS_DIR)

$(TEMP_DIR):
	mkdir -p $(TEMP_DIR)


## Bootstrapping targets #################################

.PHONY: bootstrap-tools
bootstrap-tools: $(TEMP_DIR)
	#GOBIN="$(realpath $(TEMP_DIR))" go install github.com/anchore/quill/cmd/quill@$(QUILL_VERSION)
	GOBIN="$(realpath $(TEMP_DIR))" go install ./cmd/quill
	curl -sSfL https://get.anchore.io/chronicle | sh -s -- -b $(TEMP_DIR)/ $(CHRONICLE_VERSION)
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMP_DIR)/ $(GOLANG_CI_VERSION)
	curl -sSfL https://raw.githubusercontent.com/wagoodman/go-bouncer/master/bouncer.sh | sh -s -- -b $(TEMP_DIR)/ $(GOBOUNCER_VERSION)
	GOBIN="$(realpath $(TEMP_DIR))" go install github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION)
	GOBIN="$(realpath $(TEMP_DIR))" go install github.com/rinchsan/gosimports/cmd/gosimports@$(GOSIMPORTS_VERSION)
	GOBIN="$(realpath $(TEMP_DIR))" go install github.com/charmbracelet/glow@$(GLOW_VERSION)

.PHONY: bootstrap-go
bootstrap-go:
	go mod download

.PHONY: bootstrap
bootstrap: $(RESULTS_DIR) bootstrap-go bootstrap-tools ## Download and install all go dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Bootstrapping dependencies)


## Static analysis targets #################################

.PHONY: static-analysis
static-analysis: lint check-go-mod-tidy check-licenses

.PHONY: lint
lint: ## Run gofmt + golangci lint checks
	$(call title,Running linters)
	# ensure there are no go fmt differences
	@printf "files with gofmt issues: [$(shell gofmt -l -s .)]\n"
	@test -z "$(shell gofmt -l -s .)"

	# run all golangci-lint rules
	$(LINT_CMD)
	@[ -z "$(shell $(GOIMPORTS_CMD) -d .)" ] || (echo "goimports needs to be fixed" && false)

	# go tooling does not play well with certain filename characters, ensure the common cases don't result in future "go get" failures
	$(eval MALFORMED_FILENAMES := $(shell find . | grep -e ':'))
	@bash -c "[[ '$(MALFORMED_FILENAMES)' == '' ]] || (printf '\nfound unsupported filename characters:\n$(MALFORMED_FILENAMES)\n\n' && false)"

.PHONY: format
format: ## Auto-format all source code
	$(call title,Running formatters)
	gofmt -w -s .
	$(GOIMPORTS_CMD) -w .
	go mod tidy

.PHONY: lint-fix
lint-fix: format  ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	$(LINT_CMD) --fix

.PHONY: check-licenses
check-licenses:
	$(TEMP_DIR)/bouncer check ./...

check-go-mod-tidy:
	@ .github/scripts/go-mod-tidy-check.sh && echo "go.mod and go.sum are tidy!"


## Testing targets #################################

.PHONY: unit
unit: $(TEMP_DIR)  ## Run unit tests (with coverage)
	$(call title,Running unit tests)
	go test -coverprofile $(TEMP_DIR)/unit-coverage-details.txt $(shell go list ./... | grep -v anchore/quill/test)
	@.github/scripts/coverage.py $(COVERAGE_THRESHOLD) $(TEMP_DIR)/unit-coverage-details.txt


## Test-fixture-related targets #################################

# note: this is used by CI to determine if various test fixture cache should be restored or recreated
fingerprints:
	$(call title,Creating all test cache input fingerprints)

	# for INSTALL integration test fixtures
	cd test/install && \
		make cache.fingerprint


## install.sh testing targets #################################

install-test: $(SNAPSHOT_DIR)
	cd test/install && \
		make

install-test-cache-save: $(SNAPSHOT_DIR)
	cd test/install && \
		make save

install-test-cache-load: $(SNAPSHOT_DIR)
	cd test/install && \
		make load


## Code generation targets #################################

.PHONY: update-apple-certs
update-apple-certs:  ## Update the apple certs checked into the repo
	$(call title,Updating Apple certs)
	go generate ./...


## Build-related targets #################################

.PHONY: build
build: $(SNAPSHOT_DIR) ## Build release snapshot binaries and packages

$(SNAPSHOT_DIR): ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(SNAPSHOT_DIR)" > $(TEMP_DIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMP_DIR)/goreleaser.yaml

	# build release snapshots
	bash -c "\
		VERSION=$(VERSION:v%=%) \
		$(SNAPSHOT_CMD) --config $(TEMP_DIR)/goreleaser.yaml \
	  "

.PHONY: cli
cli: $(SNAPSHOT_DIR) ## Run CLI tests
	chmod 755 "$(SNAPSHOT_BIN)"
	$(SNAPSHOT_BIN) version
	go test -count=1 -timeout=15m -v ./test/cli

.PHONY: changelog
changelog: clean-changelog  ## Generate and show the changelog for the current unreleased version
	$(CHRONICLE_CMD) -vvv -n --version-file VERSION > $(CHANGELOG)
	@$(GLOW_CMD) $(CHANGELOG)

$(CHANGELOG):
	$(CHRONICLE_CMD) -vvv > $(CHANGELOG)

.PHONY: release
release:  ## Cut a new release
	@.github/scripts/trigger-release.sh

.PHONY: release
ci-release: ci-check clean-dist $(CHANGELOG)
	$(call title,Publishing release artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(DIST_DIR)" > $(TEMP_DIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMP_DIR)/goreleaser.yaml

	bash -c "$(RELEASE_CMD) --release-notes <(cat CHANGELOG.md) --config $(TEMP_DIR)/goreleaser.yaml"

.PHONY: ci-check
ci-check:
	@.github/scripts/ci-check.sh

## Cleanup targets #################################

.PHONY: clean
clean: clean-dist clean-snapshot  ## Remove previous builds, result reports, and test cache
	rm -rf $(RESULTS_DIR)/*

.PHONY: clean-snapshot
clean-snapshot:
	rm -rf $(SNAPSHOT_DIR) $(TEMP_DIR)/goreleaser.yaml

.PHONY: clean-dist
clean-dist: clean-changelog
	rm -rf $(DIST_DIR) $(TEMP_DIR)/goreleaser.yaml

.PHONY: clean-changelog
clean-changelog:
	rm -f $(CHANGELOG) VERSION


## Halp! #################################

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
