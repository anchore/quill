BIN = quill
TEMP_DIR = ./.tmp
RESULTS_DIR = test/results
COVER_REPORT = $(RESULTS_DIR)/unit-coverage-details.txt
COVER_TOTAL = $(RESULTS_DIR)/unit-coverage-summary.txt
LINTCMD = $(TEMP_DIR)/golangci-lint run --tests=false --timeout=2m --config .golangci.yaml
GOIMPORTS_CMD = $(TEMP_DIR)/gosimports -local github.com/anchore
RELEASE_CMD = $(TEMP_DIR)/goreleaser release --rm-dist
SNAPSHOT_CMD = $(RELEASE_CMD) --skip-publish --snapshot --skip-sign
VERSION=$(shell git describe --dirty --always --tags)

# formatting
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)
# the quality gate lower threshold for unit test total % coverage (by function statements)
COVERAGE_THRESHOLD := 30
# CI cache busting values; change these if you want CI to not use previous stored cache
BOOTSTRAP_CACHE="c7afb99ad"

# ci dependency versions
QUILL_VERSION = latest
GOLANG_CI_VERSION = v1.49.0
GOBOUNCER_VERSION = v0.4.0
GORELEASER_VERSION = v1.11.5
GOSIMPORTS_VERSION = v0.3.2
CHRONICLE_VERSION = v0.4.1

## Build variables
DIST_DIR = dist
SNAPSHOT_DIR = snapshot
OS=$(shell uname | tr '[:upper:]' '[:lower:]')
SNAPSHOT_BIN=$(realpath $(shell pwd)/$(SNAPSHOT_DIR)/$(OS)-build_$(OS)_amd64_v1/$(BIN))

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

.PHONY: bootstrap-tools
bootstrap-tools: $(TEMP_DIR)
	#GOBIN="$(realpath $(TEMP_DIR))" go install github.com/anchore/quill/cmd/quill@$(QUILL_VERSION)
	GOBIN="$(realpath $(TEMP_DIR))" go install ./cmd/quill
	curl -sSfL https://raw.githubusercontent.com/anchore/chronicle/main/install.sh | sh -s -- -b $(TEMP_DIR)/ $(CHRONICLE_VERSION)
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMP_DIR)/ $(GOLANG_CI_VERSION)
	curl -sSfL https://raw.githubusercontent.com/wagoodman/go-bouncer/master/bouncer.sh | sh -s -- -b $(TEMP_DIR)/ $(GOBOUNCER_VERSION)
	GOBIN="$(realpath $(TEMP_DIR))" go install github.com/goreleaser/goreleaser@$(GORELEASER_VERSION)
	GOBIN="$(realpath $(TEMP_DIR))" go install github.com/rinchsan/gosimports/cmd/gosimports@$(GOSIMPORTS_VERSION)

.PHONY: bootstrap-go
bootstrap-go:
	go mod download

.PHONY: bootstrap
bootstrap: $(RESULTS_DIR) bootstrap-go bootstrap-tools ## Download and install all go dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Bootstrapping dependencies)

.PHONY: static-analysis
static-analysis: lint check-go-mod-tidy check-licenses

.PHONY: lint
lint: ## Run gofmt + golangci lint checks
	$(call title,Running linters)
	# ensure there are no go fmt differences
	@printf "files with gofmt issues: [$(shell gofmt -l -s .)]\n"
	@test -z "$(shell gofmt -l -s .)"

	# run all golangci-lint rules
	$(LINTCMD)
	@[ -z "$(shell $(GOIMPORTS_CMD) -d .)" ] || (echo "goimports needs to be fixed" && false)

	# go tooling does not play well with certain filename characters, ensure the common cases don't result in future "go get" failures
	$(eval MALFORMED_FILENAMES := $(shell find . | grep -e ':'))
	@bash -c "[[ '$(MALFORMED_FILENAMES)' == '' ]] || (printf '\nfound unsupported filename characters:\n$(MALFORMED_FILENAMES)\n\n' && false)"

.PHONY: lint-fix
lint-fix: ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	gofmt -w -s .
	$(GOIMPORTS_CMD) -w .
	$(LINTCMD) --fix
	go mod tidy

.PHONY: check-licenses
check-licenses:
	$(TEMP_DIR)/bouncer check ./...

check-go-mod-tidy:
	@ .github/scripts/go-mod-tidy-check.sh && echo "go.mod and go.sum are tidy!"

.PHONY: unit
unit: $(RESULTS_DIR)  ## Run unit tests (with coverage)
	$(call title,Running unit tests)
	# we don't do tests in parallel due to test fixture creation collisions
	go test -p 1 -coverprofile $(COVER_REPORT) $(shell go list ./... | grep -v anchore/quill/test)
	@go tool cover -func $(COVER_REPORT) | grep total |  awk '{print substr($$3, 1, length($$3)-1)}' > $(COVER_TOTAL)
	@echo "Coverage: $$(cat $(COVER_TOTAL))"
	@if [ $$(echo "$$(cat $(COVER_TOTAL)) >= $(COVERAGE_THRESHOLD)" | bc -l) -ne 1 ]; then echo "$(RED)$(BOLD)Failed coverage quality gate (> $(COVERAGE_THRESHOLD)%)$(RESET)" && false; fi

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
changelog: clean-changelog CHANGELOG.md
	@docker run -it --rm \
		-v $(shell pwd)/CHANGELOG.md:/CHANGELOG.md \
		rawkode/mdv \
			-t 748.5989 \
			/CHANGELOG.md

CHANGELOG.md:
	$(TEMP_DIR)/chronicle -vv > CHANGELOG.md

.PHONY: release
release: clean-dist ## Build and publish final binaries and packages
	$(call title,Publishing release artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(DIST_DIR)" > $(TEMP_DIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMP_DIR)/goreleaser.yaml

	$(RELEASE_CMD) --config $(TEMP_DIR)/goreleaser.yaml

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
	rm -f CHANGELOG.md

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'
