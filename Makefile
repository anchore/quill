TEMPDIR = ./.tmp
RESULTSDIR = test/results
COVER_REPORT = $(RESULTSDIR)/unit-coverage-details.txt
COVER_TOTAL = $(RESULTSDIR)/unit-coverage-summary.txt
LINTCMD = $(TEMPDIR)/golangci-lint run --tests=false --timeout=2m --config .golangci.yaml
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

## Build variables
DISTDIR=./dist
SNAPSHOTDIR=./snapshot
GITTREESTATE=$(if $(shell git status --porcelain),dirty,clean)

ifeq "$(strip $(VERSION))" ""
 override VERSION = $(shell git describe --always --tags --dirty)
endif

## Variable assertions

ifndef TEMPDIR
	$(error TEMPDIR is not set)
endif

ifndef RESULTSDIR
	$(error RESULTSDIR is not set)
endif

ifndef DISTDIR
	$(error DISTDIR is not set)
endif

ifndef SNAPSHOTDIR
	$(error SNAPSHOTDIR is not set)
endif

ifndef REF_NAME
	REF_NAME = $(VERSION)
endif

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef

## Tasks

.PHONY: all
all: clean bootstrap static-analysis test ## Run all linux-based checks (linting, license check, unit, integration, and linux acceptance tests)
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

.PHONY: test
test: unit ## Run all tests (currently unit, integration, linux acceptance, and cli tests)

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

.PHONY: ci-bootstrap
ci-bootstrap:
	DEBIAN_FRONTEND=noninteractive sudo apt update && sudo -E apt install -y bc jq libxml2-utils

$(RESULTSDIR):
	mkdir -p $(RESULTSDIR)

$(TEMPDIR):
	mkdir -p $(TEMPDIR)

.PHONY: bootstrap-tools
bootstrap-tools: $(TEMPDIR)
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMPDIR)/ v1.42.1
	curl -sSfL https://raw.githubusercontent.com/wagoodman/go-bouncer/master/bouncer.sh | sh -s -- -b $(TEMPDIR)/ v0.2.0
	curl -sSfL https://raw.githubusercontent.com/anchore/chronicle/main/install.sh | sh -s -- -b $(TEMPDIR)/ v0.3.0
	.github/scripts/goreleaser-install.sh -b $(TEMPDIR)/ v0.177.0

.PHONY: bootstrap-go
bootstrap-go:
	go mod download

.PHONY: bootstrap
bootstrap: $(RESULTSDIR) bootstrap-go bootstrap-tools ## Download and install all go dependencies (+ prep tooling in the ./tmp dir)
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

	# go tooling does not play well with certain filename characters, ensure the common cases don't result in future "go get" failures
	$(eval MALFORMED_FILENAMES := $(shell find . | grep -e ':'))
	@bash -c "[[ '$(MALFORMED_FILENAMES)' == '' ]] || (printf '\nfound unsupported filename characters:\n$(MALFORMED_FILENAMES)\n\n' && false)"

.PHONY: lint-fix
lint-fix: ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	gofmt -w -s .
	$(LINTCMD) --fix
	go mod tidy

.PHONY: check-licenses
check-licenses:
	$(TEMPDIR)/bouncer check

check-go-mod-tidy:
	@ .github/scripts/go-mod-tidy-check.sh && echo "go.mod and go.sum are tidy!"

.PHONY: unit
unit: $(RESULTSDIR)  ## Run unit tests (with coverage)
	$(call title,Running unit tests)
	# we don't do tests in parallel due to test fixture creation collisions
	go test -p 1  -coverprofile $(COVER_REPORT) $(shell go list ./... )
	@go tool cover -func $(COVER_REPORT) | grep total |  awk '{print substr($$3, 1, length($$3)-1)}' > $(COVER_TOTAL)
	@echo "Coverage: $$(cat $(COVER_TOTAL))"
	@if [ $$(echo "$$(cat $(COVER_TOTAL)) >= $(COVERAGE_THRESHOLD)" | bc -l) -ne 1 ]; then echo "$(RED)$(BOLD)Failed coverage quality gate (> $(COVERAGE_THRESHOLD)%)$(RESET)" && false; fi

.PHONY: build
build: $(SNAPSHOTDIR) ## Build release snapshot binaries and packages

$(SNAPSHOTDIR): ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)
	# create a config with the dist dir overridden
	echo "dist: $(SNAPSHOTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	# build release snapshots
	# DOCKER_CLI_EXPERIMENTAL needed to support multi architecture builds for goreleaser
	BUILD_GIT_TREE_STATE=$(GITTREESTATE) \
	DOCKER_CLI_EXPERIMENTAL=enabled \
	$(TEMPDIR)/goreleaser release --skip-publish --skip-sign --rm-dist --snapshot --config $(TEMPDIR)/goreleaser.yaml

.PHONY: changelog
changelog: clean-changelog CHANGELOG.md
	@docker run -it --rm \
		-v $(shell pwd)/CHANGELOG.md:/CHANGELOG.md \
		rawkode/mdv \
			-t 748.5989 \
			/CHANGELOG.md

CHANGELOG.md:
	$(TEMPDIR)/chronicle -vv > CHANGELOG.md

.PHONY: release
release: clean-dist CHANGELOG.md  ## Build and publish final binaries and packages. Intended to be run only on macOS.
	$(call title,Publishing release artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(DISTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	# release (note the version transformation from v0.7.0 --> 0.7.0)
	# DOCKER_CLI_EXPERIMENTAL needed to support multi architecture builds for goreleaser
	bash -c "\
		BUILD_GIT_TREE_STATE=$(GITTREESTATE) \
		VERSION=$(VERSION:v%=%) \
		DOCKER_CLI_EXPERIMENTAL=enabled \
		$(TEMPDIR)/goreleaser \
			--rm-dist \
			--config $(TEMPDIR)/goreleaser.yaml \
			--release-notes <(cat CHANGELOG.md)"

.PHONY: clean
clean: clean-dist clean-snapshot  ## Remove previous builds, result reports, and test cache
	rm -rf $(RESULTSDIR)/*

.PHONY: clean-snapshot
clean-snapshot:
	rm -rf $(SNAPSHOTDIR) $(TEMPDIR)/goreleaser.yaml

.PHONY: clean-dist
clean-dist: clean-changelog
	rm -rf $(DISTDIR) $(TEMPDIR)/goreleaser.yaml

.PHONY: clean-changelog
clean-changelog:
	rm -f CHANGELOG.md

