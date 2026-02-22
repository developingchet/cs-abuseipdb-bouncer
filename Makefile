PKGS := ./cmd/... ./internal/...
COVER_PROFILE ?= coverage.out

.PHONY: test test-race coverage coverage-func coverage-html coverage-check ci-test

test:
	go test $(PKGS)

test-race:
	go test -race $(PKGS)

coverage:
	go test -covermode=atomic -coverprofile=$(COVER_PROFILE) $(PKGS)

coverage-func: coverage
	go tool cover -func=$(COVER_PROFILE)

coverage-html: coverage
	go tool cover -html=$(COVER_PROFILE) -o coverage.html

coverage-check:
	bash scripts/test-coverage.sh

ci-test: test-race coverage-check
