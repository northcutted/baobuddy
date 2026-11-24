VERSION ?= 0.1.0
BINARY := baobuddy-receiver
DIST := dist
LDFLAGS := -s -w -X main.version=$(VERSION)

RELEASE_PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/arm64 \
	darwin/amd64 \
	freebsd/amd64

PLATFORMS ?= $(RELEASE_PLATFORMS)
DIST_ASSETS := $(addprefix $(BINARY)-$(VERSION)-,$(subst /,-,$(sort $(RELEASE_PLATFORMS))))

.PHONY: test build dist clean

test:
	go test -race -v ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/baobuddy-receiver

dist:
	@set -eu; export LC_ALL=C; \
	mkdir -p "$(DIST)"; \
	stage=$$(mktemp -d "$(DIST)/.receiver-build.XXXXXXXX"); \
	trap 'rm -rf "$$stage"' EXIT; \
	for target in $(PLATFORMS); do \
		os=$${target%/*}; arch=$${target#*/}; \
		name="$(BINARY)-$(VERSION)-$${os}-$${arch}"; \
		echo "Building $$name"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o "$$stage/$$name" ./cmd/baobuddy-receiver; \
		test -f "$$stage/$$name" && test -s "$$stage/$$name" || { echo "Missing or empty output: $$name" >&2; exit 1; }; \
	done; \
	(cd "$$stage"; set -- $(BINARY)-*; \
		test "$$#" -eq $(words $(DIST_ASSETS)) || { echo "Incomplete or unexpected receiver artifact set" >&2; exit 1; }; \
		shasum -a 256 $(DIST_ASSETS) > SHA256SUMS.txt); \
	mkdir "$(DIST)/.receiver-publish" || { echo "Receiver distribution already being published in $(DIST)" >&2; exit 1; }; \
	trap 'rmdir "$(DIST)/.receiver-publish"; rm -rf "$$stage"' EXIT; \
	rm -f "$(DIST)/SHA256SUMS.txt" "$(DIST)"/$(BINARY)-*; \
	mv "$$stage"/$(BINARY)-* "$(DIST)/"; \
	mv "$$stage/SHA256SUMS.txt" "$(DIST)/"

clean:
	rm -rf $(BINARY) $(DIST)
