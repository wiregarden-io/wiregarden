
GIT_COMMIT := $(shell git rev-parse --short HEAD)
NOW := $(shell date +%s)
CURRENT_VERSION := $(shell git tag -l | sort --version-sort -r | head -1 | sed 's/^v//')+$(NOW)-$(GIT_COMMIT)
NEXT_VERSION := $(shell ./scripts/version-next.bash || echo "0.0.0")~$(NOW)-$(GIT_COMMIT)
GOPATH := $(shell pwd)/.gopath
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

all: unstable

.PHONY: unstable
unstable:
	$(MAKE) dist/wiregarden VERSION=$(NEXT_VERSION)
	$(MAKE) deb VERSION=$(NEXT_VERSION)
	echo $(NEXT_VERSION) > dist/version

.PHONY: stable
stable:
	$(MAKE) dist/wiregarden VERSION=$(CURRENT_VERSION)
	$(MAKE) deb VERSION=$(CURRENT_VERSION)
	echo $(CURRENT_VERSION) > dist/version

dist/wiregarden:
	-mkdir -p dist
	go build -ldflags="-X github.com/wiregarden-io/wiregarden/cli.version=$(VERSION)" -a -o dist/wiregarden .

deb: dist/wiregarden_$(VERSION)_$(GOOS)_$(GOARCH).deb

dist/wiregarden_$(VERSION)_$(GOOS)_$(GOARCH).deb:
	VERSION="$(VERSION)" HERE=/pkg envsubst < .nfpm.yml.tmpl > .nfpm.yml
	docker run -u $(shell id -u) --rm \
		-v $(shell pwd):/pkg \
		goreleaser/nfpm:v1.10 pkg --config /pkg/.nfpm.yml --target /pkg/dist/wiregarden_$(VERSION)_$(GOOS)_$(GOARCH).deb

rpm: dist/wiregarden_$(VERSION)_$(GOOS)_$(GOARCH).rpm

dist/wiregarden_$(VERSION)_$(GOOS)_$(GOARCH).rpm:
	VERSION="$(VERSION)" HERE=/pkg envsubst < .nfpm.yml.tmpl > .nfpm.yml
	docker run -u $(shell id -u) --rm \
		-v $(shell pwd):/pkg \
		goreleaser/nfpm pkg --config /pkg/.nfpm.yml --target /pkg/dist/wiregarden_$(VERSION)_$(GOOS)_$(GOARCH).rpm

.PHONY: clean
clean:
	-$(RM) -r dist
	-$(RM) .nfpm.yml

.PHONY: distclean
distclean: clean
	-chmod -R u+rwX .gopath
	-$(RM) -r .gopath

