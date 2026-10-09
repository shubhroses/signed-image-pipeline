# Local entry points. They need docker and nothing else.
#
#   make build   build the image as signed-image-pipeline:local
#   make scan    build it and run the scan gate on it

# The pinned tool images: the file the workflows load.
include versions.env

IMAGE := signed-image-pipeline:local
REVISION := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)

.PHONY: build scan

build:
	docker build --build-arg "REVISION=$(REVISION)" --tag "$(IMAGE)" .

# The gate of ci.yml, with the same flags: Trivy reads the image from a
# read-only tarball and fails on a fixable High or Critical finding that
# .trivyignore.yaml does not accept.
scan: build
	mkdir -p .cache
	docker save --output .cache/image.tar "$(IMAGE)"
	docker run --rm \
		--volume "$(CURDIR)/.cache/image.tar:/image.tar:ro" \
		--volume "$(CURDIR)/.trivyignore.yaml:/.trivyignore.yaml:ro" \
		"$(TRIVY_IMAGE)" image --input /image.tar --no-progress \
		--exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed \
		--ignorefile /.trivyignore.yaml --show-suppressed
