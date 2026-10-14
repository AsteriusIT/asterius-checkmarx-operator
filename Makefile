.PHONY: test build scan
IMAGE ?= checkmarx-operator:dev
test:
	python3 -m unittest discover -s tests -v
build:
	docker build --pull -t $(IMAGE) .
scan: build
	trivy image --image-src docker --scanners vuln --ignore-unfixed --exit-code 1 $(IMAGE)
