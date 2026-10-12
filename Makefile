.PHONY: test build
test:
	python3 -m unittest discover -s tests -v
build:
	docker build -t checkmarx-operator:dev .
