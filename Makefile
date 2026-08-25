.PHONY: all matrix verify

all: matrix

matrix:
	./scripts/build-matrix.sh

verify:
	./scripts/verify-matrix.sh
