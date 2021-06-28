# Makefile for whoisthere

all: build
.PHONY: all

build:
	@cargo build --locked
.PHONY: build

test: build
	@cargo test --locked
	@cargo fmt --all -- --check
.PHONY: build

lint:
	@cargo fmt --all --
.PHONY: lint

clean:
	@cargo clean
.PHONY: clean
