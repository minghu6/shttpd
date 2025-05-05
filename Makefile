
clean-ice:
	trash rustc-ice-2025*.txt

build:
	cargo build --all-features

bump-version: build
	cargo ws version --no-individual-tags
