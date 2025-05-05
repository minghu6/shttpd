
bump-verson:
	cargo ws version --no-individual-tags

clean-ice:
	trash rustc-ice-2025*.txt

build:
	cargo build --all-features
