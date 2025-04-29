
bump-verson:
	cargo ws version --no-individual-tags

build-dev:
	cargo build
	sudo setcap 'cap_net_bind_service=+ep' target/debug/shttpd

test-example-1: build-dev
	@ RUST_LOG=trace cargo run -- -c examples/example-1/Shttpd.toml

clean-example-1:
	rm -rf examples/example-1/log/
