setup:
	rustup component add rustfmt
	rustup component add clippy
	cargo install cargo-deny

build:
	cargo build --locked --release

lint:
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings
	cargo deny check

fix:
	cargo fmt
	cargo clippy --locked --all-targets --fix --allow-dirty --allow-staged -- -D warnings

test:
	cargo test --locked
