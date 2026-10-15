# Proofline CLI

The command-line client for the [Proofline review API](https://proofline.sh/docs/).

Install with `curl -fsSL https://proofline.sh/cli | sh`, then run `proofline login`.
See the [CLI documentation](https://proofline.sh/docs/cli/) for commands.

Build from source with `cargo build --locked --release`. The pinned Rust toolchain
is installed by rustup. Run `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`,
`cargo test --locked` and `cargo deny check` before submitting a pull request.

`openapi.public.json` is the public API contract pinned for this revision.
Server compatibility is checked in the Proofline control plane.

Licensed under Apache-2.0.
