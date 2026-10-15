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

## Publishing

GitHub Actions checks pull requests and main. Run `Release` on main with
`publish=false` to build all four Linux/macOS archives without publishing.
A `vX.Y.Z` tag equal to Cargo's version, or a main dispatch with `publish=true`,
publishes after the `release` environment approves the job. The commit must be on main.

The build jobs have no write credential. The publisher creates a GitHub draft
to reserve the version, records artifact attestations, and uploads the binaries
and SHA256SUMS to the existing R2 download bucket and GitHub Releases.
The bucket-scoped credential is the `CLI_RELEASE_R2_CREDENTIALS` environment secret;
`CLOUDFLARE_ACCOUNT_ID` is an environment variable. R2 versions are reserved
with a conditional write. A failed publication retains its reservation; raise
the package version before another release. Install and update URLs stay on proofline.sh.
