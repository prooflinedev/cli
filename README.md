# Proofline CLI

The command-line client for the [Proofline review API](https://proofline.sh/docs/).

Install with `curl -fsSL https://proofline.sh/cli | sh`, then run `proofline login`.
See the [CLI documentation](https://proofline.sh/docs/cli/) for commands.

Build from source with `cargo build --locked --release`. The pinned Rust toolchain
is installed by rustup. Run `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`,
`cargo test --locked` and `cargo deny check` before submitting a pull request.

`openapi.public.json` is the public API contract pinned for this revision.
Server compatibility is checked in the Proofline control plane.

## Coverage uploads

Upload reports your CI produced for an exact commit:

```sh
proofline --org "$PROOFLINE_ORGANIZATION_ID" coverage upload \
  --repository-id "$PROOFLINE_REPOSITORY_ID" \
  --commit "$TESTED_COMMIT_SHA" --report coverage/lcov.info --json
```

Set `PROOFLINE_TOKEN` to a repository-restricted token with `coverage:write`.
The token holder needs current GitHub write access to the repository. Uploads
accept LCOV, Cobertura XML, JaCoCo XML and Go cover profiles. Repeat `--report`
for up to 50 UTF-8 files with distinct file names; each report uses its file name
in the upload. The JSON body cannot exceed 64 MiB. The command sends the exact
40-character lowercase SHA supplied by CI and does not resolve a branch or run tests.
An identical upload returns the recorded report. Upload success records evidence;
the server evaluates the coverage check separately.

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
