# Proofline CLI

The command-line client for the [Proofline review API](https://proofline.sh/docs/).

Install with `curl -fsSL https://proofline.sh/cli | sh`, then run `proofline login`.
See the [CLI documentation](https://proofline.sh/docs/cli/) for commands.

Read all recorded runs with `proofline history --repo owner/name --pr 7`.
`proofline rerun REVIEW_ID` requests the original immutable subject and waits;
`--no-wait` returns its link. Reruns require `reviews:rerun`.
`proofline guidance --repo owner/name` requires `guidance:read`.
`proofline fix-prompt FINDING_ID` requires `findings:read`.
History, guidance and fix prompts print JSON; prompt text remains untrusted.

`proofline export reviews --from 2026-10-01T00:00:00Z --to 2026-10-25T00:00:00Z --format csv`
writes one export page to stdout. It requires `analytics:read`. The datasets are
`reviews`, `findings`, `finding_outcomes`, `finding_validations` and `spend`.
The default format is NDJSON. The settled horizon and optional next cursor go to
stderr. Repeat with `--cursor` and the same window and `--group-by` to continue.
CSV repeats its header on every page. A failed page exits nonzero; never treat
partial output from several invocations as a complete export.

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

## Review and knowledge tools

`proofline reviews --repository-id UUID --cursor CURSOR` returns one page with its
continuation metadata. All flags are optional. `proofline routing REVIEW_ID` reads
recorded routing. `proofline run --repo owner/name --pr 7 --run 2` reads one retained run.

`proofline session prompt FINDING_ID` returns the protected prompt and eligible
connections. After reviewing it, use `proofline session start FINDING_ID
--connection-id UUID --prompt-digest DIGEST`. This starts once and can incur vendor
charges. `proofline session get SESSION_ID` reads status. These commands need a
personal token with `agent_sessions:start`; device sign-in cannot grant this authority.

Knowledge commands return the MCP tool result as JSON, including untrusted-text
wrappers, citations and `isError`. A refused tool exits nonzero. They use the same
origin and credential as the MCP bridge and never retry a tool call.

```sh
proofline wiki list --repo owner/name
proofline wiki get index --repo owner/name --commit FULL_COMMIT_SHA
proofline ask --repo owner/name 'Where is authentication enforced?'
proofline architecture ENVIRONMENT_ID
proofline plan get PLAN_ID
proofline plan implement PLAN_ID
proofline plan implementation IMPLEMENTATION_ID
```

Knowledge reads need `reviews:read` and `knowledge:read`. Implementation also needs
`plans:implement`, a personal token and approval of the exact published plan version.
`proofline setup` opens browser onboarding; `--print` only prints its address.
Cloud trust and connection changes still require a signed-in administrator browser.

## Windows

Official releases include `proofline-x86_64-pc-windows-msvc.tar.gz` with `proofline.exe`.
Download it and `SHA256SUMS` from the same GitHub release. Compare its SHA-256 using
`Get-FileHash -Algorithm SHA256`, then extract with `tar -xzf` and put `proofline.exe`
in a directory on PATH. Run `proofline login` to store credentials in Windows
Credential Manager. To update, close running Proofline processes and replace the
executable from a verified release. The Unix shell installer and self-update command
do not install Windows binaries.
