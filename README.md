# Proofline CLI

The command-line client for the [Proofline review API](https://proofline.sh/docs/). See the [CLI documentation](https://proofline.sh/docs/cli/) for commands.

This repository is the published distribution of the Proofline CLI. `openapi.public.json` is the generated public API contract pinned for this revision. During the build, `build.rs` generates request URLs for the operations it declares. [Open an issue](https://github.com/prooflinedev/cli/issues) for changes to `openapi.public.json`, generated code, or workflows. Pull requests are welcome for the hand-written installer in `install.sh`, commands in `src/`, release scripts in `scripts/`, and tests in `tests/`.

## Installation and setup

On Linux and macOS, install the CLI with `curl -fsSL https://proofline.sh/cli | sh`, then run `proofline login`. Run `proofline setup` to open the browser organization selector. Pass `--organization NAME` to open that GitHub organization's installation page, or `--print` to only print its address. Cloud trust and connection changes still require a signed-in administrator browser.

### Windows installation

Official releases include `proofline-x86_64-pc-windows-msvc.tar.gz` with `proofline.exe`. Download the archive and `SHA256SUMS` from the same GitHub release, and compare its SHA-256 hash using `Get-FileHash -Algorithm SHA256`. Extract the archive with `tar -xzf` and put `proofline.exe` in a directory on `PATH`. Run `proofline login` to store credentials in Windows Credential Manager. To update, close running Proofline processes and replace the executable from a verified release. The Unix shell installer and self-update command do not install Windows binaries.

On Linux, coding agents that omit `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR`
can still use the stored sign-in when the standard `/run/user/<uid>/bus` socket
is available. An explicit bus address or runtime directory keeps precedence.
`PROOFLINE_TOKEN` continues to take precedence over the stored sign-in.

### MCP agent registration

To register MCP without a prompt, run `proofline agent install CLIENT --yes`. Supported clients include `claude-code` (or `claude`), `cursor`, `codex`, `gemini`, and `kiro`. Without `--yes`, the command previews the entry and asks for confirmation, while `--print` previews without writing. Existing Proofline entries remain unchanged. New entries use this executable's absolute path and store no credentials. Claude Code uses the top-level `mcpServers` in `~/.claude.json`; a custom `CLAUDE_CONFIG_DIR` requires manual configuration with `--print`.

Native knowledge, plan, fix and configuration commands send the selected organization as `organization_id` in each MCP tool call. With `PROOFLINE_TOKEN`, select an authorized UUID using `--org ORGANIZATION_ID` or `PROOFLINE_ORGANIZATION_ID`; the flag takes precedence. A stored device sign-in uses its approved organization and refuses a different selection. For example, `proofline --org ORGANIZATION_ID wiki list --repo owner/name` and `proofline --org ORGANIZATION_ID config get` target that organization with a shared MCP OAuth credential. Selection grants no authority: the server checks each call, and a foreign target returns its refusal with a nonzero exit. MCP OAuth credentials remain limited to MCP and cannot use REST commands. The raw `proofline mcp` bridge preserves the caller's messages and per-call target unchanged.

## Reviews, history, and reruns

`proofline review --path src/main.rs` reviews only that file's local changes against the normal merge-base. The path is literal and repository-relative; the command refuses directories, globs, and `..`. Combine it with `--staged` to read the index, or `--include-untracked` to select a new, non-ignored file. The command preserves the real index and applies the usual secret preflight. You cannot combine `--path` with pushed-commit, range, or pull-request review.

`proofline reviews --repository-id UUID --cursor CURSOR` returns one page with its continuation metadata, and all flags are optional. `proofline routing REVIEW_ID` reads recorded routing. `proofline run --repo owner/name --pr 7 --run 2` reads one retained run, and `proofline history --repo owner/name --pr 7` reads all recorded runs. Both commands check `owner/name`, or the Git remote's owner and name, against the organization's reviewed repositories, then send the API the name without its owner. A repository with no reviews in the organization exits nonzero.

`proofline rerun REVIEW_ID` requests the original immutable subject and waits, while `--no-wait` returns its link. Reruns require `reviews:rerun`. `proofline guidance --repo owner/name` requires `guidance:read`, and `proofline fix-prompt FINDING_ID` requires `findings:read`. History, guidance, and fix prompts print JSON; prompt text remains untrusted.

## Fix verification and agent sessions

```sh
proofline fix list --repo owner/repository --pr 42
proofline fix context FINDING_ID
proofline fix verify --review REVIEW_ID --findings FINDING_ID --commit FULL_PUSHED_SHA
proofline fix status REQUEST_ID
```

`fix list` returns open ENV findings at the live pull-request head, including availability, assessment gaps, and truncation. `fix context` reads captured source excerpts and untrusted remediation. `fix verify` requests re-verification of 1 to 20 distinct findings from one review at the exact commit you pushed. The server confirms that the commit is the live head, and optional `--note` accepts 1 to 2,000 characters. The command makes one attempt; after an ambiguous failure, inspect the review before requesting again. For unpushed local changes, use `review --verify`.

These `fix` commands return MCP tool results as JSON, and `isError: true` exits nonzero. A successful read is not a verdict: `PENDING`, `UNAVAILABLE`, and `NOT_VERIFIED` retain their meaning. Only the server's recorded re-verification establishes a fix. Reads require `reviews:read`, while verification also requires `reviews:request` and current repository write access.

`proofline session prompt FINDING_ID` returns the protected prompt and eligible connections. After reviewing it, run `proofline session start FINDING_ID --connection-id UUID --prompt-digest DIGEST`. This command starts once and can incur vendor charges. `proofline session get SESSION_ID` reads status. These commands require a personal token with `agent_sessions:start`; device sign-in cannot grant this authority.

## Knowledge and plans

```sh
proofline wiki list --repo owner/name
proofline wiki get index --repo owner/name --commit FULL_COMMIT_SHA
proofline ask --repo owner/name 'Where is authentication enforced?'
proofline architecture ENVIRONMENT_ID
proofline plan get PLAN_ID
proofline plan implement PLAN_ID
proofline plan implementation IMPLEMENTATION_ID
```

Knowledge commands return the MCP tool result as JSON, including untrusted-text wrappers, citations, and `isError`. A refused tool exits nonzero. They use the same origin and credential as the MCP bridge and never retry a tool call. Knowledge reads require `reviews:read` and `knowledge:read`. Implementation also requires `plans:implement`, a personal token, and approval of the exact published plan version.

## Configuration

```sh
proofline login --scope reviews:read --scope findings:read --scope guidance:read --scope reviews:request --scope setup:write --scope org:configure
proofline config get
proofline config get --environment ENVIRONMENT_ID
proofline config get --repo owner/name
proofline config operations --area REPOSITORY_REVIEW_SETTINGS --subject repository
proofline config describe OPERATION --param repo_id=REPOSITORY_ID
proofline config propose change.json
proofline config apply CHANGE_ID
```

All five commands print the hosted MCP tool result as JSON. `get` needs `setup:write`; `describe` and `apply` need `org:configure`; `operations` and `propose` accept either scope, although an ordinary proposal needs `org:configure`. Sign in as an organization administrator and approve these scopes in the browser. A missing scope prints the server's refusal and the sign-in command above.

The change file is a JSON object with `operation`, `parameters` and `input`, plus optional `expected_revision` from `describe` and `cited_files`. Each citation names a `repository_id`, full `commit_sha` and repository-relative `path`. Omit `input` for an operation without a body. `propose` adds a fresh `request_id` on each invocation and prints the diff and change ID; a sensitive proposal also includes its browser approval link. An optional top-level `organization_id` must be a UUID matching the selected organization; a conflicting or invalid value is refused before any request. The file stays unchanged. Proposing applies nothing and exits successfully when the server records it. After an uncertain response, inspect configuration and pending changes in the console before proposing again.

`apply` sends the change ID and selected organization. An ordinary change prints its route result; a sensitive change prints `applied: false`, the reason and approval link, then exits nonzero. An administrator must open that link and approve the exact diff in a fresh browser session. Server refusals, including stale revisions and another organization's resources, also exit nonzero. Commands use the existing MCP transport and its 8,192-byte request limit, and never retry a tool call.

## Coverage uploads and analytics exports

Upload reports your CI produced for an exact commit:

```sh
proofline --org "$PROOFLINE_ORGANIZATION_ID" coverage upload \
  --repository-id "$PROOFLINE_REPOSITORY_ID" \
  --commit "$TESTED_COMMIT_SHA" --report coverage/lcov.info --json
```

Set `PROOFLINE_TOKEN` to a repository-restricted token with `coverage:write`. The token holder needs current GitHub write access to the repository. Uploads accept LCOV, Cobertura XML, JaCoCo XML, and Go cover profiles. Repeat `--report` for up to 50 UTF-8 files with distinct report names, and the JSON body cannot exceed 30 MiB. Relative paths retain their directories, so `packages/a/lcov.info` and `packages/b/lcov.info` are distinct. Leading `./` is removed, relative paths cannot contain `..`, and absolute paths use only the file name.

The command sends the exact 40-character lowercase SHA supplied by CI and does not resolve a branch or run tests. An identical upload returns the recorded report. Upload success records evidence; the server evaluates the coverage check separately.

`proofline export reviews --from 2026-10-01T00:00:00Z --to 2026-10-25T00:00:00Z --format csv` writes one export page to stdout and requires `analytics:read`. The datasets are `reviews`, `findings`, `finding_outcomes`, `finding_validations`, and `spend`. The default format is NDJSON, while CSV repeats its header on every page. The settled horizon and optional next cursor go to stderr. Repeat with `--cursor` and the same window and `--group-by` to continue. A failed page exits nonzero; never treat partial output from several invocations as a complete export.

## Development and publishing

Build from source with `cargo build --locked --release`. `rustup` installs the pinned Rust toolchain. Run `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked`, and `cargo deny check` before submitting a pull request. Adding an API operation exposes a CLI command only when a command in `src/` declares and uses it.

GitHub Actions checks pull requests and `main`. Run `Release` on `main` with `publish=false` to build the Linux, macOS, and Windows archives. A `vX.Y.Z` tag equal to Cargo's version, or a `main` dispatch with `publish=true`, publishes the checked archives through the `release` environment. The commit must be on `main`.

The build jobs have no write credential. The publisher creates a GitHub draft to reserve the version and records artifact attestations. It then uploads the binaries and `SHA256SUMS` to the existing R2 download bucket and GitHub Releases. The bucket-scoped credential is the `CLI_RELEASE_R2_CREDENTIALS` environment secret, and `CLOUDFLARE_ACCOUNT_ID` is an environment variable. The publisher reserves R2 versions with a conditional write. Retry a failed publishing job with its original build artifacts; it verifies existing files, uploads missing ones, and advances the installer only after the archives match. Install and update URLs stay on `proofline.sh`.

## License

Licensed under Apache-2.0.
