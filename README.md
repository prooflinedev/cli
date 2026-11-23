# Proofline CLI

The command-line client for the [Proofline review API](https://proofline.sh/docs/). See the [CLI documentation](https://proofline.sh/docs/cli/) for commands.

This repository is the published distribution of the Proofline CLI. `openapi.public.json` is the generated public API contract pinned for this revision. During the build, `build.rs` generates request URLs for the operations it declares. [Open an issue](https://github.com/prooflinedev/cli/issues) for changes to `openapi.public.json`, generated code, or workflows. Pull requests are welcome for the hand-written installers in `install.sh` and `install.ps1`, commands in `src/`, release scripts in `scripts/`, and tests in `tests/`.

## Installation and setup

On Linux and macOS, install the CLI with `curl -fsSL https://proofline.sh/cli | sh`, then run `proofline login`. Run `proofline setup` to open the browser organization selector. Pass `--organization NAME` to open that GitHub organization's installation page, or `--print` to only print its address. Cloud trust and connection changes still require a signed-in administrator browser.

`proofline completions SHELL` prints a completion script for `zsh`, `bash`, `fish`, `powershell`, or `elvish` without signing in or making a network call. For example, add `source <(proofline completions zsh)` to `~/.zshrc`.

### Windows installation

On **Windows x64**, run the PowerShell installer from a checked-out copy of this repository. The effective PowerShell execution policy must permit local scripts; inspect it with `Get-ExecutionPolicy -List`. If your organization permits a per-process change, use `Set-ExecutionPolicy -Scope Process RemoteSigned` in the terminal running these commands. Do not override an organization-enforced policy: consult your administrator instead.

```powershell
powershell.exe -NoProfile -File .\install.ps1
```

It downloads the official release and `SHA256SUMS` from `https://proofline.sh`, validates the archive, verifies `proofline.exe --version`, and installs for the **current user** in `%LOCALAPPDATA%\Programs\Proofline\bin` without administrator rights. By default it attempts to append that directory to the user PATH while preserving expandable registry entries; this is best-effort and may warn if registry permissions or concurrent changes prevent an update. Cooperating Proofline installer processes serialize PATH updates with a per-user mutex, but unrelated registry editors do not share that lock. If the installer warns, first check **Windows Environment Variables → User variables → Path**. Add `%LOCALAPPDATA%\Programs\Proofline\bin` (or your custom `-InstallDir`) **only if it is missing**; a notification warning does not necessarily mean the registry update failed. Open a new terminal and run `Get-Command proofline -All` to check which executable has precedence. If an older copy is found first, run the new executable using its absolute path (for example, `& "$env:LOCALAPPDATA\Programs\Proofline\bin\proofline.exe" login`) or correct the stale PATH entry. The installer does not handle login or credentials.

To pin a version or install in a disposable folder without updating PATH:

```powershell
powershell.exe -NoProfile -File .\install.ps1 -Version 0.5.2 -InstallDir "$env:TEMP\proofline-test-bin" -NoModifyPath
```

Re-running the installer with the same verified version does not replace the executable or receipt, but User PATH may still be updated unless `-NoModifyPath` is selected. Upgrading an installer-managed version preserves the previous executable and uses a pending recovery record; an unmanaged or inconsistent existing installation is not overwritten. No administrator privileges or machine-level PATH changes are required.

User PATH updates use a cross-session per-user mutex to serialize cooperating installers. Unrelated registry editors that do not take the mutex can still race because Windows does not offer an atomic registry compare-and-swap for this value; verify PATH after simultaneous unrelated edits. If appending the directory would exceed the 30,000-character User PATH safety threshold, or REG_EXPAND_SZ would reinterpret percent-delimited tokens in the literal installation directory, the installer leaves PATH unchanged and warns rather than claiming that `proofline` is discoverable by name (the verified executable remains installed).

The installer script is currently distributed **in this repository**, not via a verified Windows one-liner on `proofline.sh`. Alternatively, manually download `proofline-x86_64-pc-windows-msvc.tar.gz` and its `SHA256SUMS` from the same official release, verify the SHA-256 with `Get-FileHash`, extract `proofline.exe` and place it on PATH.

Windows `proofline update` (self-update invoked from the CLI) remains unsupported; re-run `install.ps1` to upgrade an installer-managed installation. After a process interruption, a later installer run uses a pending journal to complete or recover a recognized transaction. A partial first-install or pre-switch stage can be retained with an `.incomplete` suffix for diagnostics without blocking a new attempt. Errors that cannot be safely classified preserve evidence and may require manual recovery.

The installer verifies the archive against the official SHA-256 manifest. Because both are fetched from the same HTTPS release origin, this establishes download consistency rather than independent cryptographic publisher authentication.

To verify the installer on Windows x64, run the following from the repository root (Python 3 is required for the offline fixtures):

```powershell
powershell.exe -NoProfile -File .\scripts\test_install_windows.ps1
powershell.exe -NoProfile -File .\scripts\test_install_upgrade_windows.ps1
powershell.exe -NoProfile -File .\scripts\test_install_concurrency_windows.ps1
powershell.exe -NoProfile -File .\scripts\test_install_upgrade_real_windows.ps1
powershell.exe -NoProfile -File .\scripts\test_install_interruption_real_windows.ps1
```

Run the same commands with `pwsh.exe` to verify PowerShell 7. The interruption test covers 12 hard-termination checkpoints, including checkpoints before receipt publication. The last two tests download pinned official releases; their installations use disposable directories and do not modify User PATH. The separate `scripts/test_install_user_path_ci_windows.ps1` test intentionally runs **only on disposable GitHub-hosted Windows runners** in its own isolated CI job, where it exercises the default PATH update and restores the prior raw registry value in `finally`.

On Linux, coding agents that omit `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR`
can still use the stored sign-in when the standard `/run/user/<uid>/bus` socket
is available. An explicit bus address or runtime directory keeps precedence.
`PROOFLINE_TOKEN` continues to take precedence over the stored sign-in.

### MCP agent registration

To register MCP without a prompt, run `proofline agent install CLIENT --yes`. Supported clients include `claude-code` (or `claude`), `cursor`, `codex`, `gemini`, and `kiro`. Without `--yes`, the command previews the entry and asks for confirmation, while `--print` previews without writing. Existing Proofline entries remain unchanged. New entries use this executable's absolute path and store no credentials. Claude Code uses the top-level `mcpServers` in `~/.claude.json`; a custom `CLAUDE_CONFIG_DIR` requires manual configuration with `--print`.

Native knowledge, plan, fix and configuration commands send the selected organization as `organization_id` in each MCP tool call. With `PROOFLINE_TOKEN`, select an authorized UUID using `--org ORGANIZATION_ID` or `PROOFLINE_ORGANIZATION_ID`; the flag takes precedence. A stored device sign-in uses its approved organization and refuses a different selection. For example, `proofline --org ORGANIZATION_ID wiki list --repo owner/name` and `proofline --org ORGANIZATION_ID config get` target that organization with a shared MCP OAuth credential. Selection grants no authority: the server checks each call, and a foreign target returns its refusal with a nonzero exit. MCP OAuth credentials remain limited to MCP and cannot use REST commands. The raw `proofline mcp` bridge preserves the caller's messages and per-call target unchanged.

## Reviews, history, and reruns

`proofline review --path src/main.rs` reviews only that file's local changes against the normal merge-base. The path is literal and repository-relative; the command refuses directories, globs, and `..`. Combine it with `--staged` to read the index, or `--include-untracked` to select a new, non-ignored file. The command preserves the real index and applies the usual secret preflight. You cannot combine `--path` with pushed-commit, range, or pull-request review.

`proofline reviews --repository-id UUID --cursor CURSOR` returns one page with its continuation metadata, and all flags are optional. `proofline routing REVIEW_ID` reads recorded routing. `proofline run --repo owner/name --pr 7 --run 2` reads one retained run, and `proofline history --repo owner/name --pr 7` reads all recorded runs. Both commands send the API the name without its owner, and use the response only when its repository choices list `owner/name`, or the Git remote's owner and name, among the organization's reviewed repositories. A repository with no reviews in the organization exits nonzero. `proofline findings --pr 7` finds the pull request's newest review through the same route and counts only runs of the repository whose full name matches. None of these commands reads the organization's review list.

`proofline rerun REVIEW_ID` requests the original immutable subject and waits, while `--no-wait` returns its link. Reruns require `reviews:rerun`. `proofline guidance --repo owner/name` requires `guidance:read`, and `proofline fix-prompt FINDING_ID` requires `findings:read`. History, guidance, and fix prompts print JSON; prompt text remains untrusted.

`proofline review --range BASE..HEAD --fail-on serious` exits 3 when a complete review has an unresolved finding at or above the threshold. PR reviews use the server’s effective open-item counts; other reviews count unresolved findings. Incomplete and unavailable results retain their nonzero exits. `--fail-on` cannot be combined with `--no-wait`.

In GitHub Actions, `proofline ci review --annotations` prints unresolved findings as workflow annotations at verified cited lines. Findings without a verified head location appear on the job. The review link contains the full result.

`proofline ci deploy --until 1h` waits until Proofline has recorded the deploy checks of the job's commit through the hour check, then exits 0 when each recorded `HEALTHY` with no gap, 3 when a deploy failed or regressed, and 2 when the result is not established. Without `--timeout`, a wait for `--until 20m` or `--until 1h` lasts until that check is due for the selected deploys, and at least 30 minutes; other checks wait 30 minutes, and `--until 1d` needs `--timeout`. `--environment`, `--task`, `--run` and `--attempt` select the deploy, and on a `workflow_run` event the commit, `--run` and `--attempt` default to the completed run's. `--json` prints the response. Each deploy prints one line per check. A deploy that rolled the environment back to an earlier commit first prints a `rollback` line with the page of the deploy it restores, when Proofline recorded one, and the pages of the deploys it rolled back. A deploy whose newest check found its service serving an earlier deploy again first prints a `rolled back` line, and stops printing it once a later check finds none; with `--json` the response carries it as `rolled_back`. Both lines can appear for one deploy. A rollback's exit code comes from its checks like any other deploy's; neither line changes it or means the rollback fixed anything.

## Scans

Proofline cannot analyze a scan's files yet. An accepted scan reads the repository's files at its commit but analyzes none of them, so a scan of a repository with files ends `FAILED` or `INCOMPLETE` with no findings, and the command exits 2. That empty finding list says nothing about the code.

`proofline scan --ref main --budget 200` scans the whole repository at one commit, not a pull request's change. GitHub resolves the ref once, when the request arrives, and the scan records that commit; `--commit SHA` names an exact full SHA instead, and you give one of the two. The command waits for the scan review and prints it like `proofline review`, while `--no-wait` prints its link and `--json` prints JSON.

`--budget` is required and has no default: it is the most credits the whole scan may spend, capped by the organization's on-demand scan limit, and a limit of 0 turns on-demand scans off. Results stay in Proofline and are never posted to GitHub. The token needs `scans:request` and live GitHub write access to the repository. The default sign-in omits that scope, so run `proofline login --scope reviews:read --scope findings:read --scope reviews:request --scope scans:request`; `--scope` replaces the defaults, so list every scope you want. A sign-in that holds only `scans:request` and a repository restriction can request a scan, but cannot read the review it produces, so the command prints the scan's link instead of waiting.

The CLI prints the request ID before it sends anything and never repeats the request. When the outcome is unknown (the connection failed, the server failed, or its answer was unreadable) the command exits 4; repeat it with `--request-id ID` to read the first resolution instead of paying for a second scan. If GitHub cannot resolve the ref, nothing starts and nothing is spent, but repeating that ID returns the same answer, so omit `--request-id` to ask again; with `--json` the resolution is still printed. Other exit codes match `proofline review`: 0 for a complete result, 2 for an incomplete or unfinished one and 1 for a refusal or error.

## Fix verification and agent sessions

`review` and `findings` print each finding’s ID in text output for use with `fix context`, `fix-prompt`, and `review --verify`.

```sh
proofline fix list --repo owner/repository --pr 42
proofline fix context FINDING_ID
proofline fix verify --review REVIEW_ID --findings FINDING_ID --commit FULL_PUSHED_SHA
proofline fix status REQUEST_ID
```

`fix list` returns open ENV findings at the live pull-request head, including availability, assessment gaps, and truncation. `fix context` reads captured source excerpts and untrusted remediation. `fix verify` requests re-verification of 1 to 20 distinct findings from one review at the exact commit you pushed. The server confirms that the commit is the live head, and optional `--note` accepts 1 to 2,000 characters. The command makes one attempt; after an ambiguous failure, inspect the review before requesting again. For unpushed local changes, use `review --verify`. For a finding whose reproduction kept its test as a check, `fix context` and `review --verify` give the check's command and its last result, so you can run it against your fix.

These `fix` commands return MCP tool results as JSON, and `isError: true` exits nonzero. A successful read is not a verdict: `PENDING`, `UNAVAILABLE`, and `NOT_VERIFIED` retain their meaning. Only the server's recorded re-verification establishes a fix. Reads require `reviews:read`, while verification also requires `reviews:request` and current repository write access.

`proofline session prompt FINDING_ID` returns the protected prompt and eligible connections. After reviewing it, run `proofline session start FINDING_ID --connection-id UUID --prompt-digest DIGEST`. This command starts once and can incur vendor charges. `proofline session get SESSION_ID` reads status, and `proofline session list FINDING_ID` lists the finding's recorded sessions, such as after a start whose answer was lost. These commands require a personal token with `agent_sessions:start`; device sign-in cannot grant this authority.

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

All five commands print the hosted MCP tool result as JSON. `get` needs `setup:write`; `describe` and `apply` need `org:configure`; `operations` and `propose` accept either scope, although an ordinary proposal needs `org:configure`. Sign in as an organization administrator and approve these scopes in the browser. A missing scope prints the server's refusal and the sign-in command above. These scopes act for the browser sign-in that approved them and end when it ends, while review access continues. `proofline status` says whether they are active or ended and prints the sign-in command that renews them.

The change file is a JSON object with `operation`, `parameters` and `input`, plus optional `expected_revision` from `describe` and `cited_files`. Each citation names a `repository_id`, full `commit_sha` and repository-relative `path`. Omit `input` for an operation without a body. `propose` adds a fresh `request_id` on each invocation and prints the diff and change ID; a sensitive proposal also includes its browser approval link. An optional top-level `organization_id` must be a UUID matching the selected organization; a conflicting or invalid value is refused before any request. The file stays unchanged. Proposing applies nothing and exits successfully when the server records it. After an uncertain response, run `proofline config get` and read `configuration.pending_changes` before proposing again. It lists up to 20 of the newest sensitive changes still waiting for approval that you may see, with their approval links, and up to 20 ordinary proposals that `apply` can still apply, by change ID. A change missing from it may still have been recorded and since decided, expired or fallen outside the list, so check the console's approval list before proposing it again.

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
