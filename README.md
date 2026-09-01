# workflow-guard

`workflow-guard` is a small, dependency-free command-line linter for GitHub Actions workflows. It helps maintainers spot risky defaults and common supply-chain mistakes before they merge.

The project is intentionally conservative: it reads workflow files, reports evidence with line numbers, and never modifies repository content.

## Checks

| Rule | Severity | Check |
| --- | --- | --- |
| `WG001` | Medium | Missing top-level token permissions |
| `WG002` | High | `permissions: write-all` |
| `WG003` | Medium | Individual write-enabled token scope |
| `WG004` | Medium | External Action not pinned to a full commit SHA |
| `WG005` | Low | Job without `timeout-minutes` |
| `WG006` | Critical | `pull_request_target` combined with checkout |
| `WG007` | High | Remote script piped directly into a shell |

## Install

Python 3.9 or newer is required.

```bash
python -m pip install .
```

For development:

```bash
python -m pip install -e .
```

## Usage

Scan a repository root:

```bash
workflow-guard .
```

Scan one workflow and produce a Markdown report:

```bash
workflow-guard .github/workflows/ci.yml --format markdown --output workflow-report.md
```

Use JSON in automation and fail on medium-or-higher findings:

```bash
workflow-guard . --format json --fail-on medium
```

Generate a SARIF report for GitHub code scanning:

```bash
workflow-guard . --format sarif --output workflow-guard.sarif --fail-on none
```

The SARIF report includes rule IDs, severity levels, file paths, line numbers, and remediation guidance. Upload it with GitHub's `github/codeql-action/upload-sarif` action to show findings in the repository Security tab. Keep `--fail-on none` when a later workflow step must upload the report, and enforce a separate severity threshold after the upload step if desired.

Exit codes:

- `0`: scan completed and no finding reached the configured threshold
- `1`: at least one finding reached the configured threshold
- `2`: invalid input or an I/O error

## Example

The intentionally unsafe file at [`examples/risky-workflow.yml`](examples/risky-workflow.yml) demonstrates the built-in checks:

```bash
workflow-guard examples/risky-workflow.yml --fail-on none
```

## Design limits

`workflow-guard` uses a targeted, line-oriented parser so it can run without third-party packages. It understands conventional GitHub Actions structure, but it is not a general YAML parser. Unusual anchors, generated YAML, or nonstandard indentation can require manual review. Findings are prompts for review, not proof that a workflow is exploitable.

## Contributing

Bug reports, new test fixtures, and narrowly scoped rules are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md). Please report security-sensitive issues according to [`SECURITY.md`](SECURITY.md).

## License

MIT — see [`LICENSE`](LICENSE).
