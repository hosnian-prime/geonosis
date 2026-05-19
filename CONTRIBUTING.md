# Contributing to Geonosis

Thank you for your interest in contributing to Geonosis! This document provides
guidelines and instructions for contributing to the project.

## Code of Conduct

We expect all contributors to be respectful and constructive in their
interactions. Harassment, abusive language, and disruptive behavior will not be
tolerated. Maintainers reserve the right to remove, edit, or reject
contributions that do not align with these expectations.

## Reporting Bugs

If you find a bug, please open an issue on
[GitHub Issues](https://github.com/hosnian-prime/geonosis/issues) with the
following information:

- A clear, descriptive title.
- Steps to reproduce the issue.
- Expected behavior vs. actual behavior.
- Rust version, OS, and any other relevant environment details.
- Logs or error output, if applicable.

**Security vulnerabilities** should NOT be reported through public issues.
Please email the maintainers directly so the issue can be addressed before
public disclosure.

## Suggesting Features

Feature requests and design discussions are welcome. You can:

- Open a [GitHub Issue](https://github.com/hosnian-prime/geonosis/issues) with
  the label `enhancement` for well-defined proposals.
- Start a
  [GitHub Discussion](https://github.com/hosnian-prime/geonosis/discussions)
  for broader ideas or questions about direction.

Please check existing issues and discussions before opening a new one to avoid
duplicates.

## Development Setup

### Prerequisites

| Tool       | Minimum Version | Notes                          |
| ---------- | --------------- | ------------------------------ |
| Rust       | 1.88+           | Edition 2021                   |
| PostgreSQL | 16              | Required for integration tests |
| Docker     | Latest stable   | For `make quickstart`          |
| Redis      | Latest stable   | Used for cluster-wide caching  |

### Getting Started

1. **Fork and clone** the repository:

   ```bash
   git clone https://github.com/<your-username>/geonosis.git
   cd geonosis
   ```

2. **Quick start** with Docker Compose (spins up Postgres, Redis, and the
   server):

   ```bash
   make quickstart
   ```

3. **Build** the workspace:

   ```bash
   make build
   ```

4. **Run tests**:

   ```bash
   make test
   ```

   Unit tests use an in-memory storage backend and do not require external
   services. Integration tests require a running PostgreSQL instance.

5. **Check formatting and lints**:

   ```bash
   make fmt-check
   make clippy
   ```

## Building and Testing

The project uses a Makefile for common development tasks:

| Command            | Description                                     |
| ------------------ | ----------------------------------------------- |
| `make build`       | Build all workspace crates                      |
| `make test`        | Run the test suite                              |
| `make clippy`      | Run Clippy with warnings denied (`-D warnings`) |
| `make fmt`         | Format code with rustfmt                        |
| `make fmt-check`   | Check formatting without modifying files        |
| `make quickstart`  | Start the full stack via Docker Compose          |

CI runs `fmt-check`, `clippy`, and `test` automatically on every push and pull
request (along with CSS logical-property linting and migration discipline
checks). Please ensure your changes pass locally before opening a pull request.

## Pull Request Process

1. **Fork** the repository and create a feature branch from `hive`:

   ```bash
   git checkout -b feat/my-feature hive
   ```

2. **Make your changes.** Keep commits focused and atomic.

3. **Ensure all checks pass**:

   ```bash
   make fmt
   make clippy
   make test
   ```

4. **Push** your branch and open a pull request against `hive`.

5. In your PR description, include:
   - A summary of what the change does and why.
   - Any related issue numbers (e.g., `Closes #42`).
   - How you tested the change.

6. A maintainer will review your PR. Please be responsive to feedback. Small,
   focused PRs are reviewed faster than large ones.

### Pre-commit Hooks

The repository includes pre-commit hooks that enforce formatting and Clippy
compliance. These run automatically if configured; make sure your changes pass
`make fmt-check` and `make clippy` before pushing.

## Code Style

- **Formatting**: Use the default `rustfmt` configuration. Run `make fmt`
  before committing.
- **Lints**: All Clippy warnings are denied in CI. Run `make clippy` and
  resolve any warnings.
- **No unsafe code**: The project forbids `unsafe` code
  (`unsafe_code = "forbid"`). Do not introduce `unsafe` blocks.
- **Trait-driven design**: The codebase uses traits extensively for abstraction
  (e.g., storage backends, crypto providers). Follow existing patterns when
  adding new functionality.
- **Error handling**: Use typed errors. Avoid `.unwrap()` in library code.

## Commit Message Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Common types:

| Type       | Usage                                          |
| ---------- | ---------------------------------------------- |
| `feat`     | A new feature                                  |
| `fix`      | A bug fix                                      |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `docs`     | Documentation changes                          |
| `test`     | Adding or updating tests                       |
| `chore`    | Build, CI, or tooling changes                  |

Examples:

```
feat(token): add support for token introspection endpoint
fix(session): prevent session fixation on re-authentication
refactor(cache): simplify local cache eviction logic
```

Keep the subject line under 72 characters. Use the imperative mood ("add
support" not "added support").

## Architecture

The workspace contains 22 crates under `crates/`. Architecture decision records
and design documents are available in the `docs/` directory. Please review
relevant documentation before making significant changes to core subsystems.

## Licensing

Geonosis is dual-licensed under **Apache-2.0 OR MIT**. By submitting a
contribution, you agree that your work will be licensed under the same terms.
You retain copyright over your contributions.

## Questions?

If you have questions that are not covered here:

- Browse the `docs/` directory for architecture and design documentation.
- Open a
  [GitHub Discussion](https://github.com/hosnian-prime/geonosis/discussions).
- Comment on a relevant issue or pull request.

We appreciate every contribution, whether it is a typo fix, a bug report, or a
new feature. Thank you for helping improve Geonosis.
