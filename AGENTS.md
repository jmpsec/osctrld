# Repository Guidelines

## Project Structure & Module Organization

This repository builds one binary, `osctrld`: the endpoint daemon for [osctrl](https://osctrl.net). It manages local osquery state — flags, TLS certificate, extensions, and osquery restarts — by talking to an osctrl server.

All Go code lives in a single `package main` under [`cmd/osctrld/`](./cmd/osctrld/). There is no `pkg/` or `internal/` tree, and nothing here is importable as a library. Do not introduce packages without a concrete reason; the whole program is about 1.3k lines of code plus 1k lines of tests.

Source files and their responsibilities:

- `main.go`: app wiring, command registry, and the shared `cliWrapper` pre-flight
- `config.go`: `Configuration` type, flag and environment definitions, OS defaults, validation, file loading
- `actions.go`: command implementations and request/response types
- `actions_helpers.go`: server retrieval, file comparison, file writes, `osqueryd -version`
- `http-utils.go`: `SendRequest` and TLS client construction
- `utils.go`: URL generation, SemVer comparison, path joining
- `service.go`: daemon loop, jitter, signals, change detection
- `extensions.go`: extension manifest retrieval and deployment
- `osquery.go`: platform-specific osquery restart
- `version.go`: the `OsctrldVersion` constant

Supporting material: [`service/`](./service/) holds the sample YAML config, systemd unit, and launchd plist; [`tests/`](./tests/) holds configuration fixtures; [`.goreleaser.yml`](./.goreleaser.yml) and [`.github/workflows/`](./.github/workflows/) drive CI and releases.

Read [ARCHITECTURE.md](./ARCHITECTURE.md) before changing the configuration pipeline, the server contract, the file write path, or the daemon loop. It also lists verified known constraints worth checking before you "fix" something that looks wrong.

## Build, Test, and Development Commands

Use the root [`Makefile`](./Makefile):

- `make build`: build `bin/osctrld` for the host platform
- `make static`: build a statically linked binary
- `make install`: build and copy to `DEST` (default `/usr/local/bin`), via `sudo`
- `make test`: `go test ./cmd/osctrld/ -v`
- `make test_cover`: `go test -cover ./cmd/osctrld/`
- `make tidy`: clean binaries and `go.sum`, then `go mod tidy`
- `make release-snapshot`: local GoReleaser snapshot, no publishing
- `make release`: real GoReleaser release (tag-driven; normally left to CI)

Pre-commit hooks in [`.pre-commit-config.yaml`](./.pre-commit-config.yaml) run gofmt, golangci-lint (whole module, plus `GOOS=windows`), `go test -race`, and file hygiene checks on every commit. Install them once per clone with `pre-commit install`.

Reproduce CI locally before opening a pull request:

```bash
go test ./cmd/osctrld/ -race -coverprofile=coverage.out -v && go tool cover -func=coverage.out && golangci-lint run ./...
```

CI pins `golangci-lint` v2.14.0 and Go `>=1.27.2`. The lint configuration in [`.golangci.yml`](./.golangci.yml) enables `govet`, `errcheck` (including type assertions), `staticcheck`, `unused`, and `ineffassign`.

To exercise the binary by hand without touching a real endpoint:

```bash
go run ./cmd/osctrld default-config
go run ./cmd/osctrld check-config --config tests/osctrld-test.yaml
```

If a sandbox cannot write the global Go caches, set `GOCACHE=/tmp/...` and `GOLANGCI_LINT_CACHE=/tmp/...`.

## Coding Style & Naming Conventions

Follow standard Go conventions and the style already present:

- Format with `gofmt`; keep exported identifiers in `CamelCase`
- Keep the flat `main` package. Add a file, not a package, when adding an area of behavior
- Use table-driven tests with `stretchr/testify` assertions, matching the existing tests
- Log with `zerolog` structured fields (`log.Info().Str("path", p).Msg("...")`), never `fmt.Printf`, except where a command's output *is* stdout (`enroll`, `remove`, `default-config`)
- Keep log messages lowercase and free of secrets, flag content, and certificate material at `info` level and above

Reuse what already exists rather than reimplementing it:

- `SendRequest` for every HTTP call
- `genericRetrieve` for any new POST-JSON-to-osctrl endpoint
- `writeContentExists` for every managed file write, so change detection and `--force` semantics stay uniform
- the `gen*URL` helpers in `utils.go` for any new endpoint, and `genFullPath` for path composition

When adding configuration:

- Add the field to `Configuration` with matching `json`, `yaml`, and `mapstructure` tags
- Add a matching flag in `buildConfigFlags` with an `OSCTRL_*` or `OSQUERY_*` environment variable, unless the value is genuinely file-only
- Add a default in `applyOsqueryPathDefaults` or `applyConfigurationDefaults` if it is OS-dependent or has a sensible fallback
- Add validation in `validateConfiguration` if an invalid value would fail confusingly at runtime
- Update `defaultConfiguration`, [`service/osctrld-sample.yaml`](./service/osctrld-sample.yaml), and the README table together

Remember that a configuration file replaces `appConfig` entirely, so a new field must be handled in the file path, not only as a flag.

## Testing Guidelines

Tests are colocated in `cmd/osctrld/*_test.go` and run as one package. Most use `httptest.NewServer` for the osctrl side and `t.TempDir()` for the filesystem side — follow that pattern instead of adding mocking frameworks.

Because configuration lives in package-level globals, tests that mutate `appConfig`, `osctrlURLs`, `configFile`, or `flags` must save and restore them. CI runs with `-race`; do not add tests that depend on parallel access to those globals.

Add regression tests for:

- Configuration loading, defaulting, legacy key fallbacks, and validation errors
- Any change to `writeContentExists` semantics, `--force` behavior, or file permissions
- New or changed osctrl endpoints, including the non-`200` path
- Extension manifest parsing, download, and permission handling
- Daemon change detection and restart triggering
- URL generation and version comparison

Platform-specific code (`osqueryRestartCommand`, the install-path tables, script extensions) should be tested through `runtime.GOOS` switches the way `TestOsqueryRestartCommand` already does, rather than skipped.

If a touched area has no test coverage, say so explicitly in the final summary.

## Commit & Pull Request Guidelines

Keep commits focused and imperative, matching the existing short, direct subjects.

Pull requests should state the problem, the actual behavioral change, any security or operational impact, and the validation performed (`go test`, `golangci-lint`, `goreleaser --snapshot`, or manual checks against a real osctrl server).

Keep related files in sync within one change: `Configuration`, `defaultConfiguration`, `buildConfigFlags`, `service/osctrld-sample.yaml`, the README configuration and flag tables, and `ARCHITECTURE.md` where behavior is documented. Bump `OsctrldVersion` in [`version.go`](./cmd/osctrld/version.go) for a release — the GoReleaser `-X main.version` ldflag does not set it.

Do not mix unrelated refactors with runtime behavior changes.

## Configuration & Safety Notes

`osctrld` runs privileged on endpoints, holds an enrollment secret, writes files osquery executes against, deploys executable extensions, and restarts a security agent. Treat changes in those paths as high risk.

Constraints to preserve:

- The osctrl enrollment secret is sent in the request body. Never log it, never place it in a URL or query string, and never echo it in an error message
- `insecure` disables TLS verification entirely. Keep it opt-in, keep it off by default, and do not add code paths that enable it implicitly
- Managed files are written `0700`; extension binaries are `0755` in a `0755` directory. Do not widen these
- Extensions are downloaded from URLs supplied by the server manifest, written executable, and loaded by osquery. There is no checksum or signature verification today — do not add anything that widens that trust (arbitrary destination paths, redirects to other hosts, unvalidated `name` values used as filenames)
- `verify` and the daemon execute `osqueryd`, `systemctl`, and `launchctl`. Never interpolate server-supplied or configuration-supplied values into a command
- Daemon mode forces overwrites inside `syncOnce`. Keep that scoped to the cycle and restored afterwards
- The daemon must survive server errors. Keep per-step error handling inside `syncOnce` and keep the only exit path the signal handler
- Do not commit secrets, real endpoint configuration, certificates, `bin/`, or `dist/`. `osctrld.json` and `osctrld.yaml` are gitignored for this reason

Note that [`tests/osctrld-test.yaml`](./tests/osctrld-test.yaml) and [`tests/osctrld-test.json`](./tests/osctrld-test.json) are tracked and contain a placeholder secret and developer-specific absolute paths. They are fixtures, not deployment examples; do not copy values from them, and do not add real secrets there.

Prefer additive, reversible changes in `config.go`, `service.go`, `extensions.go`, and `osquery.go`. A bad default in this binary reaches every enrolled endpoint on the next sync.

## Agent Profiles

Default implementation work should follow [senior_software_engineer.md](./senior_software_engineer.md).

Use [security_engineer.md](./security_engineer.md) as an additional review lens for changes involving:

- The enrollment secret, TLS configuration, or the `insecure` flag
- File writes, permissions, paths, or the `--force` path
- Extension manifest handling, downloads, or deployment
- Subprocess execution and osquery restarts
- Configuration parsing, defaults, and validation
- Release packaging, systemd units, launchd plists, and installed sample configuration

For review-only work, use [security-reviewer.md](./security-reviewer.md) to scope findings to the current diff and report them by severity.
