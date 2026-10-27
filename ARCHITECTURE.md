# Architecture

## Overview

`osctrld` is a single Go binary that runs on osquery endpoints and keeps their local osquery state aligned with an [osctrl](https://osctrl.net) environment. It is a *client* of osctrl, not a service: it has no listening socket, no database, and no shared state with other processes.

The entire program is one `package main` under [`cmd/osctrld/`](./cmd/osctrld/) — roughly 1.3k lines of code plus 1k lines of colocated tests. There are no `pkg/` or `internal/` packages, and nothing in this repository is importable as a library.

Dependencies are deliberately few:

- [`urfave/cli/v3`](https://github.com/urfave/cli) for the command and flag surface
- [`spf13/viper`](https://github.com/spf13/viper) + [`gopkg.in/yaml.v3`](https://gopkg.in/yaml.v3) for configuration file loading and default-config emission
- [`rs/zerolog`](https://github.com/rs/zerolog) for structured logging
- [`shirou/gopsutil/v3`](https://github.com/shirou/gopsutil) for the process check in `verify`
- [`mattn/go-isatty`](https://github.com/mattn/go-isatty) to detect whether stderr is a terminal, gating the spinner

Everything else — HTTP, TLS, file writes, subprocess execution — uses the standard library.

## Runtime Topology

```text
                 ┌──────────────────────────────────────────────┐
                 │ osctrl server (osctrl-tls, /{env}/osctrld-*)  │
                 └──────────────────────────────────────────────┘
                        ▲ POST (secret in JSON body)
                        │ GET  (extension binaries, URLs from manifest)
                        │
                   ┌────┴─────┐
                   │ osctrld  │  one-shot command, or `service` daemon loop
                   └────┬─────┘
        writes ─────────┼───────── reads ──────────── exec
   osquery.flags        │      osquery.secret     systemctl restart osqueryd   (linux)
   osctrl.crt           │      osqueryd -version  launchctl kickstart -k       (darwin)
   extensions/*         │      process list       restart unsupported          (windows)
                        ▼
                     osqueryd
```

`osctrld` talks to exactly one osctrl endpoint family, derived from `baseurl` + `environment`. It never contacts the osctrl API or database.

## Repository Layout

| Path | Responsibility |
| --- | --- |
| [`cmd/osctrld/main.go`](./cmd/osctrld/main.go) | App wiring, command registry, `cliWrapper` pre-flight |
| [`cmd/osctrld/config.go`](./cmd/osctrld/config.go) | `Configuration` type, CLI/env flag definitions, OS defaults, validation, file loading |
| [`cmd/osctrld/actions.go`](./cmd/osctrld/actions.go) | Command implementations (`enroll`, `remove`, `flags`, `cert`, `verify`) and request/response types |
| [`cmd/osctrld/actions_helpers.go`](./cmd/osctrld/actions_helpers.go) | Server retrieval helpers, file comparison and write helpers, `osqueryd -version` |
| [`cmd/osctrld/http-utils.go`](./cmd/osctrld/http-utils.go) | `SendRequest`, TLS client construction, User-Agent |
| [`cmd/osctrld/utils.go`](./cmd/osctrld/utils.go) | URL generation, SemVer comparison, path joining |
| [`cmd/osctrld/service.go`](./cmd/osctrld/service.go) | Daemon loop, interval jitter, signal handling, change detection |
| [`cmd/osctrld/extensions.go`](./cmd/osctrld/extensions.go) | Extension manifest retrieval, download, deployment |
| [`cmd/osctrld/osquery.go`](./cmd/osctrld/osquery.go) | Platform-specific osquery restart |
| [`cmd/osctrld/install.go`](./cmd/osctrld/install.go) | `install` and `uninstall`, native enrollment flow |
| [`cmd/osctrld/packages.go`](./cmd/osctrld/packages.go) | osquery package URLs, verified download, platform installers |
| [`cmd/osctrld/privileges.go`](./cmd/osctrld/privileges.go) | Root and Administrator gate |
| [`cmd/osctrld/version.go`](./cmd/osctrld/version.go) | `OsctrldVersion` constant, build-time metadata, `versionString` |
| [`cmd/osctrld/ui.go`](./cmd/osctrld/ui.go) | Terminal spinner for the interactive one-shot commands |
| [`service/`](./service/) | Sample YAML config, systemd unit, launchd plist |
| [`tests/`](./tests/) | Config fixtures loaded by `config_test.go` |
| [`.goreleaser.yml`](./.goreleaser.yml) | Multi-platform build, archives, nfpm packages, Homebrew, Chocolatey |
| [`.github/workflows/`](./.github/workflows/) | Lint + test + snapshot on `develop`/`main`, tagged release |

## Command Surface

All commands except `default-config` are wrapped by `cliWrapper`, which loads and validates configuration before the action runs.

| Command | Network | Writes | Other effects |
| --- | --- | --- | --- |
| `enroll` | `POST /{env}/enroll/{GOOS}/osctrld-script` | none | Prints the enroll script to stdout |
| `remove` | `POST /{env}/remove/{GOOS}/osctrld-script` | none | Prints the remove script to stdout |
| `flags` | `POST /{env}/osctrld-flags` | `osqueryFlagFile` | — |
| `cert` | `POST /{env}/osctrld-cert` | `osqueryCertFile` | — |
| `verify` | `POST /{env}/osctrld-verify` | none | Compares local secret/flags/cert, checks install paths, runs `osqueryd -version`, scans processes |
| `service` | flags + cert + extensions, on an interval | flags, cert, extension binaries | Restarts osquery when any managed artifact changes |
| `install` | `POST /{env}/osctrld-verify` + package download | secret, flags, cert | Requires root/Administrator. Installs osquery when missing or outdated, then stops, configures, starts and enables the service |
| `uninstall` | none | deletes secret, flags, cert | Requires root/Administrator. Stops the service. Does not remove the osquery package |
| `check-config` | none | none | Validation happens in the wrapper; the action only prints `configuration is valid` |
| `default-config` | none | none | **Not wrapped**: prints a YAML template without loading or validating anything |

`enroll` and `remove` only *print* the osctrl-provided script. `osctrld` never executes it, and it never writes the osquery secret file — the script is responsible for both. The `enrollScript` and `removeScript` configuration fields are defaulted and logged but currently unused by any code path.

## Configuration Pipeline

`cliWrapper` in [`main.go`](./cmd/osctrld/main.go) runs the same six steps before every wrapped command:

1. **Flags and environment.** `urfave/cli` writes parsed values straight into the package-level `appConfig` through `Destination` pointers.
2. **Configuration file.** If `--configuration` (or `OSCTRL_CONFIG`) is set, `loadConfiguration` reads it with viper, unmarshals the `osctrld` top-level key, and applies legacy field fallbacks. The result **replaces `appConfig` wholesale**, so when a config file is supplied it supersedes every flag and environment variable, not just the fields it defines.
3. **Defaults.** `applyConfigurationDefaults` fills empty values from `runtime.GOOS` (see the platform matrix below), then defaults `logFormat` to `text` and `interval` to `60`.
4. **Validation.** `validateConfiguration` requires `osctrlSecret`, an `environment` that is a UUID, and a `baseurl` that parses with an `http`/`https` scheme and a host; `logFormat` must be `text` or `json`; `interval` must be greater than zero. Failure logs the problems and exits with code `2`.
5. **Logging.** Global level becomes `debug` when `verbose` is set, otherwise `info`. `logFormat: json` emits raw zerolog JSON to stderr; anything else uses `ConsoleWriter`.
   Once the logger is set up, startup checks log warnings without refusing to run: on Linux and macOS, when the effective uid is `0` and a configuration file is in use, `warnUnsafeConfigFile` (in [`owner_posix.go`](./cmd/osctrld/owner_posix.go)) stats the file after resolving symlinks, the directory holding it, and the directory holding the symlink, and logs one warning per problem — not owned by root, group-writable, world-writable — naming the path and never the content. The rule itself is the pure `ownershipProblems` in `config.go`. Other warnings follow: flags and environment variables ignored because of the configuration file, unknown keys, plain-http URLs, relative paths, and unusual values. `check-config` shows them all.
6. **URLs.** `genURLs(baseurl, environment, insecure)` builds the full endpoint set once, into the package-level `osctrlURLs`.

### Legacy configuration keys

`applyLegacyConfigurationFields` accepts the pre-1.1 names when the current field is empty:

| Legacy key | Current key |
| --- | --- |
| `secret` | `osctrlSecret` |
| `secretFile` | `osquerySecretFile` |
| `flags` | `osqueryFlagFile` |
| `cert` | `osqueryCertFile` |

YAML and JSON are both accepted; viper selects the parser from the file extension.

### Platform defaults

| | darwin | linux | windows |
| --- | --- | --- | --- |
| `osquery` path | `/private/var/osquery/` | `/etc/osquery/` | `C:\Program Files\osquery\` |
| script extension | `.sh` | `.sh` | `.ps1` |
| osquery install markers | `io.osquery.agent.plist`, `/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd` | `osqueryd.service`, `/opt/osquery/bin/osqueryd` | `manage-osqueryd.ps1`, `osqueryd.exe` |
| restart | `launchctl kickstart -k system/io.osquery.agent` | `systemctl restart osqueryd` | unsupported |

`osqueryFlagFile`, `osquerySecretFile`, `osqueryCertFile`, `enrollScript`, `removeScript`, and `extensionsDir` are all derived from the `osquery` path when not set explicitly.

## Server Contract

Every management request is a `POST` with a JSON body to a URL built as `{baseurl}/{environment}/…`. The osctrl enrollment secret travels **in the body**, not in a header.

| Endpoint | Request body | Response |
| --- | --- | --- |
| `/{env}/osctrld-flags` | `{secret, secretFile, certFile}` | osquery flags, as text |
| `/{env}/osctrld-cert` | `{secret}` | PEM certificate, as text |
| `/{env}/osctrld-verify` | `{secret, secretFile, certFile}` | `{flags, certificate, osquery_version}` |
| `/{env}/osctrld-extensions` | `{secret}` | `[{name, url}, …]` — not served by osctrl yet; a `404` is treated as an empty manifest |
| `/{env}/{enroll\|remove}/{GOOS}/osctrld-script` | `{secret}` | shell or PowerShell script, as text |

Note that `secretFile` and `certFile` are sent as *local paths*: the server templates them into the flags content it returns, which is why changing those paths changes the flags the server generates.

Extension binaries are fetched with a plain `GET` against the URL the manifest supplies.

Any non-`200` response is turned into an error carrying the status code and body. Response bodies are trimmed of surrounding whitespace before comparison or writing.

### Transport

`SendRequest` builds a fresh `http.Client` per call. For `https` URLs it loads the system certificate pool and sets `InsecureSkipVerify` when `insecure` is enabled. There is no client certificate, no proxy configuration, and **no timeout on any request**. Every request carries `User-Agent: osctrld-http-client/{version}`.

## File Management

`writeContentExists` is the single write path for flags, certificates, and extensions:

- File missing → write it, report `changed`.
- File present with identical (trimmed) content → no write, report unchanged.
- File present with different content and `force` unset → error telling the operator to pass `--force`.
- File present with different content and `force` set → overwrite, report `changed`.

Every write goes through `writeFileAtomic`: a temp file with a random name in the same directory gets the mode first (through the handle, so umask does not matter), then the content, is fsynced and renamed over the target, and the directory is fsynced on Linux and macOS. A crash or failed write leaves the previous file. A symlink at the target is never compared or written through: it counts as different content and, with `force`, is replaced by a regular file; any other non-regular target (a directory, a device) is refused. The file ends at exactly the caller's mode — `0700` for flags and certificate, `0600` for the secret — whether it was created, replaced or left alone, and a replaced file keeps its POSIX owner. The extensions directory is created with `0755` and each downloaded extension is `chmod 0755` after a successful write. Extension downloads, the autoload file and the upgrade stash use their own temp-and-rename writers, fsynced the same way.

### Windows ACL classes

Modes do not restrict reading on Windows, so files get ACLs by class. `fileACLFor` (in [`owner_acl.go`](./cmd/osctrld/owner_acl.go)) picks the class from the path:

| Class | Files | ACL |
| --- | --- | --- |
| secret | `osquerySecretFile` | `secretDACLSDDL`: protected, `SYSTEM` and `Administrators` full control, nothing else. The temp file is created with it in the `CreateFile` call, so no other account ever holds a handle to a file that will hold the secret. An existing secret with matching content is re-restricted (a failure there is only warned about). The upgrade restore writes it the same way and skips `extensionDACL`. |
| default | flagfile, certificate | written: the directory's inherited ACL. Restored after an upgrade: `extensionDACL` (owner Administrators; `SYSTEM`/`Administrators` full, `Users` read and execute). |
| extension | extension binaries, extensions directory, autoload file | `extensionDACL`, applied to the temp file before the rename |
| stash | `.osctrld-upgrade` | `stashDACLSDDL`: protected, `SYSTEM`/`Administrators` only, inherited by its content |

### Ownership checks

An existing extension file is trusted, and the autoload directory written in, only when only an administrator can have changed it. On Linux and macOS that is root ownership and no group/world write. On Windows `readSecurity` reads the owner and DACL into a small `securityInfo` struct and the portable `adminOnlyWrite` decides: the owner must be `SYSTEM`, `Administrators` or `TrustedInstaller`, the DACL must exist, and no allow entry may grant anyone else a write right (`FILE_WRITE_DATA`/`ADD_FILE`, `APPEND_DATA`/`ADD_SUBDIRECTORY`, `DELETE_CHILD`, `DELETE`, `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_WRITE`, `GENERIC_ALL`). Inheritable entries count as if they applied, since temp files osctrld creates there inherit them; `CREATOR OWNER` is the exception, as it stands for osctrld itself. Deny entries are ignored, which can only make the answer more cautious. Nothing is re-applied before the check: a file that fails is downloaded again, a directory that fails is refused like on POSIX.

The `changed` return value is what drives the osquery restart in daemon mode.

## Service Loop

`serviceNode` performs one `syncOnce` immediately, then loops:

1. Wait `interval` minutes ± 10% jitter, or return on `SIGINT`/`SIGTERM` via `signal.NotifyContext`.
2. `syncOnce` sets `force = true` for the duration of the cycle — the daemon always overwrites drifted files regardless of the configured `force` value — and restores the original afterwards.
3. Sync flags, then certificate, then extensions. Each step logs and swallows its own error so one failure does not abort the cycle.
4. If any of the three reported a change, call `restartOsquery`.

Jitter exists to spread load when many endpoints share a sync interval. Errors never terminate the loop; only a signal does.

## Build and Release

- `make build` / `make static` produce `bin/osctrld` for the host platform.
- `make test` runs `go test ./cmd/osctrld/ -v`; CI additionally uses `-race` and a coverage summary.
- GoReleaser builds `linux/darwin/windows × amd64/arm64` with `CGO_ENABLED=0` and produces binary archives plus `apk`/`deb`/`rpm` packages. Homebrew and Chocolatey publishing is configured in `.goreleaser.yml` but currently skipped by the release workflow (`--skip=homebrew,chocolatey`); CI snapshots additionally skip `publish` and `nfpm`.
- macOS has no package. The documented deployment installs the binary and configuration as `root:wheel` into `/Library/osctrld` (binary `0755`, configuration `0600`) and the plist in [`service/darwin/`](./service/darwin/) points there. The Homebrew formula only installs the binary into the Homebrew prefix, which on Intel Macs belongs to the Homebrew user, so launchd must run a root-owned copy, never the formula's binary.
- Linux packages install the systemd unit to `/lib/systemd/system/osctrld.service` and the sample config to `/etc/osctrld/osctrld.yaml` as `config|noreplace`. They do not start the service.
- `.github/workflows/ci-develop.yml` and `ci-main.yml` are identical except for their branch trigger; `release.yml` runs on `v*` tags from a `windows-latest` runner.

## Known Constraints

These are current, verified properties of the code. Treat them as context before changing the surrounding logic.

- **A configuration file overrides flags and environment variables.** `loadConfiguration` replaces the whole `appConfig` struct, so `--config` plus `--verbose` silently drops `--verbose` unless the file sets it.
- **No HTTP timeouts.** An unresponsive osctrl server blocks a one-shot command or a daemon sync cycle indefinitely.
- **The environment must be a UUID.** osctrl's osctrld endpoints look the environment up by UUID and answer a bare `HTTP 400` to a name, so `validateConfiguration` rejects anything that is not a UUID.
- **osctrl does not serve the extensions endpoint yet.** `POST /{env}/osctrld-extensions` returns `404`, which `retrieveExtensionManifest` treats as an empty manifest so the daemon does not log a failure every cycle. Extension deployment starts working with no client change once osctrl serves it.
- **Extensions are unverified.** The manifest is trusted, downloads follow whatever URL it supplies, and binaries are written executable with no checksum or signature check. The osctrl server and its TLS certificate are the only controls.
- **The spinner is suppressed in most real deployments.** It renders only when stderr is a terminal, `--verbose` is off, `logFormat` is text, and the command is not `service`, so daemon, piped and CI output is unchanged.
- **Version comparison only understands numeric components.** `osqueryVersionCompare` pads the shorter version with zeros and compares component by component, but a non-numeric component (a pre-release suffix such as `5.12.1-rc1`) returns the `-1` error sentinel, which `verify` reports as an unknown osquery version.
- **`extensionsDir` has no flag or environment variable.** It can only be set through a configuration file, or defaulted from the osquery path.
- **`genURLs` takes an unused `insecure` parameter.** Insecure mode is read from `appConfig` at request time.
- **Configuration lives in package-level globals** (`appConfig`, `osctrlURLs`, `configFile`, `flags`). Tests mutate and restore them; there is no per-invocation context.
- **The `service` daemon cannot restart osquery on Windows.** `install` and `uninstall` manage the Windows service through the service manager, but `osqueryRestartCommand` has no Windows case, so `restartOsquery` — which the daemon loop calls after syncing — still returns an error. Daemon mode on Windows syncs files but leaves osquery running the old configuration.
- **`install` refuses without a package digest.** osctrl does not serve `osquery_sha256` yet, so a plain `osctrld install` fails until the operator passes `--osquery-sha256` or `--allow-unverified`. Adding the field server-side turns verification on fleet-wide with no client change.
- **`install` does not reproduce the Windows ACL hardening of the daemon folder.** The quick-add PowerShell rewrites ACLs on the `osqueryd` folder; the MSI already sets those permissions and osctrld writes only configuration files, never the daemon binary. It does restrict the secret file to SYSTEM and Administrators (see Windows ACL classes), which the quick-add script does not.
- **Writes replace files, they do not rewrite them.** The rename gives a replaced file a new inode and, on Windows, the directory's inherited ACL (the secret aside). It fails where the target is held open without delete sharing, which osqueryd does not do for its flagfile, secret or certificate.
- **`install` overwrites unconditionally.** Unlike `flags` and `cert`, it does not honor `--force`, because re-running an enrollment is expected to replace what is there. The quick-add script behaves the same way.
- **Unsafe configuration ownership is only warned about.** A root osctrld whose configuration file or its directory another user can write hands that user root, but refusing would stop existing fleets, so `warnUnsafeConfigFile` logs and continues. Only the immediate directories are checked, not every ancestor; the flagfile, secret and certificate directories are not checked (extension files, the autoload directory and the upgrade stash have their own ownership checks, on Windows too). The configuration file is not checked on Windows.
- **osctrld never creates the Windows `osqueryd` service.** It relies on the osquery MSI having already registered it; if the service is absent, `install` fails with an error rather than creating one.
