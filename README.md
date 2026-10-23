# osctrld

<p align="center">
  <img alt="osctrld" src="logo.png" width="300" />
  <p align="center">
    Daemon for <a href="https://osctrl.net">osctrl</a>, the fast and efficient osquery management.
  </p>
  <p align="center">
    <a href="https://github.com/jmpsec/osctrld/blob/main/LICENSE">
      <img alt="Software License" src="https://img.shields.io/badge/license-MIT-green?style=flat-square">
    </a>
    <a href="https://goreportcard.com/report/github.com/jmpsec/osctrld">
      <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/jmpsec/osctrld?style=flat-square">
    </a>
    <a href="https://github.com/jmpsec/osctrld/actions/workflows/ci-main.yml">
      <img alt="CI" src="https://github.com/jmpsec/osctrld/actions/workflows/ci-main.yml/badge.svg">
    </a>
  </p>
</p>

## 👀 What is osctrld?

**osctrld** is the daemon component for [osctrl](https://osctrl.net). It keeps osquery clients aligned with their osctrl environment by managing flags, enrollment secrets, server certificates, extensions, and local osquery restarts.

It is designed to run close to osquery as a small operational companion: it can perform one-shot enrollment and verification tasks, or run continuously as a daemon that periodically syncs configuration from osctrl.

**osctrld can:**

- ✨ Enroll and remove nodes using osctrl-provided scripts.
- 📥 Retrieve osquery flags and TLS certificates from osctrl.
- 🔎 Verify local flags, certificates, and secrets against the server.
- ⚡ Run as a daemon with a configurable sync interval and jitter.
- 🔁 Restart osquery when managed files or extensions change.
- 🧩 Deploy osquery extensions from osctrl extension lists, when the osctrl server serves them.
- ⚙️ Use YAML or JSON configuration files, CLI flags, or environment variables.
- 📋 Emit human-readable or JSON structured logs.
- 🖥️ Run on Linux, macOS, and Windows.

> **⚠️ Warning**
>
> osctrld manages files and actions that affect osquery execution. Review configuration, file permissions, TLS settings, and extension sources before deploying it to production endpoints.

## 🤔 Why osctrld?

osquery is powerful, but keeping endpoint configuration current across many systems can become repetitive and error-prone. osctrld provides a narrow, auditable daemon that lets osctrl manage the local osquery client state without embedding that logic in deployment scripts.

The goal is to keep endpoint-side lifecycle work predictable: retrieve the desired state from osctrl, write it to the expected local paths, detect changes, and restart osquery only when needed.

## 📚 Documentation

Full documentation for the osctrl project is available at [https://osctrl.net](https://osctrl.net).

For this repository, the most useful starting points are:

- [service/osctrld-sample.yaml](service/osctrld-sample.yaml) for a YAML configuration example.
- [service/linux/systemd.service](service/linux/systemd.service) for Linux service deployment.
- [service/darwin/net.osctrl.daemon.plist](service/darwin/net.osctrl.daemon.plist) for macOS launchd deployment.
- [SECURITY.md](SECURITY.md) for vulnerability reporting and operator security guidance.

## 🗂️ Project Structure

```text
.
├── cmd/osctrld/                  # osctrld CLI, daemon logic, and tests
├── service/
│   ├── darwin/                   # macOS launchd service definition
│   ├── linux/                    # Linux systemd service definition
│   └── osctrld-sample.yaml       # Sample YAML configuration
├── tests/                        # Test configuration fixtures
├── .github/workflows/            # CI and release automation
├── .goreleaser.yml               # Multi-platform release configuration
├── Makefile                      # Local build, test, and release helpers
└── SECURITY.md                   # Security policy
```

## 🏗️ Architecture

osctrld is a Go CLI built around a small set of commands:

- `enroll` and `remove` retrieve osctrl-provided lifecycle scripts and print them to stdout for the operator to review and run.
- `flags` and `cert` fetch managed osquery files and write them locally.
- `verify` checks whether local osquery configuration matches osctrl.
- `service` runs the daemon loop and repeatedly syncs managed state.
- `check-config` validates a configuration file and exits.
- `default-config` prints a generated YAML configuration template.

The daemon mode performs a sync cycle on a configurable interval. During each cycle, osctrld retrieves flags, certificates, and extension lists from osctrl, writes changed content to disk, and restarts osquery through the operating system service manager when a managed artifact changes.

Configuration comes from CLI flags, environment variables, or the `osctrld` section of a YAML or JSON file. YAML is the default format for new deployments. Note that supplying a configuration file replaces the entire effective configuration, so a config file takes precedence over flags and environment variables for every field, not only the ones it sets. Runtime defaults are applied before commands run, and wrapped commands validate the effective configuration before doing work.

## 📦 Installation

### 🚀 Pre-built binaries

Download the latest release from the [Releases](https://github.com/jmpsec/osctrld/releases) page.

### 🛠️ Build from source

```shell
go build -o osctrld ./cmd/osctrld/
```

You can also use the Makefile:

```shell
make build
```

## ⚙️ Configuration

Example YAML configuration:

```yaml
osctrld:
  # osctrl enrollment secret value used to authenticate requests
  osctrlSecret: "thisisthesecret"
  # Local path where the osquery enrollment secret file is written or verified
  osquerySecretFile: "/path/to/osquery.secret"
  osqueryFlagFile: "/path/to/osquery.flags"
  osqueryCertFile: "/path/to/osquery.crt"
  environment: "osctrl_environment_UUID"
  baseurl: "https://osctrl.url"
  insecure: false
  verbose: false
  force: true
  logFormat: "text"
  interval: 60
  extensionsDir: "/path/to/extensions/"
```

JSON configuration files are also supported. Use a `.json` extension and osctrld will detect the format automatically.

`check-config`, `service`, `enroll`, `remove`, `flags`, `cert`, and `verify` all validate the effective configuration before running.

| Field | Description | Default |
| --- | --- | --- |
| `osctrlSecret` | osctrl enrollment secret value used to authenticate requests | Required |
| `osquerySecretFile` | Local path where the osquery enrollment secret file is written or verified | OS-dependent |
| `osqueryFlagFile` | Path to the osquery flags file | OS-dependent |
| `osqueryCertFile` | Path to the osquery TLS certificate file | OS-dependent |
| `enrollScript` | Path to the enroll script | OS-dependent |
| `removeScript` | Path to the remove script | OS-dependent |
| `osquery` | Path to the osquery installation directory | OS-dependent |
| `environment` | UUID of the osctrl environment. osctrl rejects environment names on the osctrld endpoints | Required |
| `baseurl` | Base URL of the osctrl server | Required |
| `insecure` | Ignore TLS certificate warnings | `false` |
| `verbose` | Enable debug logging | `false` |
| `force` | Overwrite existing managed files | `false` |
| `logFormat` | Log format: `text` or `json` | `text` |
| `interval` | Sync interval in minutes for daemon mode | `60` |
| `extensionsDir` | Directory for osquery extension binaries (configuration file only, no flag) | OS-dependent |

## 🧭 Usage

```text
NAME:
   osctrld - Daemon for osctrl, the fast and efficient osquery management

COMMANDS:
   enroll        Enroll a new node in osctrl, using new secret and flag files
   remove        Remove enrolled node from osctrl, clearing secret and flag files
   verify        Verify flags, cert and secret for an enrolled node in osctrl
   flags         Retrieve flags for osquery from osctrl and write them locally
   cert          Retrieve server certificate for osquery from osctrl and write it locally
   service       Run as a daemon, periodically syncing flags and certificate
   install       Enroll this node natively: install osquery if needed, write secret, flags and certificate, and start the service
   uninstall     Remove this node from osctrl natively: stop the service and delete secret, flags and certificate. osquery itself is left installed
   check-config  Validate configuration and exit
   default-config  Print a default YAML configuration
```

Validate configuration before launching:

```shell
osctrld check-config --config /etc/osctrld/osctrld.yaml
```

Generate a fresh config template:

```shell
osctrld default-config
```

Retrieve flags and certificates:

```shell
osctrld flags --config /etc/osctrld/osctrld.yaml
osctrld cert --config /etc/osctrld/osctrld.yaml
```

Enroll a node:

```shell
osctrld enroll --config /etc/osctrld/osctrld.yaml
```

Verify a node:

```shell
osctrld verify --config /etc/osctrld/osctrld.yaml
```

Run in daemon mode:

```shell
osctrld service --config /etc/osctrld/osctrld.yaml --interval 60
```

In daemon mode, osctrld will:

1. Sync flags, certificates, and extensions from osctrl every `--interval` minutes with jitter.
2. Detect whether managed content changed on disk.
3. Restart osquery through the OS service manager when changes are detected.
4. Shut down gracefully on `SIGINT` or `SIGTERM`.

Flag requests carry the host UUID (read with `osqueryd -S`), so osctrl can serve a
per-node flagfile, plus the outcome of the last flags change. osquery exits on an
unknown flag or bad value, so after a restart caused by new flags osctrld waits up to
60 seconds for `osqueryd` to stay running (3 consecutive checks). If it does not,
osctrld rolls back along a chain, writing, restarting once and checking each step:
from the attempted flags to the environment flags, then to the last known good flags
(the last content `osqueryd` ran with), then it stops and leaves `osqueryd` down until
osctrl serves something new. Failed content is remembered by SHA-256 and not applied again
while osctrl serves it, and the attempted flags are reported as `rejected`. A check
interrupted by a stop, crash or reboot is finished on the next sync. This state, with
the last known host UUID (used when the lookup fails), is kept next to the flagfile in
`<osqueryFlagFile>.osctrld-state.json`; the last known good flags are in
`<osqueryFlagFile>.osctrld-lastgood` (root-owned, `0600`, written atomically).

### osqueryd watcher and status report

Between syncs osctrld checks for the `osqueryd` process every 60 seconds. It is down
after 2 consecutive misses and up again only after 3 consecutive hits, so a service
manager respawning a crashing `osqueryd` does not flip the state. When osctrld starts
the state is unknown: the first hit is up, and only 2 consecutive misses are down;
until a check succeeds, nothing is reported. A single failed check is no evidence and
reports nothing. osctrld never
restarts a dead `osqueryd` on its own; a sync still runs while it is down, so a fix
served by osctrl is applied. osctrld reports to osctrl-tls with
`POST <base>/<env>/osctrld-status` (host UUID, whether `osqueryd` runs and since when
it is down, the last flags and extensions rollback):

- at the end of every sync; when the sync checked osquery after a restart, that check
  is the state reported, not a single poll: up after 3 consecutive hits, down when
  its checks never succeed and it times out;
- immediately when the watcher's state changes;
- about every 5 minutes while `osqueryd` is down, until it has been back up for 10 minutes.

Each report has a 15 second timeout, and a failed report never stops the service.
When osctrl answers 404 or 405 (a release without the route), reports pause until
the next sync tries again, logged once at debug level. When osctrl answers 429 with
`Retry-After` in seconds, no report is sent before that time (at most 1 hour).

### Extensions

Extensions are synced after flags and certificates, with their own restart and check,
so a bad extension never rolls back good flags (two restarts only when both changed).
The extensions request carries the host UUID and platform/architecture, and the
outcome of the last extensions change, which is sent once.

- **Verified.** Each extension is downloaded from the configured osctrl server with
  `POST <base>/<env>/osctrld-extension` and `{secret, sha256}` (never from a URL in the
  list) into a temp file in `extensionsDir`, and its size and SHA-256
  are checked before it is renamed into place as `<name>.ext` (`<name>.exe` on Windows).
- **Root-owned.** Files are owned by root at `0755` (an Administrators/SYSTEM-only write
  ACL on Windows), and `extensionsDir` is kept root-owned and not group/world-writable.
  Symlinks are never written or removed through.
- **Autoload file.** osctrld writes the file named by `--extensions_autoload` in the
  flagfile, or osquery's default (`/etc/osquery/extensions.load`,
  `/private/var/osquery/extensions.load`, `C:\Program Files\osquery\extensions.load`).
  It manages only its own lines; lines an operator added, and files an operator placed
  in `extensionsDir`, are kept, even when osctrl assigns no extensions. The file is
  checked every sync: if osctrld's lines are missing, or the flags moved it, the lines
  are written again (and taken out of the old file), and osquery is restarted and checked.
  Since the path comes from the flags, which environment admins can edit, osctrld only
  writes a `.load` file directly in osquery's base directory (`osquery` in the
  configuration; the defaults above qualify), and never one that is a symlink, the
  flagfile, the secret or certificate file, one of osctrld's state files, inside
  `extensionsDir`, or in a directory not owned by root or writable by others. On a
  refused path it changes nothing that sync and reports the error for every served
  extension, once per refused path. An existing file keeps its mode, minus group/world
  write.
- **Removal.** Extensions osctrld installed that are no longer assigned are removed,
  with their autoload lines, and reported as `removed`. A removal that fails (the file
  cannot be moved aside, the autoload file cannot be written, or `osqueryd` does not
  stay up without it) leaves the extension installed and is reported as `kept`, so
  osctrl can show that a revoked extension is still on the host.
- **Process check and rollback.** After the restart, osctrld waits up to 60 seconds for
  `osqueryd`, then up to 60 seconds more for a process running each new extension's
  installed path. If `osqueryd` does not stay up, the previous extensions are restored
  and osquery is restarted. If only some extensions do not run, just those are removed
  and osquery is restarted once. Failed content is reported as `rejected` and not
  installed again until osctrl serves a different SHA-256; meanwhile the last good
  version, if any, stays installed. A removal that keeps `osqueryd` down (for example
  while the flags still `--extensions_require` it) is undone and not retried until
  osctrl serves that extension again; until then it is reported `kept` on every sync,
  and once served again, as installed, it is reported `ok`.
  Statuses are sent on the next extensions request, only the newest per extension;
  they are dropped only when osctrl answers 400 or 413, and kept for the next request
  on any other error (for example 403 after a secret rotation). With `--disable_extensions`
  in the flags, extensions are still installed and reported `ok` with a note, without
  the process check.
- **Windows.** A running executable cannot be overwritten or deleted, so a replaced or
  removed extension is renamed aside (`<file>.prev`) and deleted after osquery restarted.

This state, including a check interrupted by a stop, crash or reboot (finished on the
next sync, restarting osquery first if that had not happened yet), is kept in
`<osqueryFlagFile>.osctrld-extensions-state.json`.

### osquery upgrades

The osquery version is set in osctrl: an environment target, optionally overridden
by a per-host pin, chosen from a library of package digests (SHA-256 per version,
platform and format) that only super admins enter. Packages always come from the
official osquery package server, never from the install-time `--osquery-package`
override. osctrld asks with `POST <base>/<env>/osctrld-osquery` and acts like this:

- **When.** At most one attempt per sync, at its end, only when `osqueryd` is known to
  be running and nothing else (flags, certificate, extensions) changed in that sync. A
  target lower than or equal to the installed version is ignored (`ahead_of_target`).
- **Verified first.** The target and the previous (installed) packages are downloaded
  and checked against their SHA-256 before anything on the host changes; a host whose
  running version has no digest in osctrl is not upgraded (`no_digest_for_installed`).
- **Config kept.** The flagfile, secret, certificate and autoload file are snapshotted
  and restored over whatever the package installs, and the extensions directory must
  be unchanged.
- **Confirmed or rolled back.** osctrl must report the new version within 5 minutes
  of the restart. Otherwise, or when `osqueryd` does not stay up, osctrld reinstalls
  the previous package, restores the snapshot and reports the target as `rejected`.
  Regular files the package added to the extensions directory during the upgrade
  (by inode change time, since packages carry their own mtime) are removed; anything that was there before, symlinks and directories are left alone.
  An upgrade interrupted by a stop, crash or reboot is finished or rolled back at the
  start of the next sync, before flags are synced.

The last outcome travels in the status report as `ok`, `rejected` or `skipped`, with a
reason: `no_target`, `ahead_of_target`, `no_digest_for_target`, `no_digest_for_installed`,
`unsupported_platform`, `rollout_pending`, `rollout_paused`, `previous_unavailable`, `target_unavailable`, `digest_mismatch`,
`version_not_reported`, `osqueryd_not_running`, `install_failed`, `config_changed` or
`rolled_back`. A rejected version is not retried until osctrl serves a new request id,
version or digest. A target whose packages could not be downloaded, verified or
installed (an install that failed and left the previous version in place, for example
while the package manager was busy, is a `skipped`/`install_failed`, not a rollback) is
not downloaded again for the same request for 6 hours. Package downloads always verify
the official server's certificate, even with `--insecure`, which only applies to osctrl.
Downloads are temporary `osctrld-pkg-*` files; ones an interrupted run left behind are
removed after an hour, when the service starts and before every upgrade (not on Windows,
where file ownership cannot be checked).
On macOS the upgrade starts osquery the way the installer does, copying the packaged
launchd plist into `/Library/LaunchDaemons`, which overwrites a customised plist. Windows is gated off: osctrld never
starts an upgrade there. An osctrl without the route (404/405) is logged once at debug.

State lives in `<osqueryFlagFile>.osctrld-upgrade-state.json` and, during an upgrade, the
verified packages and the config snapshot in the root-only `<osqueryFlagFile>.osctrld-upgrade`
directory. **Requirement:** the environment's osquery configuration must carry the osquery
version decorator, so osctrl sees the new version on check-in; without it confirmation
never succeeds and every upgrade rolls back with `version_not_reported`. Pin one host first.

## Native enrollment

`osctrld install` does everything the osctrl quick-add script does, without a shell:
it installs osquery when it is missing or out of date, writes the secret, flags and
certificate, and starts and enables the service. `osctrld uninstall` reverses the
configuration — it stops the service and deletes those three files, and deliberately
leaves osquery itself installed.

Both commands require root on Linux and macOS, and Administrator on Windows. osctrld
never calls `sudo` itself; run it under sudo.

The osquery package is verified before installation. The SHA-256 comes from the osctrl
server when it provides one, otherwise from `--osquery-sha256`. Without either, the
install is refused unless you pass `--allow-unverified`. The download from the official
package server always verifies its certificate; `--insecure` applies to it only with an
`--osquery-package` override, since a self-hosted mirror may use a self-signed certificate.

| Flag | Environment variable | Purpose |
| --- | --- | --- |
| `--osquery-sha256` | `OSQUERY_SHA256` | Expected SHA-256 of the osquery package |
| `--osquery-package` | `OSQUERY_PACKAGE` | Override the package URL, for mirrors and air-gapped installs |
| `--allow-unverified` | `OSCTRL_ALLOW_UNVERIFIED` | Install without verifying the package |

```bash
sudo osctrld --secret <secret> --environment <environment-uuid> --osctrl-url https://osctrl.example.com \
  --osquery-sha256 <sha256-of-the-package> install
```

## 🚢 Deployment

### 🐧 Linux systemd

```shell
cp osctrld /usr/bin/osctrld
cp service/linux/systemd.service /etc/systemd/system/osctrld.service
mkdir -p /etc/osctrld
install -m 0600 service/osctrld-sample.yaml /etc/osctrld/osctrld.yaml

systemctl daemon-reload
systemctl enable osctrld
systemctl start osctrld
```

Edit `/etc/osctrld/osctrld.yaml` with the correct osctrl URL, environment, secret, and local osquery paths before starting the service in production. The deb, rpm and apk packages install the binary, unit and configuration to these same paths.

The service runs as root: it writes the osquery flagfile, certificate and extensions, and restarts osqueryd when they change. Keep the configuration file `0600`, since it holds the osctrl secret.

### 🍎 macOS launchd

```shell
cp osctrld /usr/local/bin/
mkdir -p /usr/local/etc/osctrld
install -m 0600 service/osctrld-sample.yaml /usr/local/etc/osctrld/osctrld.yaml
cp service/darwin/net.osctrl.daemon.plist /Library/LaunchDaemons/

launchctl load /Library/LaunchDaemons/net.osctrl.daemon.plist
```

The plist runs `/usr/local/bin/osctrld` with `/usr/local/etc/osctrld/osctrld.yaml` and logs to `/var/log/osctrld.log`; adjust the paths if you installed elsewhere (Homebrew on Apple silicon uses `/opt/homebrew`). Update the configuration file for your environment before loading the daemon.

## 💻 Development

Install Go, then run the test suite:

```shell
go test ./cmd/osctrld/ -v
```

Useful Makefile targets:

```shell
make build
make test
make test_cover
make release-snapshot
```

Install the [pre-commit](https://pre-commit.com) hooks once per clone, so formatting, linting (including the `GOOS=windows` build) and the race-enabled tests run before every commit:

```shell
pre-commit install
```

Run them across the whole tree with `pre-commit run --all-files`.

Run the same checks used by CI before opening a pull request:

```shell
go test ./cmd/osctrld/ -race -coverprofile=coverage.out -v
go tool cover -func=coverage.out
```

## 🎛️ Global Options

```text
--configuration FILE, -c FILE     Configuration file for osctrld
--secret value, -s value          osctrl enrollment secret
--environment value, -e value     UUID of the osctrl environment
--secret-file FILE, -S FILE       Local osquery enrollment secret file
--flagfile FILE, -F FILE          Local osquery flags file
--certificate FILE, -C FILE       Local osquery TLS certificate file
--osctrl-url value, -U value      Base URL for the osctrl server
--osquery-path FILE, -o FILE      Path to osquery installation
--insecure, -i                    Ignore TLS warnings
--verbose, -V                     Enable debug logging
--force, -f                       Overwrite existing managed files
--log-format value, -L value      Log output format: text or json
--interval value, -I value        Sync interval in minutes for service mode
```

All flags can also be set through environment variables, including `OSCTRL_CONFIG`, `OSCTRL_SECRET`, `OSCTRL_ENV`, `OSQUERY_SECRET`, `OSQUERY_FLAGFILE`, `OSQUERY_CERTIFICATE`, `OSCTRL_URL`, `OSQUERY_PATH`, `OSCTRL_INSECURE`, `OSCTRL_VERBOSE`, `OSCTRL_FORCE`, `OSCTRL_LOG_FORMAT`, and `OSCTRL_INTERVAL`.

## 💬 Slack

Find us in the **#osctrl** channel in the official osquery Slack community ([Request an auto-invite!](https://join.slack.com/t/osquery/shared_invite/zt-h29zm0gk-s2DBtGUTW4CFel0f0IjTEw)).

## 📄 License

**osctrld** is licensed under the [MIT License](LICENSE).

## 🔐 Security & Reporting

If you believe you have found a security issue in osctrld, please do not open a public GitHub issue. Follow the process in [SECURITY.md](SECURITY.md).

## 🤝 Contributing

We ❤️ contributions!

Contributions are welcome. Please open an issue or pull request with a clear description of the problem, proposed change, and validation performed.
