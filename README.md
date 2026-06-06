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
    <a href="https://github.com/jmpsec/osctrld/actions/workflows/ci.yml">
      <img alt="CI" src="https://github.com/jmpsec/osctrld/actions/workflows/ci.yml/badge.svg">
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
- 🧩 Deploy osquery extensions from osctrl extension manifests.
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
│   └── osctrld-sample.yaml       # YAML configuration example
├── tests/                        # Test configuration fixtures
├── .github/workflows/            # CI and release automation
├── .goreleaser.yml               # Multi-platform release configuration
├── Makefile                      # Local build, test, and release helpers
└── SECURITY.md                   # Security policy
```

## 🏗️ Architecture

osctrld is a Go CLI built around a small set of commands:

- `enroll` and `remove` execute osctrl-provided lifecycle scripts for a node.
- `flags` and `cert` fetch managed osquery files and write them locally.
- `verify` checks whether local osquery configuration matches osctrl.
- `service` runs the daemon loop and repeatedly syncs managed state.

The daemon mode performs a sync cycle on a configurable interval. During each cycle, osctrld retrieves flags, certificates, and extension manifests from osctrl, writes changed content to disk, and restarts osquery through the operating system service manager when a managed artifact changes.

Configuration is loaded from the `osctrld` section of a YAML or JSON file and can be overridden by CLI flags or environment variables. YAML is the default format for new deployments.

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
  secret: "thisisthesecret"
  # Local path where the osquery enrollment secret file is written or verified
  secretFile: "/path/to/osquery.secret"
  flags: "/path/to/osquery.flags"
  cert: "/path/to/osquery.crt"
  environment: "environment_name_or_UUID"
  baseurl: "https://osctrl.url"
  insecure: false
  verbose: false
  force: true
  logFormat: "text"
  interval: 60
  extensionsDir: "/path/to/extensions/"
```

JSON configuration files are also supported. Use a `.json` extension and osctrld will detect the format automatically.

| Field | Description | Default |
| --- | --- | --- |
| `secret` | osctrl enrollment secret value used to authenticate requests | Required for enrollment workflows |
| `secretFile` | Local path where the osquery enrollment secret file is written or verified | OS-dependent |
| `flags` | Path to the osquery flags file | OS-dependent |
| `cert` | Path to the osquery TLS certificate file | OS-dependent |
| `enrollScript` | Path to the enroll script | OS-dependent |
| `removeScript` | Path to the remove script | OS-dependent |
| `osquery` | Path to the osquery installation directory | OS-dependent |
| `environment` | osctrl environment name or UUID | Required for most workflows |
| `baseurl` | Base URL of the osctrl server | Required |
| `insecure` | Ignore TLS certificate warnings | `false` |
| `verbose` | Enable debug logging | `false` |
| `force` | Overwrite existing managed files | `false` |
| `logFormat` | Log format: `text` or `json` | `text` |
| `interval` | Sync interval in minutes for daemon mode | `60` |
| `extensionsDir` | Directory for osquery extension binaries | OS-dependent |

## 🧭 Usage

```text
NAME:
   osctrld - Daemon for osctrl, the fast and efficient osquery management

COMMANDS:
   enroll   Enroll a new node in osctrl, using new secret and flag files
   remove   Remove enrolled node from osctrl, clearing secret and flag files
   verify   Verify flags, cert and secret for an enrolled node in osctrl
   flags    Retrieve flags for osquery from osctrl and write them locally
   cert     Retrieve server certificate for osquery from osctrl and write it locally
   service  Run as a daemon, periodically syncing flags and certificate
```

Retrieve flags and certificates:

```shell
osctrld flags --config /etc/osctrld/config.yaml
osctrld cert --config /etc/osctrld/config.yaml
```

Enroll a node:

```shell
osctrld enroll --config /etc/osctrld/config.yaml
```

Verify a node:

```shell
osctrld verify --config /etc/osctrld/config.yaml
```

Run in daemon mode:

```shell
osctrld service --config /etc/osctrld/config.yaml --interval 60
```

In daemon mode, osctrld will:

1. Sync flags, certificates, and extensions from osctrl every `--interval` minutes with jitter.
2. Detect whether managed content changed on disk.
3. Restart osquery through the OS service manager when changes are detected.
4. Shut down gracefully on `SIGINT` or `SIGTERM`.

## 🚢 Deployment

### 🐧 Linux systemd

```shell
cp osctrld /opt/osctrld/
cp service/linux/systemd.service /etc/systemd/system/osctrld.service
cp service/osctrld-sample.yaml /etc/osctrld/config.yaml

systemctl daemon-reload
systemctl enable osctrld
systemctl start osctrld
```

Edit `/etc/osctrld/config.yaml` with the correct osctrl URL, environment, secret, and local osquery paths before starting the service in production.

### 🍎 macOS launchd

```shell
cp osctrld /usr/local/bin/
cp service/darwin/net.osctrl.daemon.plist /Library/LaunchDaemons/

launchctl load /Library/LaunchDaemons/net.osctrl.daemon.plist
```

Edit the plist and configuration paths for your environment before loading the daemon.

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

Run the same checks used by CI before opening a pull request:

```shell
go test ./cmd/osctrld/ -race -coverprofile=coverage.out -v
go tool cover -func=coverage.out
```

## 🎛️ Global Options

```text
--configuration FILE, -c FILE     Configuration file for osctrld
--secret value, -s value          osctrl enrollment secret
--environment value, -e value     osctrl environment name or UUID
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
