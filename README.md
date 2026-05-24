# osctrld

<p align="center">
  <img alt="osctrld" src="logo.png" width="300" />
  <p align="center">
    Daemon for <a href="https://osctrl.net">osctrl</a>, the fast and efficient osquery management.
  </p>
  <p align="center">
    <a href="https://github.com/jmpsec/osctrld/blob/master/LICENSE">
      <img alt="Software License" src="https://img.shields.io/badge/license-MIT-green?style=flat-square">
    </a>
    <a href="https://goreportcard.com/report/github.com/jmpsec/osctrld">
      <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/jmpsec/osctrld?style=flat-square">
    </a>
  </p>
</p>

## What is osctrld?

**osctrld** is the daemon component for [osctrl](https://osctrl.net). It keeps osquery clients in sync with their osctrl environment by managing flags, enrollment secrets, server certificates, and extensions. When configuration changes are detected, osctrld automatically restarts osquery so the new settings take effect.

### Features

- **Configuration sync** — retrieves flags and certificates from osctrl, writes them to disk
- **Daemon mode** — runs as a long-lived service, syncing on a configurable interval with jitter
- **Osquery lifecycle** — automatically restarts osquery when flags, certificates, or extensions change
- **Extension deployment** — fetches extension manifests from osctrl and deploys binaries
- **Enrollment/removal** — one-command node enrollment and removal via osctrl scripts
- **Verification** — validates local osquery configuration matches the server
- **Structured logging** — JSON or human-readable output via [zerolog](https://github.com/rs/zerolog)
- **Cross-platform** — Linux, macOS, and Windows

## Installation

### Pre-built binaries

Download the latest release from the [Releases](https://github.com/jmpsec/osctrld/releases) page.

### Build from source

```shell
go build -o osctrld ./cmd/osctrld/
```

## Configuration

osctrld can be configured via a YAML or JSON file, CLI flags, or environment variables. YAML is the default format.

### Configuration file

```yaml
osctrld:
  secret: "your-enrollment-secret"
  secretFile: "/etc/osquery/osquery.secret"
  flags: "/etc/osquery/osquery.flags"
  cert: "/etc/osquery/osctrl.crt"
  environment: "production"
  baseurl: "https://osctrl.example.com"
  insecure: false
  verbose: false
  force: true
  logFormat: "text"
  interval: 60
  extensionsDir: "/etc/osquery/extensions/"
```

JSON configuration files are also supported — use a `.json` extension and the format is detected automatically.

### Configuration fields

| Field | Description | Default |
|---|---|---|
| `secret` | Enrollment secret for osctrl authentication | — |
| `secretFile` | Path to osquery secret file | OS-dependent |
| `flags` | Path to osquery flags file | OS-dependent |
| `cert` | Path to TLS certificate file | OS-dependent |
| `environment` | osctrl environment name or UUID | — |
| `baseurl` | Base URL of the osctrl server | — |
| `insecure` | Skip TLS certificate verification | `false` |
| `verbose` | Enable debug logging | `false` |
| `force` | Overwrite existing files | `false` |
| `logFormat` | Log format: `text` or `json` | `text` |
| `interval` | Sync interval in minutes (daemon mode) | `60` |
| `extensionsDir` | Directory for osquery extensions | OS-dependent |

## Usage

```
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

### One-shot commands

Retrieve flags and certificate:

```shell
osctrld flags --config /etc/osctrld/config.yaml
osctrld cert --config /etc/osctrld/config.yaml
```

Enroll a new node:

```shell
osctrld enroll --config /etc/osctrld/config.yaml
```

Verify configuration:

```shell
osctrld verify --config /etc/osctrld/config.yaml
```

### Daemon mode

Run osctrld as a long-lived daemon that periodically syncs configuration from osctrl:

```shell
osctrld service --config /etc/osctrld/config.yaml --interval 60
```

In daemon mode, osctrld will:

1. Sync flags, certificate, and extensions from osctrl every `--interval` minutes (with ±10% jitter)
2. Detect when any configuration has changed on disk
3. Automatically restart osquery via the OS service manager when changes are detected
4. Shut down gracefully on SIGINT/SIGTERM

## Deployment

### systemd (Linux)

Copy the service file and configuration:

```shell
cp osctrld /opt/osctrld/
cp service/linux/systemd.service /etc/systemd/system/osctrld.service
cp service/osctrld-sample.yaml /etc/osctrld/service.yaml
# Edit /etc/osctrld/service.yaml with your values

systemctl daemon-reload
systemctl enable osctrld
systemctl start osctrld
```

### launchd (macOS)

```shell
cp osctrld /usr/local/bin/
cp service/darwin/net.osctrl.daemon.plist /Library/LaunchDaemons/
# Edit the plist with correct paths

launchctl load /Library/LaunchDaemons/net.osctrl.daemon.plist
```

## Global options

```
--certificate FILE, -C FILE       Certificate file for osquery TLS
--configuration FILE, -c FILE     Configuration file for osctrld
--environment value, -e value     osctrl environment name or UUID
--flagfile FILE, -F FILE          Flagfile for osquery
--force, -f                       Overwrite existing files
--insecure, -i                    Skip TLS certificate verification
--interval value, -I value        Sync interval in minutes (default: 60)
--log-format value, -L value      Log format: text or json (default: text)
--osctrl-url value, -U value      Base URL for the osctrl server
--osquery-path FILE, -o FILE      Path to osquery installation
--secret value, -s value          Enrollment secret
--secret-file FILE, -S FILE       Secret file for osquery
--verbose, -V                     Enable debug logging
```

All flags can also be set via environment variables (e.g., `OSCTRL_URL`, `OSCTRL_ENV`, `OSQUERY_SECRET`).

## Documentation

Full documentation for the osctrl project is available at [https://osctrl.net](https://osctrl.net).

## Slack

Find us in the **#osctrl** channel in the official osquery Slack community ([Request an auto-invite!](https://join.slack.com/t/osquery/shared_invite/zt-h29zm0gk-s2DBtGUTW4CFel0f0IjTEw)).

## License

**osctrld** is licensed under the [MIT License](https://github.com/jmpsec/osctrl/blob/master/LICENSE).

## Donate

If you like **osctrld** you can send [BTC](bitcoin:bc1qvjep6r6j7a00xyhcgp4g2ea2f4pupaprcvllj5) or [ETH](ethereum:0x99e211251fca06286596498823Fd0a48785B64eB) donations to the following wallets:

<table>
  <tr align="center">
    <td><img alt="bitcoin:bc1qvjep6r6j7a00xyhcgp4g2ea2f4pupaprcvllj5" src="https://osctrl.net/btc.png" width="175" title="bitcoin:bc1qvjep6r6j7a00xyhcgp4g2ea2f4pupaprcvllj5"/></td>
    <td><img alt="ethereum:0x99e211251fca06286596498823Fd0a48785B64eB" src="https://osctrl.net/eth.png" width="175" title="ethereum:0x99e211251fca06286596498823Fd0a48785B64eB"/></td>
  </tr>
  <tr align="center">
    <td><sub>bitcoin:bc1qvjep6r6j7a00xyhcgp4g2ea2f4pupaprcvllj5</sub></td>
    <td><sub>ethereum:0x99e211251fca06286596498823Fd0a48785B64eB</sub></td>
  </tr>
</table>
