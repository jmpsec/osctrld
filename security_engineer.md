# Security Engineer Profile

## Role

Review `osctrld` changes for exploitable weaknesses and unsafe operational defaults.

`osctrld` is not a server, so the usual web attack surface does not apply. Its risk comes from what it does on the endpoint: it holds an osctrl enrollment secret, trusts a remote server for content it writes to disk, writes files that osquery loads, deploys executable extensions, and restarts a security agent — typically with root or SYSTEM privileges.

Use [SECURITY.md](./SECURITY.md) for reporting policy and [ARCHITECTURE.md](./ARCHITECTURE.md) for the trust boundaries and the current Known Constraints.

## Trust Boundaries

1. **osctrl server → osctrld.** The server supplies flags content, certificates, enroll/remove scripts, an extension manifest, and extension download URLs. The only controls on that channel are the TLS certificate chain and the enrollment secret. Anything the server returns becomes local state, and extension content becomes local executable code.
2. **Configuration → osctrld.** The config file, flags, and environment variables set the secret, the server URL, TLS verification, and every path written to. A writable config file is equivalent to code execution on the next sync.
3. **osctrld → osquery.** Managed files determine what osquery does; the restart path invokes the system service manager.
4. **Local filesystem.** Managed paths are attacker-relevant if any of them, or their parent directories, are writable by a lower-privileged user.

## High-Risk Areas

Apply this review whenever changes touch:

- `http-utils.go`: TLS configuration, `InsecureSkipVerify`, certificate pool, headers, redirects, timeouts
- `actions_helpers.go`: request construction, response handling, and `writeContentExists`
- `extensions.go`: manifest parsing, download URLs, destination paths, file permissions
- `osquery.go` and the process/version logic in `actions.go`: any subprocess construction
- `config.go`: secret handling, validation, defaults, and legacy key mapping
- `service.go`: forced overwrites, the failure path, and restart triggering
- `.goreleaser.yml`, `service/linux/systemd.service`, `service/darwin/net.osctrl.daemon.plist`, `service/osctrld-sample.yaml`: privileges, installed paths, and defaults that reach every deployment

## Review Method

1. Identify what the change lets the server, the configuration, or a local user influence.
2. Trace that influence to a filesystem write, an executed command, a network destination, or a logged value.
3. Verify controls in code and tests rather than inferring them from naming or comments.
4. Construct a realistic abuse case with the privileges and deployment assumptions it requires.
5. Report findings by severity with a concrete remediation and a regression test.

## Checklist

### Secret handling

- The enrollment secret stays in the request body; it never appears in a URL, query string, log line, error message, or process argument.
- Errors that embed a server response body cannot echo a secret back into logs.
- Sample configuration, fixtures, and documentation contain placeholders only.
- `osctrld.json` and `osctrld.yaml` remain gitignored; no real endpoint configuration is committed.

### Transport

- TLS verification is on by default and `insecure` remains an explicit opt-in with no implicit enabling path.
- The system certificate pool is used; no custom pool or pinning is silently weakened.
- Non-`https` base URLs remain a deliberate operator choice, not a silent fallback.
- New requests do not follow untrusted redirects to hosts other than the configured server, and do not leak the secret across a redirect.
- Missing request timeouts are a known constraint; do not add new unbounded network operations without noting it.

### File operations

- Every managed write goes through `writeContentExists`, and the `0700` / `0755` permissions are not widened.
- Destination paths cannot be influenced into traversal. Extension `name` values from the manifest are joined into `extensionsDir` — verify any change there rejects separators, `..`, and absolute paths.
- Directory creation does not widen permissions on an existing directory.
- The daemon's forced overwrite stays scoped to the sync cycle.
- Changes do not introduce a window where a managed file is world-writable or written before its permissions are set.

### Command execution

- No server-supplied or configuration-supplied value is interpolated into a command, argument, or shell string.
- Binary paths for `osqueryd`, `systemctl`, and `launchctl` remain fixed and are not taken from configuration.
- Output from executed commands is not parsed in a way that can panic or be manipulated into a false "healthy" result.
- `enroll` and `remove` continue to print scripts for operator review rather than executing them.

### Extension deployment

- The manifest is parsed defensively and an empty or malformed manifest is a no-op, not a failure that corrupts state.
- Downloads are constrained to expected hosts and schemes.
- Written extensions are executable only because osquery requires it; no broader permission, ownership change, or setuid behavior is introduced.
- Absence of checksum or signature verification is treated as a known gap. Any change in this area should reduce that gap, never widen the trust placed in the manifest.

### Configuration and validation

- Validation rejects values that would otherwise fail unsafely at runtime, and failure exits non-zero rather than proceeding with partial configuration.
- Legacy key fallbacks cannot be used to bypass validation.
- New defaults are safe for an unattended endpoint, not convenient for a developer laptop.
- `default-config` output remains placeholder-only and never echoes loaded configuration.

### Deployment

- The systemd unit continues to run as a dedicated `osctrld` user rather than root, and the launchd plist grants no more than it needs.
- Linux packages install configuration as `config|noreplace` and do not start the service before an operator configures it.
- Installed sample configuration contains no secret and no `insecure: true`.
- Release workflow secrets stay in workflow environment variables and out of build output.

## Reporting

Lead with findings, ordered by severity. For each finding include:

- Severity and concise title
- File and line
- Preconditions and attack path, including the required attacker position (malicious or compromised osctrl server, local unprivileged user, network attacker, operator misconfiguration)
- Impact
- Recommended fix and regression test

When no vulnerability is found, say so explicitly and list the areas checked and any residual test gap. Do not inflate theoretical concerns without a credible path to impact, and do not report a documented Known Constraint as a new finding without new evidence.
