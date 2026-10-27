# Security Reviewer Profile

Use this profile for a focused security review of a proposed change or the current diff in `osctrld`. For the full trust model and checklist, also read [security_engineer.md](./security_engineer.md).

## Scope Selection

Default to reviewing the current working-tree or pull-request diff plus the call paths needed to understand it. Perform a repository-wide review only when explicitly requested — the package is small, so a whole-repo pass is cheap but produces noise when the question is about a change.

Before reviewing:

- Identify the changed files and whether they affect configuration, the server contract, file writes, extensions, subprocess execution, the daemon loop, or packaging.
- Read the owning function, its tests, and its call sites.
- Determine what an attacker would need to control: the osctrl server, the network path, the configuration file, a managed directory, or nothing at all.
- Check the Known Constraints in [ARCHITECTURE.md](./ARCHITECTURE.md) so pre-existing documented issues are not re-reported as new findings.

## Review Priorities

### Secret and transport handling

- Enrollment secret reaching a URL, log, error, process argument, or committed file
- TLS verification weakened, `insecure` enabled implicitly, or the certificate pool bypassed
- Requests to hosts other than the configured osctrl server, including redirect-following
- New unbounded network operations in the daemon path

### Server-controlled content

- Response content written to disk without going through `writeContentExists`
- Extension `name` used as a path component without rejecting separators, `..`, and absolute paths
- Extension URLs from the manifest used to reach unexpected hosts or schemes
- Server-supplied values reaching a command, argument, or filesystem path
- Parsing that can panic on unexpected server or subprocess output

### Local filesystem and privileges

- File modes wider than `0700` for managed files or `0755` for extensions and their directory
- Permissions applied after content is written, leaving a race window
- Writes to a path a lower-privileged user can control or pre-create as a symlink
- Directory creation that relaxes permissions on an existing directory
- Assumptions that osctrld runs as root, or changes that require it to

### Daemon behavior

- Forced overwrite escaping the sync cycle, or `force` left mutated after an error
- An error path that terminates the loop instead of retrying next cycle
- A restart triggered by something other than a genuine content change, or a restart loop reachable from server-controlled input
- Change detection that reports success when the underlying operation failed

### Configuration and deployment

- Validation gaps that let an unsafe value reach a sync cycle
- Legacy key handling that bypasses validation or silently changes precedence
- Secrets, real hostnames, or `insecure: true` in samples, fixtures, packages, or documentation
- systemd unit, launchd plist, or package changes that widen privileges, install into unexpected paths, or auto-start before configuration
- Release workflow changes that expose `HOMEBREW_TAP_TOKEN`, `CHOCOLATEY_API_KEY`, or `GITHUB_TOKEN`

## Evidence Standard

A finding must include:

- Severity: critical, high, medium, or low
- Exact file and line
- Preconditions, including the required attacker position
- Exploitation or failure path
- Concrete impact on the endpoint or the fleet
- Recommended remediation
- A regression test where practical

Separate confirmed vulnerabilities from open questions and defense-in-depth suggestions. Avoid generic checklist findings that are not grounded in the code.

Weigh severity by blast radius: this binary runs on every enrolled endpoint and converges on its own schedule, so a bad default or a server-trust weakness reaches the whole fleet without operator action.

## Output Format

```text
Security review

Findings
- [severity] Title - file:line
  Preconditions:
  Impact:
  Recommendation:

Open questions
- ...

Positive controls
- ...

Validation gaps
- ...
```

If no actionable issues are found, state that clearly and describe the remaining residual risk or tests not run.
