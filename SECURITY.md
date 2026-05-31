# Security Policy

## Reporting a Vulnerability

The `osctrld` project takes security vulnerabilities seriously.

If you believe you have found a security issue in `osctrld`, please do not open a public GitHub issue.

Instead, report it responsibly by emailing:

<osctrl-security@jmpsec.com>

Please include:

- A clear description of the vulnerability.
- Steps to reproduce, including a proof of concept when possible.
- Affected versions, operating systems, commands, or daemon modes.
- Potential impact, such as credential exposure, privilege escalation, unsafe file writes, extension deployment abuse, or osquery disruption.
- Any suggested mitigation or fix.

We will acknowledge receipt of your report as soon as possible and work with you to assess and remediate the issue.

## Supported Versions

Security fixes are provided for the latest released version of `osctrld`.

Users are strongly encouraged to keep deployments up to date and follow release notes closely, especially for breaking changes and security-related updates.

## Disclosure Policy

We follow a responsible disclosure process:

- Reporters will receive confirmation of the vulnerability report.
- We will investigate and validate the issue.
- We will work on a fix and coordinate a release.
- Public disclosure will occur after a fix is available, or in coordination with the reporter when appropriate.

We appreciate responsible disclosure and will credit reporters when possible, unless anonymity is requested.

## Security Considerations

`osctrld` is a security-sensitive daemon because it manages local osquery state and can restart osquery services. Operators should take care to:

- Protect osctrl enrollment secrets and local osquery secret files.
- Use TLS for osctrl communication and avoid `insecure` mode outside controlled testing.
- Restrict write permissions on managed flag, certificate, secret, script, and extension paths.
- Validate extension deployment sources and keep extension directories writable only by trusted users.
- Run osctrld with the minimum privileges required for the target operating system and service manager.
- Monitor osctrld and osquery logs for unexpected configuration changes or restart loops.
- Apply upgrades promptly, especially for security-related releases.

## Third-Party Dependencies

`osctrld` relies on third-party open source components. Dependency updates and security fixes are tracked and applied as part of normal maintenance.

If a vulnerability is discovered in a third-party dependency that affects `osctrld`, report it using the same process above.

## Acknowledgements

We thank the security community for helping keep `osctrld`, `osctrl`, and their users safe.
