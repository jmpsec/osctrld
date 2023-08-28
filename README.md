# osctrld

<p align="center">
  <img alt="osctrld" src="logo.png" width="300" />
  <p align="center">
    Daemon for `osctrl`, the fast and efficient osquery management.
  </p>
  <p align="center">
    <a href="https://github.com/jmpsec/osctrld/blob/master/LICENSE">
      <img alt="Software License" src="https://img.shields.io/badge/license-MIT-green?style=flat-square&fuckgithubcache=1">
    </a>
    <a href="https://goreportcard.com/report/github.com/jmpsec/osctrld">
      <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/jmpsec/osctrld?style=flat-square&fuckgithubcache=1">
    </a>
  </p>
</p>

## What is osctrld?

**osctrld** is  the daemon component for [osctrl](https://osctrl.net). Its purpose is to maintain integrity of osquery clients, manage its flags, enrolling secret and server certificate. It can also provide a fast method to deploy osquery extensions.

## Documentation

You can find the full documentation of the project in [https://osctrl.net](https://osctrl.net)

## Usage

```shell
NAME:
   osctrld - Daemon for osctrl, the fast and efficient osquery management

USAGE:
   osctrld [global options] command [command options] [arguments...]

VERSION:
   1.0.0

DESCRIPTION:
   Daemon for osctrl, the fast and efficient osquery management, to manage secret, flags and osquery deployment

COMMANDS:
   enroll   Enroll a new node in osctrl, using new secret and flag files
   remove   Remove enrolled node from osctrl, clearing secret and flag files
   verify   Verify flags, cert and secret for an enrolled node in osctrl
   flags    Retrieve flags for osquery from osctrl and write them locally
   cert     Retrieve server certificate for osquery from osctrl and write it locally
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --certificate FILE, -C FILE                                    Use FILE as certificate for osquery, if needed. Default depends on OS [$OSQUERY_CERTIFICATE]
   --configuration value, -c value, --conf value, --config value  Configuration file for osctrld to load all necessary values [$OSCTRL_CONFIG]
   --environment value, -e value, --env value                     Environment in osctrl to enrolled nodes to [$OSCTRL_ENV]
   --flagfile FILE, -F FILE                                       Use FILE as flagfile for osquery. Default depends on OS [$OSQUERY_FLAGFILE]
   --force, -f                                                    Overwrite existing files for flags, certificate and secret (default: false) [$OSCTRL_FORCE]
   --help, -h                                                     show help (default: false)
   --insecure, -i                                                 Ignore TLS warnings, often used with self-signed certificates (default: false) [$OSCTRL_INSECURE]
   --osctrl-url value, -U value                                   Base URL for the osctrl server [$OSCTRL_URL]
   --osquery-path FILE, --osquery FILE, -o FILE                   Use FILE as path for osquery installation, if needed. Default depends on OS [$OSQUERY_PATH]
   --secret value, -s value                                       Enroll secret to authenticate against osctrl server [$OSCTRL_SECRET]
   --secret-file FILE, -S FILE                                    Use FILE as secret file for osquery. Default depends on OS [$OSQUERY_SECRET]
   --verbose, -V                                                  Enable verbose informational messages (default: false) [$OSCTRL_VERBOSE]
   --version, -v                                                  print the version (default: false)
```

## Slack

Find us in the #osctrl channel in the official osquery Slack community ([Request an auto-invite!](https://join.slack.com/t/osquery/shared_invite/zt-h29zm0gk-s2DBtGUTW4CFel0f0IjTEw))

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
