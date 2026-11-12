<p align="center">
  <img src="assets/logo.png" alt="evil-winrm-go" width="240">
</p>

# evil-winrm-go

A Go reimplementation of [evil-winrm](https://github.com/Hackplayers/evil-winrm): a
semi-interactive WinRM shell for pentesting and red teaming. The goal is a single
static binary, no Ruby/Python runtime, faster startup, and easy cross-compilation.

> For use only on systems you are authorized to test.

## Features

- Semi-interactive **PowerShell** shell over WinRM (HTTP/HTTPS)
- **NTLM** authentication (password), with message sealing on plain HTTP
- **Pass-the-hash** with an NT hash, with message sealing on plain HTTP
- **Kerberos** (password or credential cache) with message encryption
- **Client-certificate** authentication over HTTPS
- One PowerShell process for the whole session (variables and functions survive), with Tab completion of remote paths
- Working directory persists across commands (`cd` sticks), starting in Documents
- Dot-source local scripts into the session (`-s` / `script`)
- Built-in menu: `upload`, `download`, `script`, `services`, `menu`, `exit`
- One-shot command mode (`-c`) and a parallel multi-host mode (`-targets`)
- Single static binary

## Build

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o evil-winrm-go .
```

## Usage

```bash
# Password auth
./evil-winrm-go -i 10.10.10.10 -u Administrator -p 'P@ssw0rd'

# Over SSL (port 5986 by default with -S)
./evil-winrm-go -i 10.10.10.10 -u Administrator -p 'P@ssw0rd' -S

# Pass-the-hash (plain HTTP; -S is optional)
./evil-winrm-go -i 10.10.10.10 -u Administrator -H 2b576acbe6bcfda7294d6bd18041b8fe

# Kerberos from a credential cache. The SPN must be the host's FQDN, not an IP.
./evil-winrm-go -i dc.lab.local -kerberos -ccache /tmp/krb5cc_1000 -spn HTTP/dc.lab.local

# Kerberos with a password
./evil-winrm-go -i dc.lab.local -u Administrator -p 'P@ssw0rd' -kerberos -realm LAB.LOCAL

# Client certificate (HTTPS mutual auth)
./evil-winrm-go -i dc.lab.local -S -cert user.pem -key user.key

# Load a local script, then run one command
./evil-winrm-go -i 10.10.10.10 -u Administrator -p 'P@ssw0rd' -s ./scripts/recon.ps1 -c 'Invoke-Recon'

# Same command on every host in a file (one host per line, optional :port)
./evil-winrm-go -targets hosts.txt -u Administrator -p 'P@ssw0rd' -c 'hostname' -threads 8
```

### Flags

| Flag | Description |
|------|-------------|
| `-i` | Target IP or hostname (required) |
| `-u` | Username (required) |
| `-p` | Password |
| `-H` | NT hash for pass-the-hash |
| `-d` | Domain |
| `-S` | Use HTTPS/SSL |
| `-P` | WinRM port (default 5985, or 5986 with `-S`) |
| `-k` | Skip TLS certificate verification (default true) |
| `-c` | Run a single command then exit |
| `-targets` | File of hosts to run `-c` against, one per line |
| `-threads` | Parallel connections for `-targets` (default 8) |
| `-s` | Local `.ps1` file or directory to dot-source after connect |
| `-kerberos` | Authenticate with Kerberos |
| `-realm` | Kerberos realm |
| `-spn` | Kerberos SPN (default `HTTP/<host>`) |
| `-ccache` | Kerberos credential cache (default `$KRB5CCNAME`) |
| `-krb5conf` | Path to `krb5.conf` (default `/etc/krb5.conf`) |
| `-cert` | Client certificate PEM (requires `-S`) |
| `-key` | Client private key PEM (requires `-S`) |
| `-cacert` | CA PEM used to verify the server |

## In-shell commands

```
upload <local> [remote]     Upload a file to the target
download <remote> [local]   Download a file from the target
script <local.ps1 | dir>    Dot-source a local script into the session
services                    List services with their binary paths
menu                        Show the menu
exit | quit                 Close the session
```

Anything else is sent to the remote PowerShell session.

## Notes / limitations

- Pass-the-hash seals the WinRM messages, so it works on plain HTTP as well as
  with `-S`. Kerberos encrypts its own messages.
- Kerberos needs a `krb5.conf` and a service principal registered as `HTTP/<fqdn>`.
  An IP address will not resolve to a ticket; pass `-spn HTTP/fqdn`.
