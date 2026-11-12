<p align="center">
  <img src="assets/logo.png" alt="evil-winrm-go" width="240">
</p>

# evil-winrm-go

A Go reimplementation of [evil-winrm](https://github.com/Hackplayers/evil-winrm): a
semi-interactive WinRM shell for pentesting and red teaming. The goal is a single
static binary, no Ruby/Python runtime, faster startup, and easy cross-compilation.

## Features

- Semi-interactive **PowerShell** shell over WinRM (HTTP/HTTPS)
- **NTLM** authentication (password), with message sealing on plain HTTP
- **Pass-the-hash** with an NT hash, with message sealing on plain HTTP
- **Kerberos** (password or credential cache) with message encryption
- **Client-certificate** authentication over HTTPS
- One `powershell.exe` for the whole session: variables, functions and the working directory survive, starting in Documents
- Tab completion of command names, of local paths for `upload` and `script`, and of remote paths otherwise
- Load a local `.ps1` file or directory into that process (`-s` / `script`)
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

# Pass-the-hash. -H takes the NT hash, or the NT half of LM:NT. -S is optional.
./evil-winrm-go -i 10.10.10.10 -u Administrator -H 2b576acbe6bcfda7294d6bd18041b8fe

# Kerberos from a credential cache. The SPN must be the host's FQDN, not an IP.
./evil-winrm-go -i dc.lab.local -kerberos -ccache /tmp/krb5cc_1000 -spn HTTP/dc.lab.local

# Kerberos with a password
./evil-winrm-go -i dc.lab.local -u Administrator -p 'P@ssw0rd' -kerberos -realm LAB.LOCAL

# Client certificate (HTTPS mutual auth)
./evil-winrm-go -i dc.lab.local -S -cert user.pem -key user.key

# Load a local script, then run one command
./evil-winrm-go -i 10.10.10.10 -u Administrator -p 'P@ssw0rd' -s ./scripts/recon.ps1 -c 'Invoke-Recon'

# Same command on every host in a file. One host per line, optional :port,
# blank lines and # comments are skipped. -i cannot be combined with -targets.
./evil-winrm-go -targets hosts.txt -u Administrator -p 'P@ssw0rd' -c 'hostname' -threads 8
```

### Flags

| Flag | Description |
|------|-------------|
| `-i` | Target IP or hostname (or use `-targets`) |
| `-u` | Username |
| `-p` | Password |
| `-H` | NT hash for pass-the-hash (`NT` or `LM:NT`) |
| `-d` | Domain |
| `-S` | Use HTTPS/SSL |
| `-P` | WinRM port (default 5985, or 5986 with `-S`) |
| `-k` | Skip TLS certificate verification (default true) |
| `-c` | Run a single command then exit |
| `-targets` | File of hosts to run `-c` against, one per line (`host`, `host:port`, or `[ipv6]:port`) |
| `-threads` | Parallel connections for `-targets` (default 8) |
| `-s` | Local `.ps1` file or directory to load into the session |
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
script <local.ps1 | dir>    Load a local script into the session
services                    List services with their binary paths
menu                        Show the menu
exit | quit                 Close the session
```

Anything else is sent to the remote PowerShell session.

## Notes / limitations

- The session is one `powershell.exe` left open. `cd`, variables and functions survive. Tab completes remote paths from that process. `upload` and `script` complete local paths instead.
- `-s` and `script` upload the file to `C:\Windows\Temp` and run it with `Invoke-Expression`, so what it defines stays in the process.
- Pass-the-hash seals every WinRM message, so `-H` works on plain HTTP. `-S` is only required for certificate authentication. Kerberos encrypts its own messages.
- Kerberos needs a `krb5.conf` and a service principal registered as `HTTP/<fqdn>`. An IP address will not resolve to a ticket; pass `-spn HTTP/fqdn`. With `-kerberos` and no `-ccache`, the cache is read from `$KRB5CCNAME`.
- `-targets` requires `-c`. Output for each host is grouped on stderr. Any failed host makes the process exit 1.
