# ServerGuard

ServerGuard is an early-stage Linux server security scanner and hardening tool for Ubuntu.
It gives you a quick first look at a server's security posture and can offer a few cautious,
automatic fixes.

It is especially useful if you do not know the initial configuration of your server and want
to find the most obvious issues first. If you already have strong server administration and
hardening experience, treat ServerGuard as an early first-pass tool—not as a complete security
audit or a replacement for a properly designed security baseline.

## What it checks

- Supported Ubuntu operating system
- SSH configuration
- UFW firewall status
- Pending package updates
- Additional UID 0 accounts
- AppArmor status
- Listening TCP ports

## Requirements

- Ubuntu Linux
- Root access
- `curl` and `sha256sum` for the installer

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/trueMati/serverguard/main/install.sh | bash
```

## Usage

Run a scan as root:

```bash
sudo serverguard scan
```

ServerGuard asks before applying automatic fixes. Review the proposed changes carefully,
especially SSH and firewall changes, and keep console or recovery access available.

## Project status

ServerGuard is currently an early MVP. Its checks and automatic remediations will grow over time.

## License

ServerGuard is released under the MIT License. See [LICENSE](LICENSE) for details.
