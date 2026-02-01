# shieldcheck

Quick Linux server security status check. Get a complete security overview in ~1 second.

```
🛡️  shieldcheck
────────────────────────────────────────
SSH Security
  ✓  Password Auth           disabled
  ✓  Root Login              disabled
  ✓  Max Auth Tries          3
  ✓  Pubkey Auth             enabled

Intrusion Prevention (fail2ban)
  ✓  sshd jail               active
     Currently banned:       50 IPs
     Total banned:           109

Compromise Indicators
  ✓  User accounts           no suspicious users
  ✓  Suspicious processes    none detected
────────────────────────────────────────
✓ All checks passed
```

## Why shieldcheck?

| Tool | Run Time | Output | fail2ban Stats | GeoIP | Compromise Check |
|------|----------|--------|----------------|-------|------------------|
| **shieldcheck** | ~1 sec | 1 screen | ✅ | ✅ | ✅ |
| Lynis | 5-10 min | 100+ pages | ❌ | ❌ | Partial |
| Manual commands | varies | scattered | manual | manual | manual |

**shieldcheck** is designed for quick daily checks on personal servers and side projects. For comprehensive enterprise auditing, use [Lynis](https://github.com/CISOfy/lynis).

## Quick Start

```bash
# One-liner (run as root)
curl -sSL https://raw.githubusercontent.com/uppinote20/shieldcheck/main/shieldcheck.sh | sudo bash

# Or download and run
wget https://raw.githubusercontent.com/uppinote20/shieldcheck/main/shieldcheck.sh
chmod +x shieldcheck.sh
sudo ./shieldcheck.sh
```

## Usage

```bash
sudo shieldcheck [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| *(no flags)* | Normal mode - shows security checks with details, no GeoIP |
| `-q, --quiet` | Minimal output - counts only, ideal for scripting |
| `-v, --verbose` | Verbose mode - full details including GeoIP location info |
| `--no-geoip` | Disable external GeoIP lookups for privacy |
| `-h, --help` | Show help message |

### Examples

```bash
# Quick check (default - normal mode)
sudo shieldcheck

# Minimal output for scripts
sudo shieldcheck --quiet

# Full details with city/ISP information
sudo shieldcheck --verbose

# Run without any external API calls
sudo shieldcheck --no-geoip
```

## Features

- 🔒 **Secure** - HTTPS-only external APIs, input validation, output sanitization
- ⚡ **Fast** - ~1 second with caching, 42% faster on repeated runs
- 🌍 **GeoIP** - View login locations with city and ISP info (optional)
- 🎛️ **Flexible** - Multiple verbosity levels (quiet, normal, verbose)
- 🔇 **Privacy-first** - Disable external calls with `--no-geoip`
- 📊 **Detailed** - Shows SSH keys, cron jobs, network connections, and more

## What It Checks

### SSH Security
- Password authentication (should be disabled)
- Root login (should be disabled)
- Max auth tries (recommended: 3)
- Public key authentication (should be enabled)

### Firewall
- UFW status and rules
- iptables chain count

### Intrusion Prevention (fail2ban)
- Service status
- sshd jail (currently banned, total banned, failed attempts)
- recidive jail (repeat offender long-term bans)

### Compromise Indicators
- Suspicious user accounts (UID >= 1000)
- SSH authorized keys count (with key comments)
- User and system cron jobs
- Known malicious processes (cryptominers)
- Outbound network connections (with process names)
- Unique login IPs with GeoIP info (city, ISP) in verbose mode
  - Uses HTTPS-enabled ipinfo.io API
  - 24-hour caching for performance (42% faster on cached runs)
  - Privacy mode available with `--no-geoip`

### System Updates
- Automatic security updates configuration
- Pending security updates

## Requirements

- Linux (Ubuntu/Debian, CentOS/RHEL, etc.)
- Bash 4.0+
- Root access (for full checks)
- curl (for GeoIP lookups in verbose mode)

Optional but recommended:
- fail2ban (for intrusion prevention stats)
- UFW or iptables (for firewall checks)

## Sample Output

### All Secure
```
✓ All checks passed
```

### Verbose Mode (with GeoIP)
```
Unique login IPs             3 (last month)
  → X.X.X.10 (25x) US/Seattle, Example ISP
  → X.X.X.5 (12x) KR/Seoul, Example Telecom
  → X.X.X.8 (1x) JP/Tokyo, Example Network [NEW]
```

### Issues Found
```
⚠ Warnings: 2
  → Password authentication is enabled - use key-based auth
  → fail2ban is not installed

💡 Suggestions: 1
  → Consider setting PermitRootLogin to 'no'
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Warnings or suggestions present |

## Contributing

PRs welcome! Areas for improvement:

- [ ] JSON output mode (`--json`)
- [ ] More distro support
- [ ] Docker container checks
- [ ] Cloud provider metadata checks
- [ ] Custom check plugins

## License

MIT

## Related Projects

- [Lynis](https://github.com/CISOfy/lynis) - Comprehensive security auditing
- [ssh-audit](https://github.com/jtesta/ssh-audit) - SSH server/client auditing
- [fail2ban](https://github.com/fail2ban/fail2ban) - Intrusion prevention
