# shieldcheck

Quick Linux server security status check. Get a complete security overview in 2 seconds.

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

| Tool | Run Time | Output | fail2ban Stats | Compromise Check |
|------|----------|--------|----------------|------------------|
| **shieldcheck** | ~2 sec | 1 screen | ✅ | ✅ |
| Lynis | 5-10 min | 100+ pages | ❌ | Partial |
| Manual commands | varies | scattered | manual | manual |

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
- SSH authorized keys count
- User and system cron jobs
- Known malicious processes (cryptominers)
- Outbound network connections
- Unique login IPs

### System Updates
- Automatic security updates configuration
- Pending security updates

## Requirements

- Linux (Ubuntu/Debian, CentOS/RHEL, etc.)
- Bash 4.0+
- Root access (for full checks)

Optional but recommended:
- fail2ban
- UFW or iptables

## Sample Output

### All Secure
```
✓ All checks passed
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
