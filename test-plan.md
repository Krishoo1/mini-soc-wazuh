# Test Plan

Times are Wazuh dashboard times (raw endpoint logs are 4 hours ahead).

| # | Test | Action | Expected | Observed |
|---|---|---|---|---|
| 1 | SSH brute force | 5+ wrong passwords for `kali` from the Windows host | Several 5760 alerts, then 100100 | 100100 at 09:58:34 and 09:59:07 |
| 2 | Login after failures | Correct password right after the failures | 5715 | 5715 at 09:59:19 |
| 3 | Active Response block | More failures until 100100 fires | 651 within seconds, DROP in iptables, SSH timeouts | 651 at 10:15:06 (2 s after 100100 at 10:15:04); DROP present; connection timed out |
| 4 | Automatic unblock | Wait 600 s | 652, iptables chain empty | 652 at 10:25:05; chain empty |
| 5 | New user | `sudo useradd -m testsoc`, then `userdel -r testsoc` | 100110 | 100110 at 08:40:05 |
| 6 | Config tampering | Append a line to `/etc/ssh/sshd_config`, then revert | 100130 twice | 100130 at 09:44:16 and 09:44:27 |
| 7 | Root shell via sudo | `wazuh-logtest` with a sudo `COMMAND=/bin/bash` line | 100120 | Passes in logtest after adding parent 5403 |

## Useful dashboard queries

```
rule.id: (100100 or 5760 or 5763 or 5715)
rule.id: (100100 or 651 or 652)
rule.id: (100110 or 5901 or 5902)
rule.id: (100130 or 550)
```
