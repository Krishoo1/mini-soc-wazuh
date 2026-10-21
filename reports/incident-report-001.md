# Mini SOC with Wazuh: Incident Investigation Report

**Incident:** SSH brute-force attack followed by a successful login (simulated, lab environment)  
**Prepared by:** Krish Rawat  
**Date:** 19 October 2026  
**Platform:** Wazuh 4.14.9 (all-in-one: manager, indexer, dashboard)  
**Time convention:** All times are Wazuh dashboard times. Raw log timestamps on the endpoint are 4 hours ahead of the dashboard display (for example, a log line stamped 13:59:05 appears as 09:59 on the dashboard).

## 1. Executive Summary

A small security monitoring environment (a "Mini SOC") was built with Wazuh. One authorized endpoint was enrolled, security events were collected, four custom detection rules were written and tested, and an automated response was configured.

During a controlled attack simulation, a repeated password-guessing attack against the SSH service of the monitored endpoint was detected by custom rule **100100** within seconds. The source IP was automatically blocked by Wazuh Active Response (rule 651) and released after 10 minutes (rule 652). The exercise also demonstrated the highest-priority SOC pattern: a burst of failed logins followed by a successful login for the same account.

All systems were owned by the tester and the attack was performed only inside an isolated lab network.

## 2. Environment

| Role | System | Address | Notes |
|---|---|---|---|
| SIEM server | Ubuntu Server 24.04.5 LTS (VMware Workstation VM) | 192.168.99.132 | Wazuh 4.14.9 manager, indexer and dashboard; 4 vCPU, about 5 GB RAM, 48 GB disk |
| Monitored endpoint (victim) | Kali GNU/Linux 2026.3 (VM), agent `kali-endpoint`, ID 001 | 192.168.99.129 | Wazuh agent v4.14.9, SSH enabled, journald log collection |
| Attacker (simulated) | Windows host running the OpenSSH client | 192.168.99.1 | Manual wrong-password attempts against the `kali` account |

Network: VMware NAT network 192.168.99.0/24.

**Telemetry enabled:** system and authentication logs (journald, which carries sshd, sudo and useradd events), File Integrity Monitoring (real-time on `/etc/ssh`), and Security Configuration Assessment (CIS benchmark).

**Baseline finding:** the Security Configuration Assessment reported a CIS Distribution Independent Linux Benchmark score below 50% for the endpoint (alert 19004 showed 46%; the scan summary later showed **47%**, with 87 checks passed, 95 failed and 8 not applicable; screenshot 03). The endpoint was not hardened at the time of the exercise.

## 3. Detection Engineering: Custom Rules

Four custom rules were added to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh server and tested with `wazuh-logtest` and, where possible, live. A fifth control, Active Response, was added on top of rule 100100.

| Rule ID | Level | Detects | Built on | MITRE ATT&CK | Verification |
|---|---|---|---|---|---|
| 100100 | 10 | SSH brute force: 5 failed logins from the same source IP within 120 s | 5760 (sshd authentication failed) | T1110 Brute Force | Logtest and live |
| 100110 | 12 | New local user account created | 5902 (new user added) | T1136.001 Local Account | Live (user `testsoc` created at 08:40:05) |
| 100120 | 8 | Root shell obtained through sudo (bash, sh or su) | 5402, 5403 | T1548.003 Sudo and Sudo Caching | Logtest |
| 100130 | 12 | `/etc/ssh/sshd_config` modified (File Integrity Monitoring) | 550 (integrity checksum changed) | T1562.001 Impair Defenses | Live (09:44:16 modification, 09:44:27 revert) |
| Active Response on 100100 | n/a | Automatic block of the offending source IP for 600 s | `firewall-drop` | n/a | Live (651 at 10:15:06, 652 at 10:25:05) |

### Tuning performed

- **Rule 100120:** the first logtest of a sudo root shell matched built-in rule **5403** ("First time user executed sudo") instead of the custom rule, because Wazuh uses 5403 the first time a user runs sudo. A real attacker's first root shell would have been missed. The rule was changed from `<if_sid>5402</if_sid>` to `<if_sid>5402,5403</if_sid>`, and the retest matched 100120 on the very first event.
- **Rule 100100 vs built-in 5763:** in logtest the built-in brute-force rule 5763 fired on the 8th failure, while the custom rule fired on the 5th. In the live test rule 5763 did not fire at all, so the custom rule detected the attack earlier and more reliably in this environment.

## 4. Incident Investigation

### 4.1 Alert

Rule **100100** ("Mini-SOC: Possible SSH brute force from 192.168.99.1") fired at 09:58:34 on agent `kali-endpoint` (screenshots 17 and 18).

| Field | Value |
|---|---|
| Rule ID / level | 100100 / 10 |
| Rule frequency | 5 failures (timeframe 120 s) |
| Source IP (`data.srcip`) | 192.168.99.1 |
| Targeted account (`data.dstuser`) | kali |
| Agent | kali-endpoint (001), 192.168.99.129 |
| Log source | journald, program `sshd-session` |
| MITRE ATT&CK | T1110, tactic Credential Access, technique Brute Force |

### 4.2 Investigation

**Question 1: How many attempts, and how fast?** Searching `rule.id: (100100 or 5760 or 5763 or 5715)` for the agent shows 12 failed password attempts for the `kali` account from 192.168.99.1 between 09:58:08 and 09:59:13, about 65 seconds (screenshots 15 and 16). Two of those failures were the events that triggered rule 100100. The timing and volume indicate a rapid guessing pattern rather than a user mistyping a password.

**Question 2: Did the attacker get in?** Yes. Rule 5715 ("sshd: authentication success") fired at 09:59:19, six seconds after the last failure. A success immediately after a burst of failures is the standard indicator of a compromised credential and is the point where a SOC analyst escalates the case. The endpoint's own record confirms the source: when logging in again from the same host, the endpoint prints `Last login: Mon Oct 19 09:59:18 2026 from 192.168.99.1`, matching the 5715 alert time within a second (screenshot 22).

**Question 3: Is the attack still ongoing, and what else changed?** Pivoting on the agent for the same period showed PAM session and sudo events (rules 5501, 5502, 5402) but no new-user (100110) or configuration-tampering (100130) alerts during the attack window, so no persistence or defence-evasion activity was observed in this incident.

**Question 4: Why was it possible?** The sshd error output on the attacker side showed `Permission denied (publickey,password)`, which confirms that password authentication was enabled on the endpoint (screenshot 08). Together with the sub-50% CIS score, the weak baseline made password guessing a viable attack path.

### 4.3 Event timeline (dashboard time)

| Time | Event | Rule |
|---|---|---|
| 09:58:08 to 09:58:28 | 4 failed SSH logins for `kali` from 192.168.99.1 | 5760 |
| 09:58:34 | Brute-force threshold reached, **alert 1** | **100100** |
| 09:58:39 to 09:58:57 | 4 more failed logins | 5760 |
| 09:59:07 | Threshold reached again, **alert 2** | **100100** |
| 09:59:11 and 09:59:13 | 2 more failed logins | 5760 |
| 09:59:19 | **Successful login** for `kali` | **5715** |
| 10:15:04 | Second wave of attempts (5 failures across two sessions), brute-force alert | **100100** |
| 10:15:06 | Source IP automatically blocked | **651** |
| 10:15 to 10:25 | Further SSH connections from 192.168.99.1 time out | n/a |
| 10:25:05 | Block automatically lifted after 600 s | **652** |

## 5. Evidence

All files are in `docs/screenshots/`; see its README for the full index.

| # | Evidence | File(s) |
|---|---|---|
| E1 | Alert 100100 details (srcip, dstuser, MITRE T1110, `previous_output` with the failed attempts) | 17, 18 |
| E2 | Event list showing 5760 failures, 100100 alerts and the 5715 success | 15, 16 |
| E3 | Raw log line `Failed password for kali from 192.168.99.1 port 64049 ssh2` (program `sshd-session`, location `journald`) | 17 |
| E4 | Block and unblock alerts 651 (10:15:06) and 652 (10:25:05) | 21, 24 |
| E5 | `iptables -L INPUT -n` showing `DROP all 192.168.99.1 0.0.0.0/0` during the block, and an empty INPUT chain after it expired | 20, 23 |
| E6 | Attacker-side terminal: `Permission denied` messages, then `Connection timed out` on port 22 during the block | 08, 19 |
| E7 | Custom rule definitions | `rules/local_rules.xml`, screenshot 07 |
| E8 | New-user alert 100110 (user `testsoc`, UID 1001, from `/dev/pts/1`) and file-integrity alerts 100130 | 09 to 14 |
| E9 | `wazuh-logtest` output showing 100100 firing on the 5th event | 06 |

## 6. Response

### 6.1 Automated containment (implemented and verified)

Wazuh Active Response was configured to run the `firewall-drop` command on the endpoint whenever rule 100100 fires, with a 600-second timeout. The Wazuh server address 192.168.99.132 was added to the white list so the SIEM could never block itself.

- 10:15:04: rule 100100 fired.
- 10:15:06: rule 651 ("Host Blocked by firewall-drop Active Response"), two seconds later.
- The endpoint firewall showed a DROP rule for 192.168.99.1, and the attacker's SSH connections timed out instead of returning an authentication error.
- 10:25:05: rule 652 ("Host Unblocked"). The firewall chain was empty again, confirming the block lifted by itself.

### 6.2 Recommended actions in a production incident

These steps were not required in this controlled exercise but are the standard follow-up when a successful login follows a brute-force burst:

1. Treat the account as compromised: reset the password, terminate active sessions, and review the endpoint's authentication logs and `last` output for activity after the successful login.
2. Check for persistence: new users (rule 100110), changes to `sshd_config` (100130), new SSH keys, scheduled tasks.
3. Harden SSH: disable password authentication and use key-based login only, set `PermitRootLogin no`, restrict SSH to trusted source addresses, and consider fail2ban or rate limiting.
4. Raise the endpoint's CIS score by remediating the failed benchmark checks reported by Wazuh.
5. Enable email or ticketing notifications for level 12 and above alerts (these are flagged `mail: true` but no mail relay is configured).
6. Block permanently (rather than for 10 minutes) when the source is confirmed hostile and external.

## 7. Lessons Learned and Limitations

- **Rule order matters.** The first-time-sudo rule (5403) silently shadowed the custom rule until it was added as a parent. Always test the first event, not only repeated events.
- **Frequency rules need thresholds matched to the environment.** Five failures in 120 seconds suits a lab; in production it would need whitelisting of administrators and testing against normal behaviour to limit false positives.
- **Timestamps must be normalised.** The dashboard time and raw log time differ by 4 hours, which would confuse an investigation timeline if not stated.
- **Limitations:** a single monitored endpoint; the attack was a manual test, not a tool-driven attack; Active Response blocks only the offending IP on that endpoint; no external threat-intelligence or ticketing integration.

## Appendix: configuration

The custom rules are in `rules/local_rules.xml`. The Active Response block is in `configs/active-response.xml` and the File Integrity Monitoring snippet is in `configs/agent-fim-snippet.xml`.

Dashboard queries used:

```
rule.id: (100100 or 5760 or 5763 or 5715)
rule.id: (100100 or 651 or 652)
rule.id: (100110 or 5901 or 5902)
rule.id: (100130 or 550)
```
