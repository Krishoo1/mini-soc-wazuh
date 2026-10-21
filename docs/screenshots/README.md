# Evidence screenshots

All screenshots are from the lab run on 19 October 2026. The Wazuh admin password in screenshot 04 is blacked out.

| File | What it shows | Report ref |
|---|---|---|
| 01-wazuh-install-progress.png | Wazuh 4.14.9 assisted installer running (indexer, manager, Filebeat steps) | Environment |
| 02-dashboard-overview-no-agents.png | Fresh dashboard before any agent was enrolled | Environment |
| 03-cis-benchmark-kali-endpoint.png | CIS benchmark on `kali-endpoint`: 87 passed, 95 failed, score 47% | Baseline |
| 04-install-finished-password-redacted.png | Installer "Installation finished" (password redacted) | Environment |
| 05-baseline-auth-events-kali-endpoint.png | First authentication events collected from the endpoint | E2 |
| 06-logtest-rule-100100-fired.png | `wazuh-logtest`: rule 100100 fires on the 5th failed login | E9 |
| 07-add-rule-100100-to-local-rules.png | Adding rule 100100 and validating the rules file | Detection engineering |
| 08-attacker-cmd-failed-logins-first-test.png | Attacker terminal: wrong-password attempts | E6 |
| 09-event-list-rule-100110-new-user.png | Event list with custom rule 100110 (new user) | E8 |
| 10-query-100110-and-5901.png | Query `rule.id: (100110 or 5901 or 5902)` | E8 |
| 11-alert-100110-document-details.png | Alert 100110 details: user `testsoc`, UID 1001 | E8 |
| 12-alert-100110-rule-fields-mitre.png | Alert 100110 rule fields and MITRE T1136.001 | E8 |
| 13-query-100130-sshd-config-modified.png | Query for rule 100130, two hits | E8 |
| 14-fim-100130-timeline-agent-restart.png | 100130 alerts in the timeline, plus agent stop/start events | E8 |
| 15-bruteforce-query-5760-100100-5715.png | Query `rule.id: (100100 or 5760 or 5763 or 5715)` | E2 |
| 16-bruteforce-event-list-20-hits.png | Failures, two 100100 alerts, then the 5715 success | E2 |
| 17-alert-100100-details-srcip-fulllog.png | Alert 100100: srcip 192.168.99.1, dstuser kali, raw `full_log` | E1, E3 |
| 18-alert-100100-previous-output-mitre.png | Alert 100100: `previous_output`, frequency 5, MITRE T1110 | E1 |
| 19-attacker-cmd-connection-timed-out-during-block.png | Attacker terminal: "Connection timed out" while blocked | E6 |
| 20-iptables-drop-during-block.png | Endpoint firewall: DROP for 192.168.99.1 | E5 |
| 21-active-response-651-blocked.png | Alerts 100100 then 651 "Host Blocked" | E4 |
| 22-successful-login-last-login-from-attacker-ip.png | Endpoint "Last login ... from 192.168.99.1" on a later login | Investigation |
| 23-iptables-chain-empty-after-unblock.png | Firewall chain empty after the block expired | E5 |
| 24-active-response-652-unblocked.png | Alert 652 "Host Unblocked" at 10:25:05 | E4 |
