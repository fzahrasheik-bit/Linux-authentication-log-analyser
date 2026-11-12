# Linux Authentication Log Analysis

- **Source:** `sample_logs\auth.log`
- **Log lines scanned:** 12
- **Failed login events:** 10
- **Unique source IPs:** 2
- **Alert threshold:** 3 failed attempts per IP

## Flagged IP addresses

| Source IP | Failed attempts | Usernames targeted |
|---|---:|---|
| `203.0.113.10` | 7 | admin, deploy, oracle, postgres, root, test, ubuntu |
| `198.51.100.23` | 3 | backup, guest |

## Interpretation

An IP is flagged because its failed-login count reached the configured threshold. This is a triage signal, **not proof that the IP is malicious**. Investigate the surrounding events and validate the source before taking action.

## Method

The analyser scans each line for common OpenSSH failed-password and invalid-user messages, validates extracted IP addresses, counts events by source IP, and flags sources at or above the threshold.
