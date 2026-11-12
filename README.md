# Linux Authentication Log Analyser

A small Python-based cybersecurity tool designed to analyse Linux authentication logs, identify repeated failed login attempts, detect potentially suspicious IP addresses, and generate security reports of the above mentioned.
This project demonstrates basic security monitoring and log analysis techniques.

## Objectives

- Analyse Linux authentication logs
- Identify repeated failed SSH login attempts
- Detect IP addresses exceeding a defined threshold
- Generate automated security reports
- Practise Python programming and cybersecurity fundamentals

## Features

- Reads Linux auth.log files
- Detects failed SSH login attempts
- Counts failed attempts per source IP
- Flags IPs at or above a configurable threshold
- Generates a readable Markdown report and machine-readable JSON
- Includes safe example log data and tests
- Uses only the Python standard library

## Project structure

linux-auth-log-analyser/
├── analyser.py
├── sample_logs/
│   └── auth.log
├── reports/
│   ├── security_report.md
│   └── security_report.json
├── screenshots/
│   ├── 01_terminal_demo.png
│   └── 02_report_preview.png
├── tests/
│   └── test_analyser.py
├── .gitignore
└── README.md

## Technologies used

- Python 3
- Linux authentication logs
- Regular expressions
- Git
- Github

## Run the analyser

Open a terminal in the project folder:

```bash
py analyser.py
```

Use a different log file:

```bash
py analyser.py /var/log/auth.log
```

Set a different alert threshold (for example, flag an IP after 3 failures):

```bash
py analyser.py --threshold 3
```

Choose a report output folder:

```bash
py analyser.py sample_logs/auth.log --threshold 5 --out reports
```

## Example output

=== LINUX AUTH LOG ANALYSER ===
Lines scanned       : 12
Failed logins       : 10
Unique source IPs   : 2
Flagged IPs         : 1
  [ALERT] 203.0.113.10 - 7 failed attempts


## Run tests

```bash
python -m unittest discover -s tests -v
```

## How detection works

1. The program reads the log one line at a time.
2. It looks for common SSH failure messages.
3. It extracts the attempted username and source IP.
4. It validates the IP address and counts attempts per IP.
5. It flags an IP when its count is greater than or equal to the threshold.
6. It writes `security_report.md` and `security_report.json` to the reports folder.

## Screenshots

See the `screenshots/` folder for a terminal demo and a report preview.

## Learning outcomes

- Python file handling
- Regular expressions
- Linux authentication logs
- SSH security monitoring
- IP address analysis
- Automated security reporting
- Git and GitHub version control

## Discalimer

This project is developed for educational purposes using synthetic sample logs. Flagged IP addresses require further investigation and should not automatically be considered malicious.


## Future improvements

- Add time-window detection (for example, 5 failures within 2 minutes)
- Support more Linux authentication formats
- Add CSV export
- Add allowlists for known internal IPs
- Add visual charts for failed attempts

## Author

Fatima Sheik
(https://github.com/fzahrasheik-bit)