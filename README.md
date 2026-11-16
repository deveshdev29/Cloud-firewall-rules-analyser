# Cloud Firewall Rule Analyzer

Group number: 22
Members: DEVESH KUMAR (E23CSEU0350), SHITIZ CHATTERJEE (E23CSEU0950), KUMAR SHUBHAM (E23CSEU1510), ARSHIT ANAND (E23CSEU0649)


## About the project

Cloud systems such as AWS control access with firewall rules (Security Groups). One careless rule, for example "allow SSH from the whole internet", can let an attacker in. This project reads a list of firewall rules and:

1. loads and validates every rule (bad data is marked invalid, it does not crash the program)
2. runs the security checks (least privilege)
3. gives a risk score to each finding, each security group and the whole environment
4. links each finding to a standard (CIS AWS Foundations, PCI DSS, NIST SP 800-53)
5. writes a results table, a CSV report and two charts

The cloud is simulated. The rules are in `data/firewall_rules.json` and use the same fields as AWS, so no cloud account or API key is needed.

Pipeline: `firewall_rules.json` -> Load -> Validate -> Analyze -> Score -> Compliance map -> Report

## Folder contents

```
GroupNumber_n/
|-- README.md                  this file
|-- requirements.txt           python libraries needed
|-- run_analysis.py            main script (run this)
|-- firewall_analyzer/         the code, one file per module
|   |-- loader.py              Module 1  load and validate the rules
|   |-- analyzer.py            Module 2  security checks
|   |-- scoring.py             Module 3  risk scoring
|   |-- compliance.py          Module 4  compliance mapping
|   `-- report.py              Module 5  table, summary, charts, CSV
|-- tests/test_analyzer.py     Module 6  tests
|-- data/firewall_rules.json   sample rules (13 rules)
|-- output/                    report.csv and charts.png from our run
|-- notebook/                  Google Colab version (used in the demo video)
`-- docs/                      project explanation (PDF)
```

## How to run

There are two ways. Both give the same result.

### Option 1: Google Colab (as shown in the demo video)

1. Open https://colab.research.google.com and choose File -> Upload notebook.
2. Upload `notebook/Cloud_Firewall_Rule_Analyzer.ipynb`.
3. Click Runtime -> Run all.

Nothing else is needed. The notebook installs `tabulate`, creates `firewall_rules.json` itself, prints all tables, shows the charts, and downloads `report.csv` and `charts.png` to your computer. The last cell (Section 10) lets you upload your own rules file, set `USE_OWN_FILE = True` for that.

### Option 2: On your own computer

Python 3.8 or newer is needed.

```
pip install -r requirements.txt
python run_analysis.py
```

Run these commands from inside this folder. The tables are printed in the terminal, and `report.csv` and `charts.png` are saved in the `output/` folder.

Other ways to use the script:

```
python run_analysis.py my_rules.json     analyze your own rules file
python run_analysis.py --show            also open the charts in a window
python run_analysis.py --out results     save the output in another folder
```

### Run the tests

```
python -m unittest -v
```

This runs 14 tests: the security checks, the validation, and the sample data (total score 21 and the group scores). All of them should pass.

## What the security checks do

| # | Check | Condition | Severity |
|---|---|---|---|
| 1 | Allow-all rule | protocol = all and port = all | High |
| 2 | Risky port open to internet | source 0.0.0.0/0 (or ::/0) and port 22, 3389, 3306, 5432 or 1433 | High |
| 3 | Other port open to internet | source 0.0.0.0/0 (or ::/0) | Medium |
| 4 | Wide CIDR range | prefix /16 or bigger | Medium |
| 5 | Duplicate rule | same group, protocol, port and source | Low |
| 6 | Safe | none of the above | Safe |

Scores: High = 3, Medium = 2, Low = 1, Safe and Invalid = 0. A group score is the sum of its findings. Group rating: 6 or more is HIGH RISK, 3 or more is MEDIUM RISK, otherwise LOW RISK.

## Expected result with the sample data

If your run matches this, it is the same as in the demo video.

- `Loaded 13 rules | valid: 11 | invalid: 2` (rules 9 and 11 are invalid)
- `SUMMARY: 13 rules analyzed, 8 risky (4 High, 4 Medium, 0 Low), 2 invalid, 3 safe`
- Group scores: web-sg 10 (HIGH RISK), db-sg 5, app-sg 3, admin-sg 3 (all MEDIUM RISK)
- Overall environment risk score: 21
- `report.csv` has 14 rows (rule 8 has two findings: port open and duplicate)
- All tests pass

Note: the summary shows 0 Low but the first chart shows 1 Low. The summary counts each rule once by its worst finding (rule 8 counts as Medium). The chart counts every finding, so the duplicate of rule 8 shows as Low.

## Using your own rules file

The file must be a JSON list. Each rule needs these five fields:

```json
[
  {"rule_id": 1, "group": "web-sg", "protocol": "tcp", "port": "22", "source": "0.0.0.0/0"}
]
```

- `protocol`: tcp, udp, icmp or all
- `port`: 1 to 65535, or all
- `source`: a CIDR range such as 203.0.113.5/32

A rule with a wrong value is marked Invalid in the report. A rule with a missing field stops the program with a message telling which rule number is missing what.

## Limitations

- The data is simulated, not from a real AWS account.
- Only inbound rules are checked. Port ranges like 1000-2000 are not supported.
- The scoring weights (3, 2, 1) are our own simple choice.
- The tool cannot know the business reason for a rule. A public web server may be intended.
- The compliance mapping is simplified. Exact control numbers differ between versions of the standards.

Future work: read real rules with boto3, accept CSV files, and make an HTML or PDF report.

## Libraries used

Python standard library (`json`, `ipaddress`, `argparse`, `unittest`), `pandas`, `tabulate`, `matplotlib`.
