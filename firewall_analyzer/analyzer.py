"""Module 2 - the security checks (least privilege)."""
import ipaddress
import pandas as pd
from .scoring import SEVERITY_SCORE, SEVERITY_ORDER

RISKY_PORTS = {"22": "SSH", "3389": "RDP", "3306": "MySQL",
               "5432": "PostgreSQL", "1433": "SQL Server"}
ADMIN_PORTS = {"22", "3389"}


def make_finding(severity, finding, recommendation, compliance):
    return {"severity": severity, "finding": finding,
            "recommendation": recommendation, "compliance": compliance}


def is_open_to_world(source):
    """A /0 prefix means every address (0.0.0.0/0 and ::/0)."""
    return ipaddress.ip_network(source, strict=False).prefixlen == 0


def analyze_rule(rule):
    """Checks 1-4 on one valid rule. Returns a list of findings."""
    findings = []

    # check 1: allow-all
    if rule["protocol"] == "all" and rule["port"] == "all":
        findings.append(make_finding("High", "Allow-all rule",
                                     "Restrict to required protocols and ports", "allow_all"))

    if is_open_to_world(rule["source"]):
        # check 2: risky port open to the internet
        if rule["port"] in RISKY_PORTS:
            kind = "admin" if rule["port"] in ADMIN_PORTS else "database"
            findings.append(make_finding("High", f"{RISKY_PORTS[rule['port']]} open to the internet",
                                         "Limit source to a trusted IP or VPN", kind))
        # check 3: any other port open to the internet
        elif rule["port"] != "all":
            findings.append(make_finding("Medium", "Port open to the internet",
                                         "Confirm this port needs public access", "public_port"))
    # check 4: wide CIDR range (open to world is already handled above)
    elif ipaddress.ip_network(rule["source"], strict=False).prefixlen <= 16:
        findings.append(make_finding("Medium", "Wide CIDR range",
                                     "Narrow the source range to specific subnets", "wide_cidr"))
    return findings


def find_duplicates(rule_df):
    """Check 5: ids of rules that repeat an earlier rule."""
    seen, duplicates = set(), set()
    for r in rule_df.to_dict("records"):
        key = (r["group"], r["protocol"], r["port"], r["source"])
        if key in seen:
            duplicates.add(r["rule_id"])
        else:
            seen.add(key)
    return duplicates


def analyze_all(rule_df):
    """Analyze every rule. Returns one report row per finding."""
    duplicates = find_duplicates(rule_df[rule_df["valid"]])
    rows = []
    for r in rule_df.to_dict("records"):
        if not r["valid"]:
            findings = [make_finding("Invalid", "; ".join(r["errors"]), "Fix the rule data", "invalid")]
        else:
            findings = analyze_rule(r)
            if r["rule_id"] in duplicates:
                findings.append(make_finding("Low", "Duplicate rule", "Remove the repeated rule", "duplicate"))
            if not findings:
                findings = [make_finding("Safe", "No issue found", "None", "safe")]
        for f in findings:
            rows.append({"rule_id": r["rule_id"], "group": r["group"], "protocol": r["protocol"],
                         "port": r["port"], "source": r["source"], **f,
                         "score": SEVERITY_SCORE[f["severity"]]})
    report = pd.DataFrame(rows)
    report["_order"] = report["severity"].map(SEVERITY_ORDER)
    return report.sort_values(["_order", "rule_id"]).drop(columns="_order").reset_index(drop=True)
