"""Module 1 - load the rules file and validate every rule."""
import json
import ipaddress
import pandas as pd

VALID_PROTOCOLS = {"tcp", "udp", "icmp", "all"}
REQUIRED_FIELDS = ["rule_id", "group", "protocol", "port", "source"]


def is_valid_cidr(cidr):
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_valid_port(port):
    if port == "all":
        return True
    return str(port).isdigit() and 1 <= int(port) <= 65535


def validate_rule(rule):
    """Return a list of error messages. Empty list means the rule is valid."""
    errors = []
    if not is_valid_cidr(rule["source"]):
        errors.append(f"Invalid CIDR {rule['source']}")
    if not is_valid_port(rule["port"]):
        errors.append(f"Invalid port {rule['port']}")
    if rule["protocol"] not in VALID_PROTOCOLS:
        errors.append(f"Invalid protocol {rule['protocol']}")
    return errors


def build_dataframe(rule_list):
    df = pd.DataFrame(rule_list)
    df["port"] = df["port"].astype(str).str.lower()
    df["protocol"] = df["protocol"].astype(str).str.lower()
    df["errors"] = [validate_rule(r) for r in df.to_dict("records")]
    df["valid"] = df["errors"].apply(len) == 0
    return df


def load_rules(path):
    with open(path) as f:
        rule_list = json.load(f)
    for i, rule in enumerate(rule_list, start=1):
        missing = [k for k in REQUIRED_FIELDS if k not in rule]
        if missing:
            raise ValueError(f"Rule number {i} is missing: {', '.join(missing)}")
    return build_dataframe(rule_list)
