"""Module 4 - link each finding to a security standard.

This is a simple mapping for learning. Exact control numbers differ
between versions of the standards.
"""

COMPLIANCE_MAP = {
    "admin":       "CIS AWS Foundations (no SG ingress from 0.0.0.0/0 to remote admin ports); NIST SP 800-53 SC-7",
    "database":    "PCI DSS Req. 1 (restrict access to data systems); NIST SP 800-53 SC-7",
    "allow_all":   "PCI DSS Req. 1 (allow only necessary traffic); NIST SP 800-53 SC-7",
    "public_port": "NIST SP 800-53 SC-7 (boundary protection); least privilege",
    "wide_cidr":   "Least privilege; PCI DSS Req. 1",
    "duplicate":   "Configuration hygiene / change management",
    "invalid":     "Input validation / data integrity",
    "safe":        "Compliant with least privilege",
}


def add_compliance(report):
    report["compliance_ref"] = report["compliance"].map(COMPLIANCE_MAP)
    return report
