"""Module 3 - risk scoring."""

SEVERITY_SCORE = {"High": 3, "Medium": 2, "Low": 1, "Safe": 0, "Invalid": 0}
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Invalid": 3, "Safe": 4}


def rate(score):
    if score >= 6:
        return "HIGH RISK"
    if score >= 3:
        return "MEDIUM RISK"
    return "LOW RISK"


def score_groups(report):
    """Sum the finding scores of each security group."""
    groups = report.groupby("group")["score"].sum().reset_index(name="risk_score")
    groups["rating"] = groups["risk_score"].apply(rate)
    return groups.sort_values("risk_score", ascending=False).reset_index(drop=True)


def environment_score(report):
    return int(report["score"].sum())


def worst_per_rule(report):
    """One row per rule, keeping its most severe finding."""
    tmp = report.assign(_o=report["severity"].map(SEVERITY_ORDER)).sort_values(["rule_id", "_o"])
    return tmp.drop_duplicates("rule_id").drop(columns="_o")
