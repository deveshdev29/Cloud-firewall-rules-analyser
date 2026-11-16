"""Module 5 - results table, summary, charts and CSV."""
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
from tabulate import tabulate
from .scoring import worst_per_rule

SEVERITIES = ["High", "Medium", "Low", "Invalid", "Safe"]
COLORS = {"High": "#d9534f", "Medium": "#f0ad4e", "Low": "#5bc0de",
          "Invalid": "#777777", "Safe": "#5cb85c"}


def print_report(report):
    table = report[["rule_id", "group", "port", "source", "severity", "finding", "recommendation"]]
    print(tabulate(table, headers=["Rule", "Group", "Port", "Source", "Severity", "Finding", "Recommendation"],
                   tablefmt="grid", showindex=False))


def print_compliance(report):
    issues = report[report["severity"] != "Safe"]
    print(tabulate(issues[["rule_id", "severity", "finding", "compliance_ref"]],
                   headers=["Rule", "Severity", "Finding", "Compliance reference"],
                   tablefmt="grid", showindex=False, maxcolwidths=[None, None, 28, 60]))


def print_summary(report):
    worst = worst_per_rule(report)
    n = {s: int((worst["severity"] == s).sum()) for s in SEVERITIES}
    risky = n["High"] + n["Medium"] + n["Low"]
    print(f"SUMMARY: {len(worst)} rules analyzed, {risky} risky "
          f"({n['High']} High, {n['Medium']} Medium, {n['Low']} Low), "
          f"{n['Invalid']} invalid, {n['Safe']} safe")


def make_charts(report, path="charts.png", show=False):
    fig, axes = plt.subplots(1, 2, figsize=(13, 4.5))

    # chart 1: every finding, by severity
    counts = report["severity"].value_counts().reindex(SEVERITIES, fill_value=0)
    axes[0].bar(counts.index, counts.values, color=[COLORS[s] for s in counts.index])
    axes[0].set_title("Findings by Severity")
    axes[0].set_ylabel("Number of findings")
    for i, v in enumerate(counts.values):
        axes[0].text(i, v + 0.05, str(v), ha="center")

    # chart 2: risky rules per group, each rule counted once by its worst finding
    worst = worst_per_rule(report)
    risky = worst[worst["severity"].isin(["High", "Medium", "Low"])]
    if risky.empty:
        axes[1].text(0.5, 0.5, "No risky rules", ha="center", va="center")
        axes[1].set_axis_off()
    else:
        per_group = (pd.crosstab(risky["group"], risky["severity"])
                     .reindex(columns=["High", "Medium", "Low"], fill_value=0))
        per_group.plot(kind="bar", stacked=True, ax=axes[1],
                       color=[COLORS[c] for c in per_group.columns])
        axes[1].set_title("Risky Rules per Security Group")
        axes[1].set_ylabel("Number of risky rules")
        axes[1].set_xlabel("")
        axes[1].tick_params(axis="x", rotation=0)

    for ax in axes:
        ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    if show:
        plt.show()
    plt.close(fig)


def save_csv(report, path="report.csv"):
    export = report[["rule_id", "group", "protocol", "port", "source", "severity",
                     "finding", "recommendation", "compliance_ref", "score"]]
    export.to_csv(path, index=False)
    return len(export)
