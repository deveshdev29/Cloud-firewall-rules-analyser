"""Cloud Firewall Rule Analyzer - main script.

Usage:
    python run_analysis.py                      (uses data/firewall_rules.json)
    python run_analysis.py my_rules.json        (your own rules file)
    python run_analysis.py --show               (also open the charts window)
"""
import argparse
import os
from tabulate import tabulate

from firewall_analyzer.loader import load_rules
from firewall_analyzer.analyzer import analyze_all
from firewall_analyzer.scoring import score_groups, environment_score
from firewall_analyzer.compliance import add_compliance
from firewall_analyzer import report as rpt

BASE = os.path.dirname(os.path.abspath(__file__))


def main():
    parser = argparse.ArgumentParser(description="Cloud Firewall Rule Analyzer")
    parser.add_argument("rules_file", nargs="?", default=os.path.join(BASE, "data", "firewall_rules.json"))
    parser.add_argument("--out", default=os.path.join(BASE, "output"), help="folder for report.csv and charts.png")
    parser.add_argument("--show", action="store_true", help="show the charts in a window")
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    # Module 1
    df = load_rules(args.rules_file)
    print(f"Loaded {len(df)} rules | valid: {df['valid'].sum()} | invalid: {(~df['valid']).sum()}\n")
    print(tabulate(df[["rule_id", "group", "protocol", "port", "source", "valid"]],
                   headers="keys", tablefmt="grid", showindex=False))

    # Modules 2, 3, 4
    report = add_compliance(analyze_all(df))
    groups = score_groups(report)

    # Module 5
    print("\nRESULTS")
    rpt.print_report(report)
    print()
    rpt.print_summary(report)

    print("\nRisk score per security group")
    print(tabulate(groups, headers=["Group", "Score", "Rating"], tablefmt="grid", showindex=False))
    print(f"\nOverall environment risk score: {environment_score(report)}")

    print("\nCompliance mapping")
    rpt.print_compliance(report)

    rows = rpt.save_csv(report, os.path.join(args.out, "report.csv"))
    rpt.make_charts(report, os.path.join(args.out, "charts.png"), show=args.show)
    print(f"\nSaved report.csv ({rows} rows) and charts.png in {args.out}")


if __name__ == "__main__":
    main()
