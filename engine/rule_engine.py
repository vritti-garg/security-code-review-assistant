"""
Rule Engine

Responsible for:
- Loading security rules
- Matching AST signals to rules
- Producing structured security findings

No AST parsing happens here.
"""

import json


class RuleEngine:
    def __init__(self, rules_path: str):
        with open(rules_path, "r") as f:
            self.rules = json.load(f)

    def apply_rules(self, signals):
        findings = []

        for signal in signals:
            if signal["type"] != "call":
                continue

            for rule_id, rule in self.rules.items():
                if signal["name"] in rule.get("apis", []):
                    findings.append({
                        "risk": rule["risk_category"],
                        "reason": rule["reason"],
                        "line": signal["line"],
                        "review_checklist": rule["review_checklist"]
                    })

        return findings

