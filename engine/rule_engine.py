import json

class RuleEngine:
    def __init__(self, rules_path: str):
        with open(rules_path, "r") as f:
            self.rules = json.load(f)

    def apply_rules(self, signals):
        findings = []

        for signal in signals:
            
            for rule_id, rule in self.rules.items():
                triggers = rule.get("triggers", [])
                is_match = False

                # LOGIC 1: Exact Match for Calls (e.g., os.system)
                if signal["type"] == "call":
                    if signal["name"] in triggers: 
                        is_match = True

                # LOGIC 2: Partial Match for Functions (e.g., login_user contains 'login')
                elif signal["type"] == "function_def":
                    # Check agar koi bhi trigger keyword function name ke andar hai
                    if any(trigger in signal["name"] for trigger in triggers):
                        is_match = True

                if is_match:
                    findings.append({
                        "id": rule["id"],
                        "risk": rule["risk_category"],
                        "trigger_found": signal["name"], # Debugging ke liye help karega
                        "reason": rule["reason"],
                        "line": signal["line"], # Where is it?
                        "review_checklist": rule["review_checklist"]
                    })

        return findings