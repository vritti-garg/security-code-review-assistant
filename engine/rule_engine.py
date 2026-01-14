import json

class RuleEngine:
    def __init__(self, rules_path: str):
        with open(rules_path, "r") as f:
            self.rules = json.load(f)

    def apply_rules(self, signals):
        findings = []
        
        # --- PHASE 1: Standard Detection ---
        for signal in signals:
            for rule_id, rule in self.rules.items():
                triggers = rule.get("triggers", [])
                is_match = False

                # Logic 1: Exact Match for Calls (e.g., os.system)
                if signal["type"] == "call":
                    if signal["name"] in triggers:
                        is_match = True

                # Logic 2: Partial Match for Functions (e.g., login_user)
                elif signal["type"] == "function_def":
                    if any(trigger in signal["name"] for trigger in triggers):
                        is_match = True

                if is_match:
                    findings.append({
                        "id": rule["id"],
                        "risk": rule["risk_category"],
                        "trigger": signal["name"],
                        "line": signal["line"],
                        "function": signal.get("function", "Global Scope"),
                        "reason": rule["reason"],
                        "checklist": rule["review_checklist"]
                    })

        # --- PHASE 2: Heuristic Correlation (Combined Risk) ---
        combined_findings = self.detect_combined_risk(findings)
        findings.extend(combined_findings)
        
        return findings

    def detect_combined_risk(self, findings):
        """
        Groups findings by function and looks for dangerous combinations.
        Target: INPUT_HANDLING + SYSTEM_CALL inside same function.
        """
        function_map = {}
        extra_findings = []

        # 1. Findings ko Function ke naam se group karein
        for f in findings:
            func_name = f.get("function", "Global Scope")
            
            # Agar ye function pehli baar dikha hai, toh empty list banayein
            if func_name not in function_map:
                function_map[func_name] = []
            
            # IMP: List mein append kar rahe hain (Dictionary nahi assign kar rahe)
            function_map[func_name].append(f)

        # 2. Combinations check karein
        for func_name, func_findings in function_map.items():
            
            # Yahan check kar rahe hain ki kya 'func_findings' ek list hai
            # aur uske andar dictionaries hain.
            
            risks = set()
            for f in func_findings:
                risks.add(f["risk"]) # Yahan error aa raha tha, ab thik chalega

            # Agar ek hi function mein Input bhi hai aur System Call bhi...
            if "Input Handling" in risks and "System Call" in risks:
                
                # Line Range Calculate karein
                lines = [f["line"] for f in func_findings if f["risk"] in ["Input Handling", "System Call"]]
                
                # Handle case where lines might be empty (rare but safe to check)
                if lines:
                    line_range = f"{min(lines)} - {max(lines)}"
                else:
                    line_range = "Unknown"

                extra_findings.append({
                    "id": "CRITICAL_01",
                    "risk": "Combined Risk: Untrusted Input in System Command Execution",
                    "trigger": "Input + System Call",
                    "line": line_range,
                    "function": func_name,
                    "reason": "Untrusted input flowing into system commands can allow attackers to execute arbitrary OS-level commands.",
                    "evidence": [
                        "Input Handling detected",
                        "System Command execution detected"
                    ],
                    "checklist": [
                        "Trace how user input is constructed",
                        "Verify whether input reaches command execution",
                        "Check for validation or sanitization",
                        "Ensure shell execution is not used"
                    ]
                })
        
        return extra_findings