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
                    # If it's just a Name Match (Heuristic) -> LOW/LOW
                    if signal["type"] == "function_def":
                        sev = "LOW"
                        conf = "LOW" 
                    # 2. Input Handling (Source) -> LOW Severity, MEDIUM Confidence
                    elif rule["risk_category"] == "Input Handling":
                        sev = "LOW"
                        conf = "MEDIUM"
                    # If it's a specific API Call -> MEDIUM/MEDIUM
                    else:
                        sev = "MEDIUM"
                        conf = "MEDIUM"

                    findings.append({
                        "id": rule["id"],
                        "risk": rule["risk_category"],
                        "trigger": signal["name"],
                        "line": signal["line"],
                        "function": signal.get("function", "Global Scope"),
                        "func_start": signal.get("func_start"), 
                        "func_end": signal.get("func_end"),
                        "reason": rule["reason"],
                        "checklist": rule["review_checklist"],
                        "severity": sev,
                        "confidence": conf,
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
            risks = {f["risk"] for f in func_findings}
            
            # Yahan check kar rahe hain ki kya 'func_findings' ek list hai
            # aur uske andar dictionaries hain.
            
            severity = "LOW"
            confidence = "LOW"
            is_combined = False
            title = ""
            reason = ""

            # Scenario A : Input + System + Auth (CRITICAL)
            if "Input Handling" in risks and "System Call" in risks and "Authentication Logic" in risks:
                severity = "CRITICAL"
                confidence = "HIGH"
                is_combined = True
                title = "CRITICAL RISK: Unsafe Auth & Command Execution"
                reason = "Heuristic analysis detected Authentication logic mixing Input with System Calls."
            
            # Scenario B : Input + System (HIGH)
            elif "Input Handling" in risks and "System Call" in risks:
                severity = "HIGH"
                confidence = "HIGH"
                is_combined = True
                title = "HIGH RISK: Potential Command Injection"
                reason = "Function accepts untrusted input and performs System Calls. If input is not sanitized, this leads to RCE."

            # Scenario C: Input + File (HIGH) -> Solves 'upload_file' case
            elif "Input Handling" in risks and "File Operation" in risks:
                severity = "MEDIUM"  # <--- CHANGED HERE
                confidence = "HIGH"  # Still HIGH because we have 2 signals
                is_combined = True
                title = "MEDIUM RISK: Potential Path Traversal"
                reason = "Function uses untrusted input to access the File System. This may allow unauthorized file creation or overwriting."

            # Use Combined Logic
            if is_combined:
                # Line Range Calculate karein
                lines = [f["line"] for f in func_findings]
                # Handle case where lines might be empty (rare but safe to check)
                line_range = f"{min(lines)} - {max(lines)}" if lines else "Unknown"

                extra_findings.append({
                    "id": "CRITICAL_COMBINED",
                    "risk": title,
                    "trigger": "Multiple Signals",
                    "line": line_range,
                    "function": func_name,
                    "func_start": func_start, # 👇 PASS FUNCTION START
                    "func_end": func_end,
                    "reason": f"Heuristic analysis detected multiple risk factors ({', '.join(risks)}) in the same function context.",
                    "evidence": [f["trigger"] for f in func_findings],
                    "checklist": [
                        "Review entire function flow",
                        "Ensure Input is sanitized before System Call",
                        "Verify Authentication logic is not bypassed"
                    ],
                    "severity": severity,       # 👈 Calculated
                    "confidence": confidence    # 👈 Calculated
                })

        return extra_findings