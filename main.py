from analyzer.ast_parser import ASTParser
from engine.rule_engine import RuleEngine

def print_report(findings):
    if not findings:
        print("\n Clean Code! No risks detected.")
        return

    # Sort: Critical issues first
    findings.sort(key=lambda x: "Combined" in x['risk'], reverse=True)
    
    # Count criticals
    critical_count = sum(1 for f in findings if "Combined" in f['risk'])

    print(f"\n{'='*60}")
    print(f"SECURITY REVIEW REPORT — {len(findings)} Issues Detected")
    if critical_count > 0:
        print(f"{critical_count} CRITICAL ISSUES FOUND")
    print(f"{'='*60}\n")

    for f in findings:
        # Check if it is a Critical Combined Risk
        is_critical = "Combined" in f['risk']
        
        if is_critical:
            print(f"🔴 [CRITICAL] {f['risk']}")
            print(f"\nLocation:")
            print(f"  Function: {f['function']}")
            print(f"  Lines:    {f['line']}") # Shows range now
            
            print(f"\nWhy this matters:")
            # Wrap text nicely
            print(f"  {f['reason']}")
            
            print(f"\nTrigger Evidence:")
            # Use the new evidence list we created in rule_engine
            for ev in f.get('evidence', ["Risk detected"]):
                print(f"  - {ev}")

        else:
            # Standard output for normal warnings
            print(f"  [WARNING] {f['risk']}")
            print(f"  Function: {f['function']} (Line {f['line']})")
            print(f"  Reason:   {f['reason']}")

        # Checklist for both
        print(f"\nReviewer Checklist:")
        for item in f['checklist']:
            print(f"  - [ ] {item}")
            
        print("\n" + "-" * 60 + "\n")


def main():
    # Read sample demo file 
    try:
        with open("sample.py", "r") as f:
            source_code = f.read()
    except FileNotFoundError:
        print("Error: 'sample.py' not found.")
        return

    parser = ASTParser(source_code)
    signals = parser.extract_signals()
    
    engine = RuleEngine("rules/rules.json")
    findings = engine.apply_rules(signals)

    print_report(findings)

if __name__ == "__main__":
    main()