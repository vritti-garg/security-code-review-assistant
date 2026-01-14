from analyzer.ast_parser import ASTParser
from engine.rule_engine import RuleEngine
import json

def main():
    print("Starting Security Scan...\n")
    # Read sample demo file 
    try:
        with open("sample.py", "r") as f:
            source_code = f.read()
    except FileNotFoundError:
        print("🔴Error: 'sample.py' file nahi mili!")
        return

    parser = ASTParser(source_code)
    signals = parser.extract_signals()
    print(f"Found {len(signals)} AST signals.")
    
    engine = RuleEngine("rules/rules.json")
    findings = engine.apply_rules(signals)

    if findings:
        print(f"\n Found {len(findings)} Security Issues:\n")
        for i, f in enumerate(findings, 1):
            print(f"[{i}] Rule ID: {f['id']} | Risk: {f['risk']}")
            print(f"    Line: {f['line']} | Trigger: {f['trigger_found']}")
            print(f"    Reason: {f['reason']}")
            print("-" * 30)
    else:
        print("\n No issues found!")


if __name__ == "__main__":
    main()





