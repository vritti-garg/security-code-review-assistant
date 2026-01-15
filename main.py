import sys
import json
import argparse
from analyzer.ast_parser import ASTParser
from engine.rule_engine import RuleEngine

def group_findings_by_function(findings):
    """
    Groups individual findings into a dictionary keyed by function name.
    """
    grouped = {}
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    for f in findings:
        func_name = f['function']
        if func_name not in grouped:
            grouped[func_name] = {
                "findings": [],
                "max_severity": "LOW",
                "max_confidence": "LOW",
                # New: Store function boundaries
                "start": f.get("func_start"),
                "end": f.get("func_end")
            }
        
        grouped[func_name]["findings"].append(f)
        
        # Update Max Severity/Confidence for the function header
        current_max = grouped[func_name]["max_severity"]
        if severity_rank[f['severity']] < severity_rank[current_max]:
            grouped[func_name]["max_severity"] = f['severity']
            grouped[func_name]["max_confidence"] = f['confidence']

    # Sort functions by severity (Critical first)
    sorted_groups = sorted(
        grouped.items(),
        key=lambda item: severity_rank[item[1]["max_severity"]]
    )
    return sorted_groups

def print_cli_report(findings):
    if not findings:
        print("\n✅ Clean Code! No risks detected.")
        return
    
    grouped_data = group_findings_by_function(findings)

    print(f"\n{'='*60}")
    print(f"SECURITY CODE REVIEW REPORT")
    print(f"{'='*60}\n")

    for func_name, data in grouped_data:
        findings_list = data["findings"]
        
        # 1. GET FUNCTION RANGE
        if data["start"] and data["end"]:
            loc_str = f"Lines {data['start']}–{data['end']}"
        else:
            loc_str = "Global Scope / Unknown"

        # 2. Determine Main Finding (The one that sets the severity)
        # Priority: Combined Risk > Critical > High
        main_finding = findings_list[0]
        for f in findings_list:
            if "COMBINED" in f.get('id', '') or f['severity'] == "CRITICAL":
                main_finding = f
                break

        # 3. Collect Unique Risks (e.g., "Input Handling", "File Operation")
        # Exclude the abstract "Combined Risk" label from this list
        risks = sorted(list(set(f['risk'] for f in findings_list if "COMBINED" not in f.get('id', ''))))
        
        # 4. Collect Evidence (The raw triggers)
        # Exclude the combined finding itself, just show the signals
        evidence = [f for f in findings_list if "COMBINED" not in f.get('id', '')]
        evidence.sort(key=lambda x: x['line'])

        # --- PRINT REPORT ---
        print(f"Function: {func_name}")
        print(f"Location: {loc_str}")
        print(f"")
        print(f"Severity  : {data['max_severity']}")
        print(f"Confidence: {data['max_confidence']}")
        print(f"")

        print("Identified Risks:")
        for r in risks:
            print(f"  • {r}")
        print("")

        print("Insight:")
        print(f"  {main_finding['reason']}")
        print("")

        print("Evidence:")
        for ev in evidence:
            # Format: - Line 2 → input()      [Input Handling]
            print(f"  - Line {ev['line']} → {ev['trigger']}() \t [{ev['risk']}]")
        print("")

        print("Reviewer Checklist:")
        for item in main_finding['checklist']:
            print(f"  - [ ] {item}")

        print(f"\n{'-'*60}\n")

def export_json(findings, filename):
    """Exports findings to a JSON file."""
    try:
        with open(filename, "w") as f:
            json.dump(findings, f, indent=4)
        print(f"\n JSON Report saved to: {filename}")
    except Exception as e:
        print(f" Error saving JSON: {e}")

def export_markdown(findings, filename):
    """Exports findings to a Markdown file."""
    # Reuse your existing helper to structure the data
    grouped_data = group_findings_by_function(findings)
    
    try:
        with open(filename, "w") as f:
            f.write("#  Security Code Review Report\n\n")
            f.write(f"**Total Risky Functions Detected:** {len(grouped_data)}\n\n")
            f.write("---\n\n")

            for func_name, data in grouped_data:
                # Determine Icon
                icon = "⚪"
                if data["max_severity"] == "CRITICAL": icon = "🔴"
                elif data["max_severity"] == "HIGH": icon = "🟠"
                elif data["max_severity"] == "MEDIUM": icon = "🟡"
                elif data["max_severity"] == "LOW": icon = "🔵"
                
                # Determine Location
                if data["start"] and data["end"]:
                    loc_str = f"Lines {data['start']}–{data['end']}"
                else:
                    loc_str = "Global Scope"

                # Write Function Header
                f.write(f"## {icon} Function: `{func_name}`\n")
                f.write(f"**Location:** {loc_str}\n\n")
                f.write(f"| Severity | Confidence | Issues |\n")
                f.write(f"| :--- | :--- | :--- |\n")
                f.write(f"| **{data['max_severity']}** | {data['max_confidence']} | {len(data['findings'])} |\n\n")

                # Write Insight (Reason from the main finding)
                main_finding = data["findings"][0]
                for find in data["findings"]:
                    if "COMBINED" in find.get('id', '') or find['severity'] == "CRITICAL":
                        main_finding = find
                        break
                
                f.write(f"###  Insight\n")
                f.write(f"> {main_finding['reason']}\n\n")

                # Write Checklist
                f.write(f"###  Reviewer Checklist\n")
                for item in main_finding['checklist']:
                    f.write(f"- [ ] {item}\n")
                
                f.write("\n---\n\n")
        
        print(f"\n Markdown Report saved to: {filename}")

    except Exception as e:
        print(f" Error saving Markdown: {e}")

def main():
    parser = argparse.ArgumentParser(description="Python Static Analysis Security Tool")
    parser.add_argument("file", nargs="?", default="sample.py", help="Python file to analyze")
    parser.add_argument("--output", help="Export report to file (.json or .md)")
    
    args = parser.parse_args()
    target_file = "sample_code.py"
    try:
        with open(target_file, "r") as f:
            source_code = f.read()
    except FileNotFoundError:
        print(f"Error: '{target_file}' not found.")
        return

    parser = ASTParser(source_code)
    signals = parser.extract_signals()
    
    try:
        engine = RuleEngine("rules/rules.json")
        findings = engine.apply_rules(signals)
    except FileNotFoundError:
        print("Error: 'rules/rules.json' not found.")
        return
    # 4. Handle Output (The Logic Switch)
    if args.output:
        if args.output.endswith(".json"):
            export_json(findings, args.output)
        elif args.output.endswith(".md"):
            export_markdown(findings, args.output)
        else:
            print(" Error: Unsupported format. Please use .json or .md")
    else:
        # Default to CLI output if no flag is provided
        print_cli_report(findings)

if __name__ == "__main__":
    main()