from analyzer.ast_parser import ASTParser
from engine.rule_engine import RuleEngine


def main():
    # Temporary demo file (you can replace later)
    with open("sample.py", "r") as f:
        source_code = f.read()

    parser = ASTParser(source_code)
    signals = parser.extract_signals()

    engine = RuleEngine("rules/rules.json")
    findings = engine.apply_rules(signals)

    for finding in findings:
        print(finding)


if __name__ == "__main__":
    main()

