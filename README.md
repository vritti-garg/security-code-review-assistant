# security-code-review-assistant
AST-based assistive security tool that flags **security-sensitive code paths** and provides **review guidance** for manual code reviews.

## 🚨 Important
This tool does **NOT** detect or confirm vulnerabilities.

It flags **security-relevant code regions** that require **human review**.

## 🎯 Purpose
Many security issues arise from subtle logic mistakes in:
- Authentication
- Input handling
- Database access
- File operations
- System command execution

This tool highlights such areas and explains **what to review and why**.

## 🧠 How It Works
1. Parses Python source code using the Abstract Syntax Tree (AST)
2. Extracts functions, imports, and function calls
3. Applies rule-based security interpretation
4. Generates structured review findings

## ❌ What It Does NOT Do
- No exploit detection
- No vulnerability claims
- No runtime analysis
- No CVE matching

## 🚀 Status
Project under active development.
