"""
AST Parser Module

Responsible for:
- Parsing Python source code
- Extracting raw AST signals (functions, calls)
- Producing data for the rule engine

This module does NOT apply security logic.
"""

import ast


class ASTParser:
    def __init__(self, source_code: str):
        self.tree = ast.parse(source_code)

    def extract_signals(self):
        """
        Walks the AST and extracts raw signals.
        Returns a list of dictionaries.
        """
        signals = [] #save raw data

        for node in ast.walk(self.tree):

            # Function definitions
            if isinstance(node, ast.FunctionDef):
                signals.append({ 
                    "type": "function_def",
                    "name": node.name,
                    "line": node.lineno
                })

            # Function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    signals.append({ 
                        "type": "call",
                        "name": node.func.id, 
                        "line": node.lineno
                    })

                elif isinstance(node.func, ast.Attribute):
                    signals.append({
                        "type": "call",
                        "name": node.func.attr,
                        "line": node.lineno
                    })

        return signals #send signal 

