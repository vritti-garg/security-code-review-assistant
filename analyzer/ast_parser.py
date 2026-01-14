"""
AST Parser Module

Responsible for:
- Parsing Python source code
- Extracting raw AST signals (functions, calls)
- Tracking CONTEXT (which function a call belongs to)
- Producing data for the rule engine

This module does NOT apply security logic.
"""

import ast

class ASTParser(ast.NodeVisitor):
    def __init__(self, source_code: str):
        self.tree = ast.parse(source_code)
        self.signals = []
        # State variable to track where we are currently looking
        self.current_function = "Global Scope" 

    def extract_signals(self):
        """
        Walks the AST and extracts raw signals with context.
        Returns a list of dictionaries.
        """
        self.signals = [] # Reset list
        self.visit(self.tree) # Start the recursive visit
        return self.signals

    def visit_FunctionDef(self, node):
        """
        Runs when the parser sees a function definition (def name():).
        """
        # 1. Record the function definition itself (For Rule 4 - Auth Logic)
        self.signals.append({
            "type": "function_def",
            "name": node.name,
            "line": node.lineno,
            "function": self.current_function # In case of nested functions
        })

        # 2. Context Tracking: Update state to current function name
        previous_function = self.current_function
        self.current_function = node.name

        # 3. Continue looking inside this function
        self.generic_visit(node)

        # 4. Context Tracking: Restore state when leaving the function
        self.current_function = previous_function

    def visit_Call(self, node):
        """
        Runs when the parser sees a function call (print(), os.system()).
        """
        func_name = None

        # Case A: Simple call -> print()
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        
        # Case B: Attribute call -> os.system()
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name:
            self.signals.append({
                "type": "call",
                "name": func_name, 
                "line": node.lineno,
                # THE UPGRADE: Attaching the context
                "function": self.current_function 
            })

        # Continue looking inside arguments (e.g. print(input()))
        self.generic_visit(node)