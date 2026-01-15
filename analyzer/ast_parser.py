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
        # New: Track Function Boundaries
        self.current_func_start = None
        self.current_func_end = None

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
        # 1. Capture Function Boundaries
        previous_function = self.current_function
        previous_start = self.current_func_start
        previous_end = self.current_func_end

        self.current_function = node.name
        self.current_func_start = node.lineno
        self.current_func_end = node.end_lineno

        # 1. Record the function definition itself (For Rule 4 - Auth Logic)
        self.signals.append({
            "type": "function_def",
            "name": node.name,
            "line": node.lineno,
            "function": self.current_function, # In case of nested functions
            "func_start": self.current_func_start, # Pass context
            "func_end": self.current_func_end      # Pass context
        })

        # 3. Visit children
        self.generic_visit(node)

        # 4. Context Tracking: Restore state when leaving the function
        self.current_function = previous_function
        self.current_func_start = previous_start
        self.current_func_end = previous_end

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
                "function": self.current_function,
                # ATTACH BOUNDARIES TO EVERY CALL
                "func_start": self.current_func_start,
                "func_end": self.current_func_end
            })

        # Continue looking inside arguments (e.g. print(input()))
        self.generic_visit(node)