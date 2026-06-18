import ast
import os
from typing import Dict, Optional

class NamespaceResolver(ast.NodeVisitor):
    def __init__(self, file_path: str, module_namespace: str):
        self.file_path = file_path
        self.module_namespace = module_namespace
        # Maps local aliases / names -> absolute import namespaces
        # e.g., {"db_conn": "database.connections.db_conn", "utils": "core.utils"}
        self.imports = {}

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            # e.g., import os -> self.imports["os"] = "os"
            # e.g., import my_pkg.utils as mu -> self.imports["mu"] = "my_pkg.utils"
            self.imports[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        
        # Resolve relative import level
        if node.level > 0:
            # Relative import (e.g. from . import x, from ..y import z)
            parts = self.module_namespace.split(".")
            # Strip level number of elements from the end
            # level=1 means same folder, so strip the module filename itself
            strip_count = node.level
            if len(parts) >= strip_count:
                base_parts = parts[:-strip_count]
            else:
                base_parts = []
                
            if module:
                base_parts.append(module)
            base_module = ".".join(base_parts)
        else:
            # Absolute import (e.g. from my_pkg import utils)
            base_module = module

        for alias in node.names:
            resolved_path = f"{base_module}.{alias.name}" if base_module else alias.name
            self.imports[alias.asname or alias.name] = resolved_path
            
        self.generic_visit(node)
        
    def resolve_call_namespace(self, func_node: ast.expr) -> Optional[str]:
        """
        Attempts to resolve a Call's function node to an absolute namespace.
        Supports:
          - Direct call: process_data() -> resolved if 'process_data' in imports
          - Attribute call: utils.process_data() -> resolved if 'utils' in imports
          - Nested attributes: package.utils.func()
        """
        if isinstance(func_node, ast.Name):
            # Direct name call, check if it was imported
            name = func_node.id
            if name in self.imports:
                return self.imports[name]
            # If not in imports, it might be a function defined in the current file
            return f"{self.module_namespace}.{name}"
            
        elif isinstance(func_node, ast.Attribute):
            # Attribute call (e.g., mu.process_data)
            # Reconstruct the attribute access string
            parts = []
            curr = func_node
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
                
            if isinstance(curr, ast.Name):
                parts.append(curr.id)
                parts.reverse() # now we have e.g., ["mu", "process_data"]
                
                base_name = parts[0]
                if base_name in self.imports:
                    # Replace base alias with absolute path
                    resolved_base = self.imports[base_name]
                    remaining = parts[1:]
                    return ".".join([resolved_base] + remaining)
                else:
                    # Fallback to reconstructing full path from current namespace
                    return ".".join([self.module_namespace] + parts)
                    
        return None
