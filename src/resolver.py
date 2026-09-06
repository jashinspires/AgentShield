import ast
import os
from typing import Dict, Optional, List


def extract_exported_symbols_from_ast(filepath: str) -> List[str]:
    """
    Parses a python file and extracts all exported symbols:
    1. If __all__ is explicitly defined, parses string elements from __all__.
    2. Otherwise, collects all top-level public functions, classes, and assigned variables (not starting with '_').
    """
    if not os.path.exists(filepath):
        return []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            tree = ast.parse(f.read())
    except Exception:
        return []

    # Check for explicit __all__ definition
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                        symbols = []
                        for el in node.value.elts:
                            if isinstance(el, ast.Constant) and isinstance(el.value, str):
                                symbols.append(el.value)
                        return symbols

    # Fallback: extract public functions, classes, and assigned variables
    symbols = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if not node.name.startswith("_"):
                symbols.append(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and not target.id.startswith("_"):
                    symbols.append(target.id)
    return symbols


def locate_module_file(module_name: str, current_file: str, root: Optional[str] = None) -> Optional[str]:
    """
    Attempts to locate the .py file on disk for a given module import name.
    Checks relative to current file's directory, workspace root, and common source dirs.
    """
    search_dirs = []
    current_dir = os.path.dirname(os.path.abspath(current_file))
    search_dirs.append(current_dir)

    if root:
        abs_root = os.path.abspath(root)
        search_dirs.append(abs_root)
        for sub in ("src", "lib", "app", "tests"):
            sub_dir = os.path.join(abs_root, sub)
            if os.path.isdir(sub_dir):
                search_dirs.append(sub_dir)

    module_rel_path = module_name.replace(".", os.sep)
    for base in search_dirs:
        # Check direct module file: module.py
        candidate_file = os.path.join(base, f"{module_rel_path}.py")
        if os.path.isfile(candidate_file):
            return candidate_file

        # Check package init: module/__init__.py
        candidate_pkg = os.path.join(base, module_rel_path, "__init__.py")
        if os.path.isfile(candidate_pkg):
            return candidate_pkg

    return None


class NamespaceResolver(ast.NodeVisitor):
    def __init__(self, file_path: str, module_namespace: str, root: Optional[str] = None):
        self.file_path = file_path
        self.module_namespace = module_namespace
        self.root = root
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
            if alias.name == "*":
                # Wildcard star import: resolve symbols from target module AST
                target_file = locate_module_file(base_module, self.file_path, self.root)
                if target_file:
                    symbols = extract_exported_symbols_from_ast(target_file)
                    for sym in symbols:
                        self.imports[sym] = f"{base_module}.{sym}" if base_module else sym
            else:
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
                parts.reverse()  # now we have e.g., ["mu", "process_data"]

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
