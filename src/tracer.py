import subprocess
import os
import ast
from typing import Dict, Any, List, Optional

class FunctionSignatureVisitor(ast.NodeVisitor):
    def __init__(self, file_content: str):
        self.file_content = file_content
        # Maps "Class.func" or "func" -> ast.FunctionDef node
        self.functions = {}
        self.current_class = None

    def visit_ClassDef(self, node: ast.ClassDef):
        old_class = self.current_class
        if self.current_class:
            self.current_class = f"{self.current_class}.{node.name}"
        else:
            self.current_class = node.name
            
        self.generic_visit(node)
        self.current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        full_name = node.name
        if self.current_class:
            full_name = f"{self.current_class}.{node.name}"
        self.functions[full_name] = node
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        full_name = node.name
        if self.current_class:
            full_name = f"{self.current_class}.{node.name}"
        self.functions[full_name] = node
        self.generic_visit(node)

class CodeImpactTracer:
    def __init__(self, workspace_root: str):
        self.root = os.path.abspath(workspace_root)

    def get_file_content_from_git(self, filepath: str) -> Optional[str]:
        """Retrieves the previous version of the file from Git index (HEAD)."""
        # Convert absolute path to relative to root for git command
        rel_path = os.path.relpath(filepath, self.root).replace("\\", "/")
        try:
            res = subprocess.run(
                ["git", "show", f"HEAD:{rel_path}"],
                cwd=self.root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="ignore"
            )
            if res.returncode == 0:
                return res.stdout
        except Exception:
            pass
        return None

    def parse_signatures(self, content: str) -> Dict[str, ast.arguments]:
        """Parses python content and extracts all function signatures."""
        try:
            tree = ast.parse(content)
            visitor = FunctionSignatureVisitor(content)
            visitor.visit(tree)
            return {name: node.args for name, node in visitor.functions.items()}
        except SyntaxError:
            return {}

    def get_module_path(self, filepath: str) -> str:
        """Converts file path to absolute module import namespace."""
        rel_path = os.path.relpath(filepath, self.root)
        base, _ = os.path.splitext(rel_path)
        parts = base.replace("\\", "/").split("/")
        
        # If 'src' is the first segment, strip it as standard python path mapping usually does
        if parts and parts[0] == "src":
            parts = parts[1:]
            
        return ".".join(parts)

    def get_candidate_module_namespaces(self, filepath: str) -> List[str]:
        """
        Returns all valid module import namespaces for a given file.
        Supports root-relative, source-root-relative (src/, tests/, lib/, app/),
        and direct module names for seamless cross-directory import resolution.
        """
        rel_path = os.path.relpath(filepath, self.root)
        base, _ = os.path.splitext(rel_path)
        parts = base.replace("\\", "/").split("/")
        
        candidates = set()
        # 1. Full relative to project root
        candidates.add(".".join(parts))
        
        # 2. Stripping standard source prefixes
        standard_prefixes = {"src", "tests", "test", "lib", "app", "packages"}
        if parts and parts[0] in standard_prefixes and len(parts) > 1:
            candidates.add(".".join(parts[1:]))
            
        # 3. Direct basename for sibling or sys.path imports
        candidates.add(parts[-1])
        return sorted(list(candidates))

    def parse_git_diff(self) -> List[Dict[str, Any]]:
        """
        Identifies changed python files in git, parses old and new signatures,
        and returns list of functions with modified parameters.
        """
        modified_funcs = []
        
        try:
            # Get list of staged/modified python files
            res = subprocess.run(
                ["git", "diff", "--name-only"],
                cwd=self.root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8"
            )
            files = res.stdout.strip().split("\n")
            
            # Also get staged changes
            res_cached = subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                cwd=self.root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8"
            )
            files.extend(res_cached.stdout.strip().split("\n"))
            
            # Filter unique python files that exist
            py_files = sorted(list(set([
                os.path.join(self.root, f) for f in files if f.endswith(".py")
            ])))
            
            for filepath in py_files:
                if not os.path.exists(filepath):
                    continue
                    
                # Read current file on disk
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    new_content = f.read()
                    
                # Read old version from Git
                old_content = self.get_file_content_from_git(filepath)
                if old_content is None:
                    # File is untracked/newly created. No previous signature to regress.
                    continue
                
                old_sigs = self.parse_signatures(old_content)
                new_sigs = self.parse_signatures(new_content)
                
                module_namespace = self.get_module_path(filepath)
                candidate_modules = self.get_candidate_module_namespaces(filepath)
                
                for name, new_arg_node in new_sigs.items():
                    if name in old_sigs:
                        old_arg_node = old_sigs[name]
                        if not self._are_signatures_equal(old_arg_node, new_arg_node):
                            modified_funcs.append({
                                "file": filepath,
                                "module": module_namespace,
                                "candidate_modules": candidate_modules,
                                "func_name": name,
                                "old_sig": old_arg_node,
                                "new_sig": new_arg_node
                            })
        except Exception as e:
            import sys
            sys.stderr.write(f"[*] Git diff parsing failed: {e}\n")
            
        return modified_funcs

    def _are_signatures_equal(self, sig1: ast.arguments, sig2: ast.arguments) -> bool:
        """Helper to compare if two ast.arguments signatures are structurally identical."""
        # 1. Compare positional arguments count
        if len(sig1.args) != len(sig2.args):
            return False
            
        # 2. Compare names
        for arg1, arg2 in zip(sig1.args, sig2.args):
            if arg1.arg != arg2.arg:
                return False
                
        # 3. Compare positional-only arguments (Python 3.8+)
        pos1 = getattr(sig1, "posonlyargs", [])
        pos2 = getattr(sig2, "posonlyargs", [])
        if len(pos1) != len(pos2):
            return False
        for p1, p2 in zip(pos1, pos2):
            if p1.arg != p2.arg:
                return False
                
        # 4. Compare keyword-only arguments
        if len(sig1.kwonlyargs) != len(sig2.kwonlyargs):
            return False
        for kw1, kw2 in zip(sig1.kwonlyargs, sig2.kwonlyargs):
            if kw1.arg != kw2.arg:
                return False
                
        # 5. Compare default parameters count (positional default count)
        if len(sig1.defaults) != len(sig2.defaults):
            return False
            
        # 6. Compare keyword default parameters count
        # Note: kw_defaults is a list of expressions, some elements can be None if no default
        kwd1 = [d for d in sig1.kw_defaults if d is not None] if sig1.kw_defaults else []
        kwd2 = [d for d in sig2.kw_defaults if d is not None] if sig2.kw_defaults else []
        if len(kwd1) != len(kwd2):
            return False
            
        # 7. Compare vararg (*args) and kwarg (**kwargs) status
        va1 = sig1.vararg.arg if sig1.vararg else None
        va2 = sig2.vararg.arg if sig2.vararg else None
        if va1 != va2:
            return False
            
        kw1 = sig1.kwarg.arg if sig1.kwarg else None
        kw2 = sig2.kwarg.arg if sig2.kwarg else None
        if kw1 != kw2:
            return False
            
        return True
