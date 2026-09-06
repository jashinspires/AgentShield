import ast
import os
import sys
import json
from typing import Dict, List, Any, Optional

# Ensure sibling imports work regardless of CWD
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from tracer import CodeImpactTracer
from resolver import NamespaceResolver

class SignatureAuditor:
    def __init__(self):
        pass

    def check_caller_mismatch(self, caller_node: ast.Call, target_signature: ast.arguments) -> List[str]:
        """
        Compares arguments passed in a Call node against target_signature.
        Correctly accounts for bound method invocations (self/cls implicit first argument).
        Returns a list of warnings if mismatch is found.
        """
        warnings = []
        
        # Extract target signature lists
        sig_pos_only = [a.arg for a in getattr(target_signature, "posonlyargs", [])]
        sig_args = [a.arg for a in target_signature.args]
        sig_pos_total = sig_pos_only + sig_args
        
        sig_kw_only = [a.arg for a in target_signature.kwonlyargs]
        
        # Defaults
        defaults = target_signature.defaults or []
        num_pos_defaults = len(defaults)
        
        kw_defaults = target_signature.kw_defaults or []
        
        # Caller arguments
        passed_pos = len(caller_node.args)
        passed_kw = {kw.arg: kw.value for kw in caller_node.keywords if kw.arg is not None}
        
        has_starred_pos = any(isinstance(arg, ast.Starred) for arg in caller_node.args)
        has_double_star_kw = any(kw.arg is None for kw in caller_node.keywords)
        
        # Check if call is a bound method invocation (e.g. obj.method() or self.method())
        is_bound_method = False
        if sig_pos_total and sig_pos_total[0] in ("self", "cls"):
            if isinstance(caller_node.func, ast.Attribute):
                is_bound_method = True

        pos_offset = 1 if is_bound_method else 0
        expected_pos_max = len(sig_pos_total) - pos_offset

        # 1. Match positional arguments
        provided_indices = set()
        if is_bound_method:
            provided_indices.add(0)  # self/cls is implicitly passed by runtime
        
        if passed_pos > expected_pos_max:
            if not target_signature.vararg and not has_starred_pos:
                warnings.append(f"Too many positional arguments: passed {passed_pos}, expected at most {expected_pos_max}")
            for i in range(pos_offset, len(sig_pos_total)):
                provided_indices.add(i)
        else:
            for i in range(passed_pos):
                provided_indices.add(i + pos_offset)

        # 2. Match keyword arguments
        for kw_name in passed_kw:
            # Check if positional-only
            if kw_name in sig_pos_only:
                warnings.append(f"Parameter '{kw_name}' is positional-only and cannot be passed as a keyword argument")
            elif kw_name in sig_args:
                idx = sig_pos_only.index(kw_name) if kw_name in sig_pos_only else (len(sig_pos_only) + sig_args.index(kw_name))
                if idx in provided_indices and idx != (0 if is_bound_method else -1):
                    warnings.append(f"Parameter '{kw_name}' received multiple values (both positional and keyword)")
                provided_indices.add(idx)
            elif kw_name in sig_kw_only:
                pass # Keyword only arguments are valid keyword arguments
            else:
                # Unknown keyword argument
                if not target_signature.kwarg and not has_double_star_kw:
                    warnings.append(f"Unknown keyword argument '{kw_name}'")

        # 3. Check for missing required positional arguments
        # Defaults cover the end of sig_pos_total
        first_default_idx = len(sig_pos_total) - num_pos_defaults
        for idx, param_name in enumerate(sig_pos_total):
            if idx == 0 and is_bound_method:
                continue
                
            if idx not in provided_indices:
                if idx < first_default_idx and not has_starred_pos and not has_double_star_kw:
                    warnings.append(f"Missing required positional argument '{param_name}'")

        # 4. Check for missing required keyword-only arguments
        for idx, param_name in enumerate(sig_kw_only):
            if param_name not in passed_kw:
                # kw_defaults corresponds element-by-element with kwonlyargs
                default_val = kw_defaults[idx] if idx < len(kw_defaults) else None
                if default_val is None and not has_double_star_kw:
                    warnings.append(f"Missing required keyword-only argument '{param_name}'")

        return warnings


class CodebaseAuditor:
    def __init__(self, workspace_root: str):
        self.root = os.path.abspath(workspace_root)
        self.tracer = CodeImpactTracer(self.root)
        self.auditor = SignatureAuditor()

    def find_all_py_files(self) -> List[str]:
        """Recursively finds all python files in the workspace (excluding virtual environments and agent/IDE data)."""
        py_files = []
        exclude_dirs = {
            ".git", ".venv", "venv", "env", "node_modules", "__pycache__", "build", "dist",
            ".agent", ".agents", ".obsidian", ".idea", ".vscode"
        }
        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for file in files:
                if file.endswith(".py"):
                    py_files.append(os.path.join(root, file))
        return py_files

    def audit_workspace(self) -> List[Dict[str, Any]]:
        """
        Scans git diff for signature modifications, audits the entire codebase calling sites,
        and returns list of regression warnings.
        """
        # Find modified functions
        modified_funcs = self.tracer.parse_git_diff()
        if not modified_funcs:
            return []

        # Create mapping of "absolute_namespace" -> new_sig_node
        # Supports primary namespace, candidate module namespaces, and bare function names
        modified_map = {}
        for item in modified_funcs:
            abs_ns = f"{item['module']}.{item['func_name']}"
            modified_map[abs_ns] = item["new_sig"]
            for cand in item.get("candidate_modules", []):
                modified_map[f"{cand}.{item['func_name']}"] = item["new_sig"]
            modified_map[item["func_name"]] = item["new_sig"]

        warnings_found = []
        py_files = self.find_all_py_files()

        for filepath in py_files:
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    
                tree = ast.parse(content)
                module_ns = self.tracer.get_module_path(filepath)
                resolver = NamespaceResolver(filepath, module_ns, root=self.root)
                
                # Build imports map first
                resolver.visit(tree)
                
                # Now audit all Call nodes
                class CallAuditorVisitor(ast.NodeVisitor):
                    def __init__(self, auditor_ref):
                        self.auditor_ref = auditor_ref
                        
                    def visit_Call(self, node: ast.Call):
                        resolved_ns = resolver.resolve_call_namespace(node.func)
                        if resolved_ns and resolved_ns in modified_map:
                            target_sig = modified_map[resolved_ns]
                            mismatches = self.auditor_ref.auditor.check_caller_mismatch(node, target_sig)
                            if mismatches:
                                warnings_found.append({
                                    "file": filepath,
                                    "line": node.lineno,
                                    "col": node.col_offset,
                                    "target_function": resolved_ns,
                                    "mismatches": mismatches
                                })
                        self.generic_visit(node)
                        
                visitor = CallAuditorVisitor(self)
                visitor.visit(tree)
                
            except Exception as e:
                # Parse error in some codebase file, skip it
                pass
                
        return warnings_found

def main():
    workspace = os.getcwd()
    auditor = CodebaseAuditor(workspace)
    warnings = auditor.audit_workspace()
    
    if warnings:
        # Format warning alerts as structured JSON to stderr
        sys.stderr.write("[!] AgentShield AST Code Auditor detected regressions:\n")
        sys.stderr.write(json.dumps(warnings, indent=2) + "\n")
        sys.exit(1)
    else:
        print("[+] AgentShield AST Code Auditor: No regressions detected.")
        sys.exit(0)

if __name__ == "__main__":
    main()
