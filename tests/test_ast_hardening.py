import unittest
import os
import sys
import tempfile
import shutil
import ast

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from resolver import NamespaceResolver, extract_exported_symbols_from_ast
from tracer import CodeImpactTracer
from auditor import SignatureAuditor

class TestASTHardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.auditor = SignatureAuditor()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def parse_expr(self, code: str) -> ast.Call:
        tree = ast.parse(code)
        expr = tree.body[0]
        if isinstance(expr, ast.Expr) and isinstance(expr.value, ast.Call):
            return expr.value
        raise ValueError("Must be Call expr")

    def parse_sig(self, sig_code: str) -> ast.arguments:
        tree = ast.parse(sig_code)
        func = tree.body[0]
        return func.args

    def test_star_import_with_dunder_all(self):
        mod_content = """
__all__ = ["calculate_tax", "TaxReport"]

def calculate_tax(amount, rate):
    return amount * rate

def internal_calc():
    pass

class TaxReport:
    pass
"""
        mod_file = os.path.join(self.temp_dir, "finance.py")
        with open(mod_file, "w", encoding="utf-8") as f:
            f.write(mod_content)

        caller_content = """
from finance import *
print(calculate_tax(100, 0.18))
"""
        caller_file = os.path.join(self.temp_dir, "caller.py")
        with open(caller_file, "w", encoding="utf-8") as f:
            f.write(caller_content)

        tree = ast.parse(caller_content)
        resolver = NamespaceResolver(caller_file, "caller", self.temp_dir)
        resolver.visit(tree)

        self.assertEqual(resolver.imports.get("calculate_tax"), "finance.calculate_tax")
        self.assertEqual(resolver.imports.get("TaxReport"), "finance.TaxReport")
        self.assertNotIn("internal_calc", resolver.imports)

        # Verify call resolution
        call_node = tree.body[1].value.args[0]
        resolved = resolver.resolve_call_namespace(call_node.func)
        self.assertEqual(resolved, "finance.calculate_tax")

    def test_star_import_without_dunder_all(self):
        mod_content = """
def public_fn(a, b):
    pass

def _private_fn():
    pass

class PublicClass:
    pass
"""
        mod_file = os.path.join(self.temp_dir, "utils.py")
        with open(mod_file, "w", encoding="utf-8") as f:
            f.write(mod_content)

        caller_file = os.path.join(self.temp_dir, "main.py")
        tree = ast.parse("from utils import *")
        resolver = NamespaceResolver(caller_file, "main", self.temp_dir)
        resolver.visit(tree)

        self.assertEqual(resolver.imports.get("public_fn"), "utils.public_fn")
        self.assertEqual(resolver.imports.get("PublicClass"), "utils.PublicClass")
        self.assertNotIn("_private_fn", resolver.imports)

    def test_candidate_module_namespaces(self):
        tracer = CodeImpactTracer(self.temp_dir)

        # File in tests/
        test_file = os.path.join(self.temp_dir, "tests", "dummy_math.py")
        cands = tracer.get_candidate_module_namespaces(test_file)
        self.assertIn("tests.dummy_math", cands)
        self.assertIn("dummy_math", cands)

        # File in src/
        src_file = os.path.join(self.temp_dir, "src", "core", "engine.py")
        cands_src = tracer.get_candidate_module_namespaces(src_file)
        self.assertIn("src.core.engine", cands_src)
        self.assertIn("core.engine", cands_src)
        self.assertIn("engine", cands_src)

    def test_bound_method_self_handling(self):
        sig = self.parse_sig("def calculate(self, amount, rate=0.0): pass")
        # Instance method call: obj.calculate(100)
        call = self.parse_expr("obj.calculate(100)")
        warnings = self.auditor.check_caller_mismatch(call, sig)
        # Should not warn about missing 'self'
        self.assertEqual(len(warnings), 0)

    def test_positional_only_and_keyword_only(self):
        sig = self.parse_sig("def calculate(amount, /, *, rate): pass")
        # Valid call
        valid_call = self.parse_expr("calculate(100, rate=0.18)")
        self.assertEqual(len(self.auditor.check_caller_mismatch(valid_call, sig)), 0)

        # Pass positional-only as keyword -> Error
        invalid_pos = self.parse_expr("calculate(amount=100, rate=0.18)")
        warnings = self.auditor.check_caller_mismatch(invalid_pos, sig)
        self.assertTrue(any("positional-only" in w for w in warnings))

        # Missing required keyword-only -> Error
        missing_kw = self.parse_expr("calculate(100)")
        warnings2 = self.auditor.check_caller_mismatch(missing_kw, sig)
        self.assertTrue(any("keyword-only" in w for w in warnings2))

if __name__ == "__main__":
    unittest.main()
