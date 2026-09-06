import unittest
import os
import sys
import shutil
import tempfile
import sqlite3
import ast
import base64

# Add src folder to import path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from deobfuscator import ShellCommandNormalizer
from guard import CommandGuard
from resolver import NamespaceResolver
from auditor import SignatureAuditor

class TestDeobfuscator(unittest.TestCase):
    def setUp(self):
        self.normalizer = ShellCommandNormalizer()

    def test_quote_stripping_bash(self):
        # Bash style quote stripping
        original_platform = sys.platform
        sys.platform = "linux"
        try:
            self.assertEqual(self.normalizer.normalize("c\"\"u''rl"), "curl")
            self.assertEqual(self.normalizer.normalize("c\"\"u''rl -fsSL some_url"), "curl -fsSL some_url")
            self.assertEqual(self.normalizer.normalize("echo 'hello world'"), "echo 'hello world'")
        finally:
            sys.platform = original_platform

    def test_quote_stripping_powershell(self):
        # PowerShell/Windows style quote stripping
        # Force windows style checks by running on win32 or mocking
        original_platform = sys.platform
        sys.platform = "win32"
        try:
            self.assertEqual(self.normalizer.normalize("c\"\"u''rl"), "curl")
            # If alias is matched (cat -> Get-Content on Windows)
            self.assertEqual(self.normalizer.normalize("cat file.txt"), "Get-Content file.txt")
        finally:
            sys.platform = original_platform

    def test_base64_decode_bash(self):
        # echo "Y3VybCBleGFtcGxlLmNvbQ==" | base64 -d | sh -> curl example.com
        original_platform = sys.platform
        sys.platform = "linux"
        try:
            encoded = base64.b64encode(b"curl example.com").decode()
            cmd = f"echo {encoded} | base64 -d | sh"
            self.assertEqual(self.normalizer.normalize(cmd), "curl example.com")
        finally:
            sys.platform = original_platform

    def test_base64_decode_powershell(self):
        # powershell.exe -enc <utf-16le encoded command>
        encoded = base64.b64encode("Get-Process".encode("utf-16-le")).decode()
        cmd = f"powershell.exe -enc {encoded}"
        self.assertEqual(self.normalizer.normalize(cmd), "Get-Process")


class TestGuard(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_cache.db")
        self.guard = CommandGuard(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_speculative_rules(self):
        # git status is a spec rule ALLOW
        self.assertEqual(self.guard.check_speculative_rules("git status"), "ALLOW")
        self.assertEqual(self.guard.check_speculative_rules("pytest tests/"), "ALLOW")
        
        # rm -rf / is a spec rule BLOCK
        self.assertEqual(self.guard.check_speculative_rules("rm -rf /"), "BLOCK")
        self.assertEqual(self.guard.check_speculative_rules("cat ~/.ssh/id_rsa"), "BLOCK")
        
        # Normal command is None (queries model)
        self.assertIsNone(self.guard.check_speculative_rules("python app.py"))

    def test_sqlite_cache(self):
        cmd = "pip install requests"
        self.assertIsNone(self.guard.get_cache_verdict(cmd))
        
        self.guard.cache_verdict(cmd, "SANDBOX", "User installing packages")
        cached = self.guard.get_cache_verdict(cmd)
        self.assertIsNotNone(cached)
        self.assertEqual(cached[0], "SANDBOX")
        self.assertEqual(cached[1], "User installing packages")


class TestASTAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = SignatureAuditor()

    def parse_expr(self, code: str) -> ast.Call:
        tree = ast.parse(code)
        # Verify it is a Call expression
        expr = tree.body[0]
        if isinstance(expr, ast.Expr) and isinstance(expr.value, ast.Call):
            return expr.value
        raise ValueError("Code snippet must be a function call expression")

    def parse_sig(self, sig_code: str) -> ast.arguments:
        tree = ast.parse(sig_code)
        func = tree.body[0]
        if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return func.args
        raise ValueError("Code snippet must be a function definition")

    def test_exact_match(self):
        sig = self.parse_sig("def func(a, b): pass")
        call = self.parse_expr("func(1, 2)")
        warnings = self.auditor.check_caller_mismatch(call, sig)
        self.assertEqual(len(warnings), 0)

    def test_missing_positional(self):
        sig = self.parse_sig("def func(a, b, c): pass")
        call = self.parse_expr("func(1, 2)")
        warnings = self.auditor.check_caller_mismatch(call, sig)
        self.assertIn("Missing required positional argument 'c'", warnings)

    def test_missing_positional_with_defaults(self):
        sig = self.parse_sig("def func(a, b, c=3): pass")
        call = self.parse_expr("func(1, 2)")
        warnings = self.auditor.check_caller_mismatch(call, sig)
        self.assertEqual(len(warnings), 0) # c has a default

    def test_too_many_positional(self):
        sig = self.parse_sig("def func(a, b): pass")
        call = self.parse_expr("func(1, 2, 3)")
        warnings = self.auditor.check_caller_mismatch(call, sig)
        self.assertIn("Too many positional arguments: passed 3, expected at most 2", warnings)

    def test_unknown_keyword(self):
        sig = self.parse_sig("def func(a, b): pass")
        call = self.parse_expr("func(1, 2, z=9)")
        warnings = self.auditor.check_caller_mismatch(call, sig)
        self.assertIn("Unknown keyword argument 'z'", warnings)

    def test_positional_only_keyword_fail(self):
        # Python 3.8 positional-only argument notation: /
        sig = self.parse_sig("def func(a, b, /): pass")
        call = self.parse_expr("func(1, b=2)")
        warnings = self.auditor.check_caller_mismatch(call, sig)
        self.assertIn("Parameter 'b' is positional-only and cannot be passed as a keyword argument", warnings)

    def test_keyword_only_missing(self):
        # Python keyword-only argument notation: *
        sig = self.parse_sig("def func(a, *, b): pass")
        call = self.parse_expr("func(1)")
        warnings = self.auditor.check_caller_mismatch(call, sig)
        self.assertIn("Missing required keyword-only argument 'b'", warnings)


class TestNamespaceResolver(unittest.TestCase):
    def test_absolute_import_resolve(self):
        code = """
import math
from utils import db_connector as db
from my_pkg.views import render
"""
        tree = ast.parse(code)
        resolver = NamespaceResolver("my_pkg/views.py", "my_pkg.views")
        resolver.visit(tree)
        
        self.assertEqual(resolver.imports.get("math"), "math")
        self.assertEqual(resolver.imports.get("db"), "utils.db_connector")
        self.assertEqual(resolver.imports.get("render"), "my_pkg.views.render")

    def test_relative_import_resolve(self):
        code = """
from . import local_helper
from ..models import db_session
"""
        tree = ast.parse(code)
        resolver = NamespaceResolver("my_pkg/sub_pkg/views.py", "my_pkg.sub_pkg.views")
        resolver.visit(tree)
        
        # level=1: from . import local_helper -> my_pkg.sub_pkg.local_helper
        self.assertEqual(resolver.imports.get("local_helper"), "my_pkg.sub_pkg.local_helper")
        # level=2: from ..models import db_session -> my_pkg.models.db_session
        self.assertEqual(resolver.imports.get("db_session"), "my_pkg.models.db_session")

if __name__ == "__main__":
    unittest.main()
