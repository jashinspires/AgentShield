import unittest
import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from guard import CommandGuard
from deobfuscator import ShellCommandNormalizer

class TestGuardPowerShell(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_guard.db")
        self.guard = CommandGuard(self.db_path)
        self.normalizer = ShellCommandNormalizer()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_powershell_destructive_commands_blocked(self):
        # Even after normalizer maps rm -> Remove-Item
        cmds = [
            "Remove-Item -rf /",
            "Remove-Item -Recurse -Force C:\\",
            "Remove-Item C:\\ -Recurse -Force",
            "del /f /q C:\\",
            "del /f /s /q C:\\",
            "rmdir /s /q C:\\",
            "rm -rf /",
            "rm -rf ~",
            "rm -rf $HOME"
        ]
        for cmd in cmds:
            verdict = self.guard.check_speculative_rules(cmd)
            self.assertEqual(verdict, "BLOCK", f"Failed to block: {cmd}")

    def test_credential_theft_blocked(self):
        cmds = [
            "cat ~/.ssh/id_rsa",
            "gc .ssh/id_ed25519",
            "type .env",
            "cat .env",
            "cat /etc/shadow",
            "echo aws_access_key_id"
        ]
        for cmd in cmds:
            verdict = self.guard.check_speculative_rules(cmd)
            self.assertEqual(verdict, "BLOCK", f"Failed to block: {cmd}")

    def test_safe_developer_tools_allowed(self):
        cmds = [
            "git status",
            "git diff HEAD~1",
            "pytest",
            "python -m pytest tests/",
            "npm test",
            "npm run test",
            "cargo test",
            "go test",
            "python --version",
            "docker --version"
        ]
        for cmd in cmds:
            verdict = self.guard.check_speculative_rules(cmd)
            self.assertEqual(verdict, "ALLOW", f"Failed to allow: {cmd}")

if __name__ == "__main__":
    unittest.main()
