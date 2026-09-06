import unittest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from sandbox import SandboxExecutionEngine

class TestSandboxAdvanced(unittest.TestCase):
    def test_build_docker_command_with_proxy(self):
        engine = SandboxExecutionEngine(
            workspace_root=os.getcwd(),
            network_access=False,
            network_whitelist=["pypi.org", "*.pythonhosted.org"]
        )
        cmd = engine.build_docker_command("pip install requests", proxy_port=8888)
        cmd_str = " ".join(cmd)

        # Check persistent volume
        self.assertIn("-v agentshield_pkg_cache:/opt/agentshield_packages", cmd_str)
        # Check Python path and pip target
        self.assertIn("--env PYTHONPATH=/opt/agentshield_packages:/workspace", cmd_str)
        self.assertIn("--env PIP_TARGET=/opt/agentshield_packages", cmd_str)
        # Check proxy routing
        self.assertIn("--add-host host.docker.internal:host-gateway", cmd_str)
        self.assertIn("--env HTTP_PROXY=http://host.docker.internal:8888", cmd_str)
        self.assertIn("--env HTTPS_PROXY=http://host.docker.internal:8888", cmd_str)
        # Verify --network=none is NOT present when proxy is enabled
        self.assertNotIn("--network=none", cmd_str)

    def test_build_docker_command_without_network(self):
        engine = SandboxExecutionEngine(
            workspace_root=os.getcwd(),
            network_access=False,
            network_whitelist=[]
        )
        cmd = engine.build_docker_command("python script.py", proxy_port=None)
        cmd_str = " ".join(cmd)

        # When no whitelist and network_access is False, must enforce --network=none
        self.assertIn("--network=none", cmd_str)
        # Still retains persistent package cache
        self.assertIn("-v agentshield_pkg_cache:/opt/agentshield_packages", cmd_str)

    def test_build_docker_command_with_full_network(self):
        engine = SandboxExecutionEngine(
            workspace_root=os.getcwd(),
            network_access=True,
            network_whitelist=[]
        )
        cmd = engine.build_docker_command("curl example.com", proxy_port=None)
        cmd_str = " ".join(cmd)

        self.assertNotIn("--network=none", cmd_str)
        self.assertNotIn("HTTP_PROXY", cmd_str)

    def test_stopped_docker_fails_gracefully(self):
        engine = SandboxExecutionEngine(workspace_root=os.getcwd())
        # If docker daemon is stopped on this machine, test execute_in_sandbox
        if not engine.check_docker_available():
            res = engine.execute_in_sandbox("ls -la")
            self.assertEqual(res["exit_code"], 127)
            self.assertIn("Docker engine is not running or available", res["stderr"])

if __name__ == "__main__":
    unittest.main()
