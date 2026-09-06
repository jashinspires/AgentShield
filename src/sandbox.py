import subprocess
import os
import sys
import shutil
from typing import Dict, Any, List, Optional

# Add src dir to path for sibling imports
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from proxy import FilteringForwardProxy

class SandboxExecutionEngine:
    def __init__(self, workspace_root: str, sandbox_provider: str = "docker",
                 image: str = "python:3.11-slim-buster", memory_limit: str = "512m",
                 cpu_limit: str = "1.0", network_access: bool = False,
                 network_whitelist: List[str] = None):
        self.root = os.path.abspath(workspace_root)
        self.provider = sandbox_provider.lower()
        self.image = image
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.network_access = network_access
        self.network_whitelist = network_whitelist or []
        self._docker_available = None

    def check_docker_available(self) -> bool:
        """Checks if Docker engine is running and accessible."""
        if self._docker_available is not None:
            return self._docker_available
        
        docker_bin = shutil.which("docker")
        if not docker_bin:
            self._docker_available = False
            return False
            
        try:
            # Run docker info to verify the daemon is running
            res = subprocess.run(
                ["docker", "info"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            self._docker_available = (res.returncode == 0)
        except Exception:
            self._docker_available = False
            
        return self._docker_available

    def build_docker_command(self, cmd_str: str, proxy_port: Optional[int] = None) -> List[str]:
        """Constructs the docker run CLI argument list with mounts, env vars, and proxy rules."""
        workspace_mount = self.root
        if os.name == "nt":
            workspace_mount = self.root.replace("\\", "/")

        docker_cmd = [
            "docker", "run", "--rm",
            "--name", "agentshield_sandbox_instance",
            "-v", f"{workspace_mount}:/workspace",
            # Persistent package volume across container runs
            "-v", "agentshield_pkg_cache:/opt/agentshield_packages",
            "-w", "/workspace",
            "--memory", self.memory_limit,
            "--cpus", self.cpu_limit,
            # Persistence environment configuration
            "--env", "PYTHONPATH=/opt/agentshield_packages:/workspace",
            "--env", "PATH=/opt/agentshield_packages/bin:/usr/local/bin:/usr/bin:/bin",
            "--env", "PIP_TARGET=/opt/agentshield_packages",
            "--env", "PIP_CACHE_DIR=/opt/agentshield_packages/.cache/pip",
            "--env", "npm_config_prefix=/opt/agentshield_packages"
        ]

        # Network isolation / proxying
        if proxy_port:
            docker_cmd.extend([
                "--add-host", "host.docker.internal:host-gateway",
                "--env", f"HTTP_PROXY=http://host.docker.internal:{proxy_port}",
                "--env", f"HTTPS_PROXY=http://host.docker.internal:{proxy_port}",
                "--env", f"http_proxy=http://host.docker.internal:{proxy_port}",
                "--env", f"https_proxy=http://host.docker.internal:{proxy_port}"
            ])
        elif not self.network_access:
            docker_cmd.append("--network=none")

        docker_cmd.append(self.image)
        docker_cmd.extend(["sh", "-c", cmd_str])
        return docker_cmd

    def execute_on_host(self, cmd_str: str) -> Dict[str, Any]:
        """Runs the command directly on the host machine subprocess with working directory limits."""
        # Detect host shell
        if os.name == "nt":
            shell_executable = "powershell.exe"
            shell_args = ["-NoProfile", "-NonInteractive", "-Command", cmd_str]
        else:
            shell_executable = "/bin/bash"
            shell_args = ["-c", cmd_str]

        try:
            # We set cwd to workspace root for isolation safety
            proc = subprocess.Popen(
                [shell_executable] + shell_args,
                cwd=self.root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate()
            return {
                "exit_code": proc.returncode,
                "stdout": stdout,
                "stderr": stderr
            }
        except Exception as e:
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": f"[*] Error executing command on host: {e}"
            }

    def execute_in_sandbox(self, cmd_str: str) -> Dict[str, Any]:
        """
        Runs the command in an ephemeral Docker container with network isolation,
        domain-whitelisted forwarding proxy, and persistent package caching.
        """
        if self.provider != "docker":
            return self.execute_on_host(cmd_str)

        if not self.check_docker_available():
            # If docker is configured but not running, report error
            return {
                "exit_code": 127,
                "stdout": "",
                "stderr": "[!] Docker engine is not running or available. Sandboxed execution blocked."
            }

        proxy = None
        proxy_port = None
        # If whitelist is configured, start local filtering forward proxy
        if self.network_whitelist:
            try:
                proxy = FilteringForwardProxy(whitelist=self.network_whitelist, host="0.0.0.0", port=0)
                proxy.start()
                proxy_port = proxy.port
            except Exception as e:
                sys.stderr.write(f"[AgentShield Sandbox] Warning: failed to start proxy: {e}\n")
                proxy = None

        try:
            docker_cmd = self.build_docker_command(cmd_str, proxy_port=proxy_port)
            proc = subprocess.Popen(
                docker_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate()
            return {
                "exit_code": proc.returncode,
                "stdout": stdout,
                "stderr": stderr
            }
        except Exception as e:
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": f"[!] Ephemeral sandbox container execution failed: {e}"
            }
        finally:
            if proxy:
                proxy.stop()
