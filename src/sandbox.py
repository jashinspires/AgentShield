import subprocess
import os
import sys
import shutil
from typing import Dict, Any, List

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
        Runs the command in an ephemeral Docker container with network isolation and resource limits.
        Falls back to host execution or blocks if Docker is missing based on settings.
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

        # Format workspace mount path appropriately for Docker (converting backslashes on Windows)
        workspace_mount = self.root
        if os.name == "nt":
            # Convert Windows path to Docker-friendly format if needed
            workspace_mount = self.root.replace("\\", "/")

        # Build Docker command
        docker_cmd = [
            "docker", "run", "--rm",
            "--name", "agentshield_sandbox_instance",
            "-v", f"{workspace_mount}:/workspace",
            "-w", "/workspace",
            "--memory", self.memory_limit,
            "--cpus", self.cpu_limit
        ]

        if not self.network_access:
            docker_cmd.append("--network=none")

        # Docker image to run
        docker_cmd.append(self.image)
        
        # Shell inside Docker to execute command
        docker_cmd.extend(["sh", "-c", cmd_str])

        try:
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
