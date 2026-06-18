import sys
import os
import argparse
import sqlite3
from datetime import datetime, timezone

# Resolve all paths relative to THIS file's location, not CWD
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SRC_DIR)

# Add src directory to Python path so sibling imports work
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from deobfuscator import ShellCommandNormalizer
from guard import CommandGuard
from sandbox import SandboxExecutionEngine
from brain import BrainClient


def _find_config_file():
    """Searches for agentshield.yaml in standard locations relative to the engine's own directory."""
    candidates = [
        os.path.join(_PROJECT_ROOT, "config", "agentshield.yaml"),
        os.path.join(_SRC_DIR, "..", "config", "agentshield.yaml"),
        os.path.join(os.getcwd(), "config", "agentshield.yaml"),
        os.path.join(os.getcwd(), "agentshield.yaml"),
    ]
    for p in candidates:
        resolved = os.path.normpath(p)
        if os.path.isfile(resolved):
            return resolved
    return None


def _load_yaml_config(path):
    """Load YAML config, with graceful fallback if pyyaml is missing."""
    if not path or not os.path.isfile(path):
        return {}
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        # PyYAML not installed — parse a minimal subset manually
        config = {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        key, _, val = line.partition(":")
                        val = val.strip().strip('"').strip("'")
                        if val:
                            config[key.strip()] = val
        except Exception:
            pass
        return config
    except Exception as e:
        sys.stderr.write(f"[AgentShield] Warning: failed to load config {path}: {e}\n")
        return {}


class AgentSubshell:
    def __init__(self, config_path=None):
        if config_path is None:
            config_path = _find_config_file()

        self.config = _load_yaml_config(config_path)
        self.shell_path = self.config.get("shell") or ("powershell.exe" if os.name == "nt" else "/bin/bash")
        self.fail_safe_mode = self.config.get("fail_safe_mode", "closed")

        # Database path — resolve relative to project root, not CWD
        db_path = self.config.get("database", {}).get("path", "command_cache.db") if isinstance(self.config.get("database"), dict) else "command_cache.db"
        if not os.path.isabs(db_path):
            db_path = os.path.join(_PROJECT_ROOT, db_path)
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

        self.guard = CommandGuard(db_path)
        self.normalizer = ShellCommandNormalizer()

        # Workspace root is where the user's project lives (CWD or env override)
        workspace_root = os.environ.get("AGENTSHIELD_WORKSPACE", os.getcwd())

        sandbox_config = self.config.get("sandbox", {}) if isinstance(self.config.get("sandbox"), dict) else {}
        self.sandbox_engine = SandboxExecutionEngine(
            workspace_root=workspace_root,
            sandbox_provider=sandbox_config.get("provider", "docker"),
            image=sandbox_config.get("image", "python:3.11-slim-buster"),
            memory_limit=sandbox_config.get("memory_limit", "512m"),
            cpu_limit=sandbox_config.get("cpu_limit", "1.0"),
            network_access=sandbox_config.get("network_access", False),
            network_whitelist=sandbox_config.get("network_whitelist", [])
        )

        # Ollama brain client — graceful fallback if Ollama is not running
        self.brain = None
        ollama_config = self.config.get("ollama", {}) if isinstance(self.config.get("ollama"), dict) else {}
        try:
            self.brain = BrainClient(
                endpoint=ollama_config.get("endpoint", "http://localhost:11434/api/generate"),
                model_name=ollama_config.get("model", "qwen2.5-coder:3b")
            )
        except Exception as e:
            sys.stderr.write(f"[AgentShield] Warning: Could not initialize Ollama client: {e}\n")
            sys.stderr.write("[AgentShield] Running in rules-only mode (no AI classification).\n")

    def is_agent_redirected(self):
        """Checks if standard streams are piped by an AI agent or are a direct TTY."""
        return not sys.stdin.isatty()

    def prompt_human_override(self, blocked_cmd):
        """
        Bypasses standard redirected output streams to ask the user on the direct console.
        Uses 'CON' on Windows or '/dev/tty' on Linux/macOS.
        """
        console_path = "CON" if os.name == "nt" else "/dev/tty"
        try:
            with open(console_path, "r") as r_tty, open(console_path, "w") as w_tty:
                w_tty.write(f"\n[AgentShield ALERT] Suspicious command intercepted:\n")
                w_tty.write(f"  >> {blocked_cmd}\n")
                w_tty.write(f"Do you want to override and allow this command? (y/N): ")
                w_tty.flush()
                response = r_tty.readline().strip().lower()
                return response in ["y", "yes"]
        except Exception:
            # In VS Code terminal, CON/tty may not be available — fall back to stdin
            try:
                sys.stderr.write(f"\n[AgentShield ALERT] Suspicious command intercepted:\n")
                sys.stderr.write(f"  >> {blocked_cmd}\n")
                sys.stderr.write(f"Do you want to override and allow this command? (y/N): ")
                sys.stderr.flush()
                response = input().strip().lower()
                return response in ["y", "yes"]
            except Exception:
                return False

    def log_execution(self, raw_cmd, normalized_cmd, verdict, reason, exit_code):
        """Logs the command execution into the database for auditing and dashboard rendering."""
        try:
            conn = sqlite3.connect(self.guard.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    raw_command TEXT,
                    normalized_command TEXT,
                    verdict TEXT,
                    reason TEXT,
                    exit_code INTEGER
                )
            """)
            cursor.execute("""
                INSERT INTO audit_logs (timestamp, raw_command, normalized_command, verdict, reason, exit_code)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (datetime.now(timezone.utc).isoformat(), raw_cmd, normalized_cmd, verdict, reason, exit_code))
            conn.commit()
            conn.close()
        except Exception as e:
            sys.stderr.write(f"[AgentShield] DB log error: {e}\n")

    def run_command_pipeline(self, cmd_str):
        """Processes and runs a single command string through normalization, audit, and execution."""
        if not cmd_str.strip():
            return 0

        # 1. Normalize/deobfuscate
        normalized_cmd = self.normalizer.normalize(cmd_str)

        # 2. Check speculative regex rules (instant, no latency)
        verdict = self.guard.check_speculative_rules(normalized_cmd)
        reason = "Speculative Rule Match"

        if not verdict:
            # 3. Check SQLite cache
            cached = self.guard.get_cache_verdict(normalized_cmd)
            if cached:
                verdict, reason = cached
                reason = f"Cache Hit ({reason})"
            elif self.brain:
                # 4. Query local Ollama model
                try:
                    verdict, reason = self.brain.classify_command(normalized_cmd)
                    self.guard.cache_verdict(normalized_cmd, verdict, reason)
                except Exception as e:
                    reason = f"Model Error: {e}"
                    verdict = "BLOCK" if self.fail_safe_mode == "closed" else "ALLOW"
            else:
                # No brain client available — use fail-safe mode
                reason = "No AI model available, using fail-safe mode"
                verdict = "BLOCK" if self.fail_safe_mode == "closed" else "ALLOW"

        # 5. Execute based on verdict
        exit_code = 0
        if verdict == "BLOCK":
            if self.prompt_human_override(cmd_str):
                sys.stderr.write(f"[AgentShield] User override accepted. Executing on host.\n")
                result = self.sandbox_engine.execute_on_host(cmd_str)
                exit_code = result.get("exit_code", 0)
                if result.get("stdout"):
                    sys.stdout.write(result["stdout"])
                if result.get("stderr"):
                    sys.stderr.write(result["stderr"])
            else:
                sys.stderr.write(f'[AgentShield] BLOCKED: "{cmd_str}" — {reason}\n')
                exit_code = 1
        elif verdict == "SANDBOX":
            sys.stderr.write(f"[AgentShield] Sandboxed: {reason}\n")
            result = self.sandbox_engine.execute_in_sandbox(cmd_str)
            exit_code = result.get("exit_code", 0)
            if result.get("stdout"):
                sys.stdout.write(result["stdout"])
            if result.get("stderr"):
                sys.stderr.write(result["stderr"])
        else:  # ALLOW
            result = self.sandbox_engine.execute_on_host(cmd_str)
            exit_code = result.get("exit_code", 0)
            if result.get("stdout"):
                sys.stdout.write(result["stdout"])
            if result.get("stderr"):
                sys.stderr.write(result["stderr"])

        # Log for dashboard
        self.log_execution(cmd_str, normalized_cmd, verdict, reason, exit_code)
        return exit_code

    def start_loop(self):
        """Starts interactive shell wrapper REPL."""
        print("=" * 56)
        print("  AgentShield Interactive Shell Proxy")
        print(f"  Fail-safe mode: {self.fail_safe_mode}")
        print(f"  AI model: {'connected' if self.brain else 'offline (rules-only)'}")
        print("  Type 'exit' or press Ctrl+D to quit.")
        print("=" * 56)

        while True:
            try:
                cwd = os.getcwd()
                prompt = f"(agentsh) {cwd}> "
                cmd = input(prompt)
                if cmd.strip().lower() in ["exit", "quit"]:
                    break
                self.run_command_pipeline(cmd)
            except KeyboardInterrupt:
                print("\nType 'exit' to quit.")
            except EOFError:
                break
            except Exception as e:
                print(f"[AgentShield] Error: {e}")


def main():
    parser = argparse.ArgumentParser(description="AgentShield CLI Shell Proxy")
    parser.add_argument("-c", "--command", type=str, help="Command to run through the proxy")
    parser.add_argument("--interactive", action="store_true", help="Force interactive REPL mode")
    parser.add_argument("--config", type=str, help="Path to agentshield.yaml config file")
    parser.add_argument("args", nargs="*", help="Direct command arguments")
    args = parser.parse_args()

    try:
        subshell = AgentSubshell(config_path=args.config)
    except Exception as e:
        sys.stderr.write(f"[AgentShield] Fatal: Failed to initialize — {e}\n")
        sys.exit(2)

    # Determine what to do
    cmd_to_run = ""
    if args.command:
        cmd_to_run = args.command
    elif args.args:
        cmd_to_run = " ".join(args.args)

    if cmd_to_run:
        exit_code = subshell.run_command_pipeline(cmd_to_run)
        sys.exit(exit_code)
    elif args.interactive or sys.stdin.isatty():
        subshell.start_loop()
    else:
        # Piped mode — read commands from stdin line by line
        for line in sys.stdin:
            subshell.run_command_pipeline(line.strip())


if __name__ == "__main__":
    main()
