import urllib.request
import json
from typing import Tuple

class BrainClient:
    def __init__(self, endpoint: str = "http://localhost:11434/api/generate", model_name: str = "qwen2.5-coder:3b"):
        self.endpoint = endpoint
        self.model = model_name
        
        # XML delimited safety prompt
        self.system_prompt = (
            "You are a secure operating system guardrail. You analyze shell commands executed by autonomous agents.\n"
            "You must output a valid JSON block containing:\n"
            "{\n"
            '  "verdict": "ALLOW" | "BLOCK" | "SANDBOX",\n'
            '  "reason": "A short 1-sentence explanation of your choice."\n'
            "}\n\n"
            "Verdicts rules:\n"
            "- ALLOW: Command is a safe, local-read operation (e.g. git status, git diff, pytest, npm test, rustc --version).\n"
            "- BLOCK: Command attempts to delete files outside the workspace root, access SSH directories (~/.ssh), dump credentials, write to root directories, or compromise host security.\n"
            "- SANDBOX: Command installs packages (npm install, pip install), starts local servers, executes arbitrary shell scripts, or makes network queries (curl, wget)."
        )

    def classify_command(self, cmd_str: str) -> Tuple[str, str]:
        """Queries local Ollama using standard urllib POST calls to avoid external SDK dependencies."""
        user_prompt = (
            "Evaluate the command inside the <target_command> tag.\n"
            "<target_command>\n"
            f"{cmd_str}\n"
            "</target_command>"
        )
        
        payload = {
            "model": self.model,
            "prompt": user_prompt,
            "system": self.system_prompt,
            "stream": False,
            "options": {"temperature": 0.0},
            "format": "json" # Enforces direct JSON output parameters
        }
        
        req = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        
        try:
            with urllib.request.urlopen(req, timeout=3.0) as response:
                res_data = json.loads(response.read().decode())
                raw_response = res_data.get("response", "").strip()
                parsed = json.loads(raw_response)
                
                verdict = parsed.get("verdict", "BLOCK").upper()
                reason = parsed.get("reason", "No reason provided")
                
                if verdict not in ["ALLOW", "BLOCK", "SANDBOX"]:
                    verdict = "BLOCK"
                    
                return verdict, reason
        except Exception as e:
            # Fallback when Ollama model endpoint times out or is offline
            import sys
            sys.stderr.write(f"[*] Brain Ollama query failed: {e}. Falling back to default block.\n")
            return "BLOCK", f"Model API Timeout or Parse Error: {e}"
