import re
import base64
import sys

class ShellCommandNormalizer:
    def __init__(self):
        pass

    def normalize(self, cmd_str: str) -> str:
        """Determines platform and normalizes command string."""
        if not cmd_str:
            return ""
        
        # Trim leading/trailing whitespace
        cmd_str = cmd_str.strip()
        
        # Apply normalization rules
        if self._looks_like_powershell(cmd_str):
            return self.normalize_powershell(cmd_str)
        else:
            return self.normalize_bash(cmd_str)

    def _looks_like_powershell(self, cmd_str: str) -> bool:
        """Determines if the command looks like Windows PowerShell or CMD."""
        # If it contains typical shell pipeline shims or base64 decoding, classify as bash
        if "sh -c" in cmd_str or "bash" in cmd_str or "base64" in cmd_str or "base64 -d" in cmd_str:
            return False
            
        if sys.platform == "win32":
            return True
        # Detect Powershell signatures: -Command, -EncodedCommand, -enc, powershell, pwsh
        ps_indicators = [r"\bpowershell\b", r"\bpwsh\b", r"-encodedcommand\b", r"-enc\b"]
        for ind in ps_indicators:
            if re.search(ind, cmd_str, re.IGNORECASE):
                return True
        return False

    def normalize_bash(self, cmd_str: str) -> str:
        """
        Cleans Bash inputs. Strips quotes (c""u''rl -> curl), decodes Base64 shims,
        and expands simple internal aliases.
        """
        import shlex
        try:
            parts = shlex.split(cmd_str, posix=False)
        except Exception:
            parts = cmd_str.split(" ")
            
        cleaned_parts = []
        for part in parts:
            if (part.startswith("'") and part.endswith("'")) or (part.startswith('"') and part.endswith('"')):
                # Preserve fully quoted arguments
                cleaned_parts.append(part)
            else:
                # Remove quotes within command word (e.g. c""u''rl -> curl)
                cleaned_part = part.replace('"', '').replace("'", "")
                cleaned_parts.append(cleaned_part)
        
        cleaned = " ".join(cleaned_parts)

        # 2. Base64 Shim Extraction
        base64_patterns = [
            r"echo\s+['\"]?([A-Za-z0-9+/={}\s]+)['\"]?\s*\|\s*base64\s+-d\s*\|\s*sh",
            r"echo\s+['\"]?([A-Za-z0-9+/={}\s]+)['\"]?\s*\|\s*base64\s+--decode\s*\|\s*sh",
            r"base64\s+-d\s*<<<['\"]?([A-Za-z0-9+/={}\s]+)['\"]?\s*\|\s*sh"
        ]
        
        for pattern in base64_patterns:
            matches = re.search(pattern, cleaned, re.IGNORECASE)
            if matches:
                encoded_payload = matches.group(1).replace(" ", "").replace("\n", "").replace("\r", "")
                try:
                    decoded_bytes = base64.b64decode(encoded_payload)
                    decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                    return self.normalize(decoded_str)
                except Exception:
                    pass

        # 3. Expand aliases
        bash_aliases = {
            "cat": "cat",
            "ls": "ls",
            "echo": "echo",
            "rm": "rm"
        }
        words = cleaned.split()
        if words and words[0] in bash_aliases:
            words[0] = bash_aliases[words[0]]
            cleaned = " ".join(words)

        return cleaned

    def normalize_powershell(self, cmd_str: str) -> str:
        """Normalizes Windows cmd and PowerShell inputs."""
        import shlex
        try:
            parts = shlex.split(cmd_str, posix=False)
        except Exception:
            parts = cmd_str.split(" ")
            
        cleaned_parts = []
        for part in parts:
            if (part.startswith("'") and part.endswith("'")) or (part.startswith('"') and part.endswith('"')):
                cleaned_parts.append(part)
            else:
                cleaned_part = re.sub(r"[\"']", "", part)
                cleaned_parts.append(cleaned_part)
                
        cleaned = " ".join(cleaned_parts)

        # 2. Decode PowerShell Encoded Command flags (-EncodedCommand, -enc)
        encoded_arg_pattern = r"-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+['\"]?([A-Za-z0-9+/=]+)['\"]?"
        match = re.search(encoded_arg_pattern, cleaned, re.IGNORECASE)
        if match:
            encoded_payload = match.group(2)
            try:
                decoded_bytes = base64.b64decode(encoded_payload)
                decoded_str = decoded_bytes.decode("utf-16-le", errors="ignore")
                return self.normalize(decoded_str)
            except Exception:
                try:
                    decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                    return self.normalize(decoded_str)
                except Exception:
                    pass

        # 3. Resolve aliases
        ps_aliases = {
            "gc": "Get-Content",
            "rm": "Remove-Item",
            "cat": "Get-Content",
            "ls": "Get-ChildItem",
            "dir": "Get-ChildItem",
            "echo": "Write-Output"
        }
        words = cleaned.split()
        if words and words[0] in ps_aliases:
            words[0] = ps_aliases[words[0]]
            cleaned = " ".join(words)

        return cleaned
