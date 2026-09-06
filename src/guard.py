import sqlite3
import hashlib
import os
import sys
import re
from typing import Tuple, Optional

# Resolve paths relative to this file
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from config_loader import get_database_path

class CommandGuard:
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = get_database_path()
        self.db_path = db_path
        self.setup_cache()
        
        # Speculative validation rules to allow safe common actions immediately (<1ms)
        self.allow_rules = [
            r"^git\s+(status|diff|log|show|branch|remote|rev-parse)\b",
            r"^(pytest|python\s+-m\s+pytest|python3\s+-m\s+pytest)\b",
            r"^npm\s+(test|run\s+test|run\s+lint)\b",
            r"^(cargo\s+test|go\s+test)\b",
            r"^(python|python3|node|cargo|rustc|go|git|docker)\s+(--version|-v|-V)\b"
        ]

        # Speculative validation rules to block extremely malicious actions instantly (<1ms)
        self.block_rules = [
            # 1. Linux/POSIX recursive removal
            r"\brm\s+-[a-zA-Z0-9]*r[a-zA-Z0-9]*f[a-zA-Z0-9]*\s+(/|\~|~|/\*|\$HOME)(\s|$|\b)",
            r"\brm\s+-[a-zA-Z0-9]*f[a-zA-Z0-9]*r[a-zA-Z0-9]*\s+(/|\~|~|/\*|\$HOME)(\s|$|\b)",
            r"\brm\s+--no-preserve-root\b",
            
            # 2. PowerShell & Windows recursive removal (handles normalizer mapping rm -> Remove-Item)
            r"\b(Remove-Item|del|erase|rd|rmdir|ri)\b.*(?:\s|/)-(Recurse|r)\b.*(?:\s|/)-(Force|f)\b.*(?:C:\\|C:/|/|\~|\$HOME|%USERPROFILE%|%SystemDrive%)",
            r"\b(Remove-Item|del|erase|rd|rmdir|ri)\b.*(?:C:\\|C:/|/|\~|\$HOME|%USERPROFILE%|%SystemDrive%).*(?:\s|/)-(Recurse|r)\b",
            r"\b(Remove-Item|del|erase|rd|rmdir|ri)\s+-[a-zA-Z0-9]*r[a-zA-Z0-9]*f[a-zA-Z0-9]*\s+(/|\~|~|/\*|\$HOME|C:\\)(\s|$|\b)",
            r"\b(Remove-Item|del|erase|rd|rmdir|ri)\s+-[a-zA-Z0-9]*f[a-zA-Z0-9]*r[a-zA-Z0-9]*\s+(/|\~|~|/\*|\$HOME|C:\\)(\s|$|\b)",
            r"\bdel\s+/[fF]\s+/[sS]\s+/[qQ]\s+[cC]:\\",
            r"\bdel\s+/[fF]\s+/[qQ]\s+[cC]:\\",
            r"\brmdir\s+/[sS]\s+/[qQ]\s+[cC]:\\",
            
            # 3. Sensitive file and credential harvesting
            r"\.ssh/(id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts)",
            r"aws_access_key_id|aws_secret_access_key",
            r"slack_api_token|SLACK_BOT_TOKEN",
            r"\b(cat|type|gc|Get-Content)\s+.*(\.env|\.bash_history|\.zsh_history|/etc/shadow|/etc/passwd)",
            r"\b/etc/passwd\b|\b/etc/shadow\b",
            r"\bSAM\b|\bSYSTEM\b.*config/system",
            
            # 4. Fork bombs and denial of service
            r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
            r"while\s+true\s*;\s*do\s+.*&\s*done"
        ]

    def setup_cache(self):
        """Initializes SQLite cache schema and indexes."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS command_cache (
                    cmd_hash TEXT PRIMARY KEY,
                    cmd_string TEXT NOT NULL,
                    verdict TEXT NOT NULL CHECK (verdict IN ('ALLOW', 'BLOCK', 'SANDBOX')),
                    reason TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cmd_hash ON command_cache(cmd_hash)")
            conn.commit()
            conn.close()
        except Exception as e:
            import sys
            sys.stderr.write(f"[*] Guard database setup failed: {e}\n")

    def get_cache_verdict(self, cmd_str: str) -> Optional[Tuple[str, str]]:
        """Hashes the command string and checks cache table. Returns (verdict, reason)."""
        cmd_hash = hashlib.sha256(cmd_str.strip().encode()).hexdigest()
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT verdict, reason FROM command_cache WHERE cmd_hash = ?", (cmd_hash,))
            row = cursor.fetchone()
            conn.close()
            if row:
                return row[0], row[1]
        except Exception:
            pass
        return None

    def cache_verdict(self, cmd_str: str, verdict: str, reason: str):
        """Caches a new command evaluation verdict."""
        cmd_hash = hashlib.sha256(cmd_str.strip().encode()).hexdigest()
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO command_cache (cmd_hash, cmd_string, verdict, reason)
                VALUES (?, ?, ?, ?)
            """, (cmd_hash, cmd_str, verdict, reason))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def check_speculative_rules(self, cmd_str: str) -> Optional[str]:
        """Runs speculative regex rules for latency bypass. Returns verdict or None."""
        cmd_str_clean = cmd_str.strip()
        
        # Check instant blocks
        for rule in self.block_rules:
            if re.search(rule, cmd_str_clean, re.IGNORECASE):
                return "BLOCK"
                
        # Check instant allows
        for rule in self.allow_rules:
            if re.search(rule, cmd_str_clean, re.IGNORECASE):
                return "ALLOW"
                
        return None
