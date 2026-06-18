import sqlite3
import hashlib
import os
import re
from typing import Tuple, Optional

# Default DB path relative to project root (parent of src/)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_DB_PATH = os.path.join(_PROJECT_ROOT, "command_cache.db")

class CommandGuard:
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = _DEFAULT_DB_PATH
        self.db_path = db_path
        self.setup_cache()
        
        # Speculative validation rules to allow safe common actions immediately
        self.allow_rules = [
            r"^git\s+(status|diff|log|show|branch|remote|rev-parse)\b",
            r"^pytest\b",
            r"^npm\s+(test|run\s+test)\b",
            r"^python\s+-m\s+pytest\b",
            r"^cargo\s+test\b",
            r"^go\s+test\b"
        ]

        # Speculative validation rules to block extremely malicious actions instantly
        self.block_rules = [
            r"rm\s+-rf\s+(/|\~|~|/\*|\$HOME)(\s|$|\b)",
            r"del\s+/f\s+/q\s+C:\\",
            r"\.ssh/id_rsa",
            r"aws_access_key_id",
            r"slack_api_token",
            r"passwd"
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
