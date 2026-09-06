import os
import sys
import sqlite3
from typing import Dict, Any, Optional

# Project root is the parent directory of src/
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SRC_DIR)


def find_config_file() -> Optional[str]:
    """Searches for agentshield.yaml in standard locations relative to project root."""
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


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Loads YAML configuration with graceful fallback if PyYAML is missing."""
    if config_path is None:
        config_path = find_config_file()

    if not config_path or not os.path.isfile(config_path):
        return {}

    try:
        import yaml
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        # Minimal fallback parser if pyyaml is not installed
        config = {}
        try:
            with open(config_path, "r", encoding="utf-8") as f:
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
        sys.stderr.write(f"[AgentShield] Warning: failed to load config {config_path}: {e}\n")
        return {}


def get_database_path(config: Optional[Dict[str, Any]] = None) -> str:
    """
    Returns the absolute path to the SQLite database.
    Prioritizes path from config, defaulting to data/command_cache.db in project root.
    Ensures parent directory exists.
    """
    if config is None:
        config = load_config()

    default_rel_path = os.path.join("data", "command_cache.db")
    db_rel = default_rel_path

    db_cfg = config.get("database")
    if isinstance(db_cfg, dict) and db_cfg.get("path"):
        db_rel = db_cfg.get("path")
    elif isinstance(db_cfg, str) and db_cfg:
        db_rel = db_cfg

    if os.path.isabs(db_rel):
        db_path = db_rel
    else:
        db_path = os.path.join(_PROJECT_ROOT, db_rel)

    db_path = os.path.normpath(db_path)
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    return db_path


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Creates a connection to the AgentShield SQLite database."""
    if db_path is None:
        db_path = get_database_path()
    return sqlite3.connect(db_path)


def cleanup_shadow_root_db():
    """
    Removes any stale empty command_cache.db at the project root
    that might accidentally shadow the active database in data/.
    """
    root_db = os.path.join(_PROJECT_ROOT, "command_cache.db")
    data_db = os.path.join(_PROJECT_ROOT, "data", "command_cache.db")
    if os.path.isfile(root_db) and os.path.isfile(data_db):
        try:
            if os.path.getsize(root_db) == 0:
                os.remove(root_db)
        except Exception:
            pass
