import sqlite3
import os
import sys

# Resolve paths relative to THIS file, not CWD
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SRC_DIR)
_UI_DIR = os.path.join(_SRC_DIR, "dashboard_ui")

if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from config_loader import get_database_path

def _resolve_db_path():
    """Find the command_cache.db file using unified config loader."""
    return get_database_path()


# Import FastAPI with graceful error handling
try:
    from fastapi import FastAPI
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import HTMLResponse
    from fastapi.middleware.cors import CORSMiddleware
except ImportError:
    print("[AgentShield] ERROR: FastAPI is not installed. Run: pip install fastapi uvicorn")
    sys.exit(1)

app = FastAPI(title="AgentShield Dashboard")

# CORS — allow VS Code webview iframe to access the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static Assets — serve dashboard UI files
if os.path.isdir(_UI_DIR):
    app.mount("/static", StaticFiles(directory=_UI_DIR), name="static")
else:
    print(f"[AgentShield] Warning: Dashboard UI directory not found at {_UI_DIR}")


@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    index_file = os.path.join(_UI_DIR, "index.html")
    if os.path.isfile(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>AgentShield Dashboard — UI assets not found</h1><p>Expected at: " + _UI_DIR + "</p>"


@app.get("/favicon.ico")
def get_favicon():
    return HTMLResponse(content="", status_code=204)


@app.get("/api/logs")
def get_logs():
    """Returns recent command log history from SQLite audit log database."""
    db_path = _resolve_db_path()
    logs = []
    if not os.path.isfile(db_path):
        return logs

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs'")
        if cursor.fetchone():
            cursor.execute("""
                SELECT timestamp, raw_command, normalized_command, verdict, reason, exit_code
                FROM audit_logs
                ORDER BY id DESC
                LIMIT 50
            """)
            rows = cursor.fetchall()
            for row in rows:
                logs.append({
                    "timestamp": row["timestamp"],
                    "raw_command": row["raw_command"],
                    "normalized_command": row["normalized_command"],
                    "verdict": row["verdict"],
                    "reason": row["reason"],
                    "exit_code": row["exit_code"]
                })
        conn.close()
    except Exception as e:
        sys.stderr.write(f"[AgentShield Dashboard] Log query error: {e}\n")

    return logs


@app.get("/api/graph")
def get_graph():
    """
    Analyzes all Python files in the workspace and outputs basic
    nodes and links representing import relationships.
    """
    import ast
    nodes = []
    links = []

    # Use the workspace from env (set by extension.js) or fall back to project root
    workspace = os.environ.get("AGENTSHIELD_WORKSPACE", _PROJECT_ROOT)
    py_files = []
    exclude_dirs = {
        ".git", ".venv", "venv", "env", "node_modules", "__pycache__", "build", "dist",
        ".agent", ".agents", ".obsidian", ".idea", ".vscode"
    }

    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for file in files:
            if file.endswith(".py"):
                py_files.append(os.path.join(root, file))

    # Build module namespace mapping
    file_modules = {}
    for filepath in py_files:
        rel_path = os.path.relpath(filepath, workspace)
        base, _ = os.path.splitext(rel_path)
        parts = base.replace("\\", "/").split("/")
        if parts and parts[0] == "src":
            parts = parts[1:]
        mod_name = ".".join(parts)
        file_modules[mod_name] = rel_path
        nodes.append({"id": mod_name, "type": "file", "label": os.path.basename(filepath)})

    # Find import edges
    for filepath in py_files:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            tree = ast.parse(content)

            rel_path = os.path.relpath(filepath, workspace)
            base, _ = os.path.splitext(rel_path)
            parts = base.replace("\\", "/").split("/")
            if parts and parts[0] == "src":
                parts = parts[1:]
            source_mod = ".".join(parts)

            class ImportVisitor(ast.NodeVisitor):
                def visit_Import(self, node):
                    for alias in node.names:
                        if alias.name in file_modules:
                            links.append({"source": source_mod, "target": alias.name})
                    self.generic_visit(node)

                def visit_ImportFrom(self, node):
                    module = node.module or ""
                    if module in file_modules:
                        links.append({"source": source_mod, "target": module})
                    self.generic_visit(node)

            ImportVisitor().visit(tree)
        except Exception:
            pass

    return {"nodes": nodes, "links": links}


@app.get("/api/health")
def health_check():
    """Simple health check endpoint for the extension to verify the server is running."""
    return {"status": "ok", "engine": "AgentShield Dashboard v1.1.0"}


if __name__ == "__main__":
    try:
        import uvicorn
    except ImportError:
        print("[AgentShield] ERROR: uvicorn is not installed. Run: pip install uvicorn")
        sys.exit(1)

    port = int(os.environ.get("AGENTSHIELD_PORT", 8000))
    print(f"[AgentShield] Starting dashboard on http://127.0.0.1:{port}")
    print(f"[AgentShield] UI directory: {_UI_DIR}")
    print(f"[AgentShield] Database: {_resolve_db_path()}")

    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    except OSError as e:
        if "address already in use" in str(e).lower() or "10048" in str(e):
            print(f"[AgentShield] Port {port} is already in use. Dashboard may already be running.")
            sys.exit(0)
        raise
