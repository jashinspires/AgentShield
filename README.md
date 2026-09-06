# AgentShield

AgentShield is a local-first security proxy and static code analysis tool designed to protect developer workstations when using autonomous AI coding assistants (such as Claude Code, Cursor, Aider, or custom LLM agents).

It operates on two layers:
1. **Runtime Shell Interception**: Acts as a protective subshell between the AI agent and the operating system. It normalizes obfuscated commands, evaluates safety through a fastest-first pipeline (speculative regex -> SQLite cache -> local Ollama model), and isolates untrusted commands inside an egress-filtered Docker container.
2. **Pre-Commit AST Code Auditing**: Analyzes Git diffs using Python's Abstract Syntax Tree (`ast`) module to detect modified function signatures across the repository. It audits all call sites to prevent AI-generated code from introducing silent argument mismatches and runtime errors before changes are committed.

---

## Why AgentShield?

When autonomous AI tools are granted terminal access, they run commands with the developer's full user privileges. This introduces two major failure modes in practice:

### 1. Terminal-Level Exploits and Data Exfiltration
- **Indirect Prompt Injection**: Malicious instructions embedded inside a cloned repo, an issue, or external documentation can steer an agent into running destructive shell commands.
- **Obfuscation Tricks**: Attackers can mask commands using quote splicing (`c""u''rl`), base64 pipes (`echo ... | base64 -d | sh`), or PowerShell encoded flags (`-EncodedCommand`) to evade simple keyword-matching filters.
- **Secret Exfiltration**: Commands can silently read and upload `.env` files, SSH keys, or cloud credentials disguised as routine network traffic.

### 2. Silent Code Regressions
- LLMs frequently refactor a function in one file (adding a parameter or changing positional-only/keyword-only arguments) but fail to update all corresponding caller sites across other files in the codebase.
- Standard linters don't always catch dynamic call-site mismatches across unstaged Git diffs. AgentShield traces the diff AST and catches signature regressions before code is committed.

---

## Architecture Overview

```
                        [ AI Agent / Terminal Command ]
                                       │
                                       ▼
                         [ 1. Shell Deobfuscator ]
                     (Strips quotes, decodes Base64,
                        expands shell aliases)
                                       │
                                       ▼
                       [ 2. Speculative Command Guard ]
                                       │
              ┌────────────────────────┼────────────────────────┐
              ▼                        ▼                        ▼
        [ <1ms Match ]           [ Cache Hit ]           [ Local LLM ]
       (Speculative Rules)     (SQLite SHA-256)      (Ollama qwen2.5-coder)
              │                        │                        │
              └────────────────────────┬────────────────────────┘
                                       │
                     ┌─────────────────┼─────────────────┐
                     ▼                 ▼                 ▼
                 [ ALLOW ]        [ SANDBOX ]         [ BLOCK ]
                     │                 │                 │
                     ▼                 ▼                 ▼
              (Host Machine)   (Docker Container)  (Prompt Human via
                                • 512MB RAM / 1.0 CPU  CON / /dev/tty)
                                • CONNECT Socket Proxy
                                  (Whitelist PyPI/npm)
                                • Persistent Volume
                                  (Package Cache)

─────────────────────────────────────────────────────────────────────────────

                    [ Git Diff (Staged / Unstaged Files) ]
                                       │
                                       ▼
                         [ 3. Code Impact Tracer ]
                   (Extracts old vs new function signatures,
                     generates multi-root candidate namespaces)
                                       │
                                       ▼
                         [ 4. Namespace Resolver ]
                    (Maps imports, resolves wildcard star
                      imports via target module __all__)
                                       │
                                       ▼
                         [ 5. Signature Auditor ]
                  (Audits call sites: positional, keyword-only,
                     defaults, and bound method self/cls offsets)
                                       │
                                       ▼
                     [ VS Code Inline Diagnostics / CI Gate ]
```

---

## Key Components

### 1. Subshell Proxy (`src/agentsh.py`)
Intercepts CLI commands before execution. It coordinates the deobfuscation, evaluation, execution, and SQLite audit logging. It includes:
- **Interactive REPL**: A guarded shell session for manual testing (`--interactive`).
- **Non-Interactive Mode**: A `--non-interactive` flag and `AGENTSHIELD_NON_INTERACTIVE=1` environment variable for automated agent runs and CI/CD pipelines, preventing commands from hanging on physical console prompts when blocked.

### 2. Normalizer & Deobfuscator (`src/deobfuscator.py`)
Cleans and normalizes commands before classification:
- Strips embedded quotes within command words (e.g., `c""u''rl` becomes `curl`).
- Unpacks and recursively decodes base64 pipelines (e.g., `echo <b64> | base64 -d | sh`).
- Decodes PowerShell UTF-16LE encoded commands (`-EncodedCommand` / `-enc`).
- Normalizes cross-platform shell aliases (e.g., maps `rm` to `Remove-Item` on Windows, and normalizes `cat`, `ls`, `dir`).

### 3. Speculative Command Guard (`src/guard.py`)
Evaluates commands using a fastest-first strategy to eliminate latency for safe developer actions:
- **Tier 1 — Speculative Rules (<1ms)**: Fast regex matching for common safe actions (`git status`, `git diff`, `pytest`, `npm test`, `cargo test`) and immediate blocks for destructive commands (`rm -rf /`, `Remove-Item -Recurse -Force C:\`, `del /f /s /q`, fork bombs, reading `.env` or `id_rsa`).
- **Tier 2 — SQLite Cache**: Checks `command_cache.db` using a SHA-256 hash of the command string.
- **Tier 3 — Local LLM**: Sends ambiguous commands to a local Ollama model (`qwen2.5-coder:3b`) with structured JSON output instructions.
- **Tier 4 — Fail-Safe Fallback**: If the local LLM is offline or times out, defaults to `closed` mode (blocks the command) or `open` mode based on configuration.
- **Out-of-Band Human Override**: If a command is blocked in an interactive session, AgentShield prompts the developer directly through the physical console (`CON` on Windows, `/dev/tty` on Unix). This bypasses standard input so an automated agent cannot spoof a confirmation.

### 4. Docker Sandboxing & Persistent Package Cache (`src/sandbox.py`)
When a command receives a `SANDBOX` verdict, it runs inside an isolated Docker container:
- Enforces strict memory (`512m`) and CPU (`1.0`) quotas.
- Mounts a persistent named volume (`agentshield_pkg_cache`) to `/opt/agentshield_packages`. Configures `PYTHONPATH`, `PIP_TARGET`, and `npm_config_prefix` so installed dependencies persist across ephemeral container runs.

### 5. Zero-Dependency Egress Proxy (`src/proxy.py`)
A lightweight forward filtering proxy written entirely with Python's standard library (`socket`, `threading`, `select`):
- Handles both plain HTTP and HTTPS `CONNECT` tunneling.
- Allows raw TLS tunneling to whitelisted package registries (e.g., `*.pypi.org`, `files.pythonhosted.org`, `*.npmjs.org`) without needing SSL MITM or custom CA certificates.
- Immediately blocks non-whitelisted outbound requests with `HTTP 403 Forbidden` to prevent data exfiltration.

### 6. Static AST Code Regression Auditor (`src/tracer.py`, `src/resolver.py`, `src/auditor.py`)
Guarantees codebase semantic integrity before code reaches Git commits:
- **`tracer.py`**: Reads `git diff` against `HEAD`, extracts modified function signatures, and generates candidate module namespaces (root-relative, source-stripped `src/`, and basenames).
- **`resolver.py`**: Resolves local calls and imports. Dynamically resolves wildcard star imports (`from module import *`) by parsing target module ASTs for `__all__` lists or public symbol tables.
- **`auditor.py`**: Verifies call sites against updated signatures. Accurately handles positional arguments, positional-only arguments (`/`), keyword-only arguments (`*`), default values, and bound methods (offsetting `self`/`cls` parameters). Optimized directory filtering skips non-project folders (`.agent`, `.venv`, `.git`), reducing full-workspace audit times from ~35 seconds to ~0.2 seconds.

### 7. Observability Dashboard (`src/dashboard.py`)
A local FastAPI application that provides:
- `/api/logs`: Real-time query of recent command execution history, verdicts, and exit codes.
- `/api/graph`: Visual dependency graph of workspace Python import relationships.
- `/api/health`: Health status endpoint for the VS Code extension.

---

## Project Structure

```
AgentShield/
├── config/
│   └── agentshield.yaml        # Main configuration file
├── src/
│   ├── agentsh.py              # CLI subshell proxy (REPL, -c, and CI runner)
│   ├── auditor.py              # Codebase AST call-site regression auditor
│   ├── brain.py                # Local Ollama LLM integration client
│   ├── config_loader.py        # Centralized configuration & DB path resolver
│   ├── dashboard.py            # FastAPI observability web server
│   ├── deobfuscator.py         # Shell command normalizer & Base64 decoder
│   ├── guard.py                # Speculative regex rules & SQLite verdict cache
│   ├── install_hooks.py        # Git pre-commit hook installer
│   ├── proxy.py                # Zero-dependency HTTP/CONNECT egress proxy
│   ├── resolver.py             # AST import and star-import symbol resolver
│   ├── sandbox.py              # Docker sandbox & persistent volume manager
│   ├── tracer.py               # Git diff signature parser & namespace generator
│   └── dashboard_ui/           # Dashboard web assets (HTML, CSS, JS)
├── tests/
│   ├── test_agentshield.py     # Core baseline tests (guard, deobfuscator, AST)
│   ├── test_ast_hardening.py   # Multi-namespace, star-import, and bound method tests
│   ├── test_guard_powershell.py# PowerShell and destructive command tests
│   ├── test_proxy.py           # Forward proxy HTTP and CONNECT filtering tests
│   └── test_sandbox_advanced.py# Docker command builder and volume tests
├── extension.js                # VS Code extension entry point
├── package.json                # VS Code extension manifest
├── LICENSE                     # MIT License
└── README.md                   # Project documentation
```

---

## Prerequisites

- **Python 3.10+** (Tested on Python 3.11 and 3.13)
- **Docker** (Optional, required for sandbox mode)
- **Ollama** (Optional, required for LLM classification fallback)
  ```bash
  ollama pull qwen2.5-coder:3b
  ```
- **Node.js & npm** (Optional, only needed if packaging the VS Code extension)

---

## Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/jashinspires/AgentShield.git
   cd AgentShield
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install pyyaml fastapi uvicorn
   ```

---

## Configuration

Configuration is managed in `config/agentshield.yaml`:

```yaml
# Target subshell executable (leave empty to auto-detect powershell.exe on Windows, /bin/bash on Unix)
shell: ""

# Fail-safe behavior if LLM is offline or times out: "closed" (block) or "open" (allow)
fail_safe_mode: "closed"

sandbox:
  provider: "docker"
  image: "python:3.11-slim-buster"
  memory_limit: "512m"
  cpu_limit: "1.0"
  network_access: false
  network_whitelist:
    - "pypi.org"
    - "*.pypi.org"
    - "files.pythonhosted.org"
    - "*.pythonhosted.org"
    - "registry.npmjs.org"
    - "*.npmjs.org"

database:
  path: "data/command_cache.db"

ollama:
  endpoint: "http://localhost:11434/api/generate"
  model: "qwen2.5-coder:3b"
```

---

## How to Run

### 1. Execute Commands via the Subshell Proxy

Run individual commands through AgentShield:
```bash
# Safe command (instant speculative allow in <1ms)
python src/agentsh.py -c "git status"

# Destructive command (intercepted and blocked)
python src/agentsh.py -c "rm -rf /"

# Non-interactive / CI mode (fails with exit code 1 without waiting for console input)
python src/agentsh.py --non-interactive -c "Remove-Item -Recurse -Force C:\"
```

### 2. Interactive Secure Subshell REPL

Start an interactive shell session where every command is evaluated before execution:
```bash
python src/agentsh.py --interactive
```

### 3. Run the Static AST Code Auditor

Scan the repository for function signature regressions introduced in your unstaged or staged Git changes:
```bash
python src/auditor.py
```
If a regression is found (e.g. an added argument that broke a caller site in another file), the auditor prints structured JSON error diagnostics to `stderr` and exits with code `1`.

### 4. Install the Git Pre-Commit Hook

Ensure no signature regressions can be committed into the repository:
```bash
python src/install_hooks.py
```

### 5. Start the Observability Dashboard

Launch the local web dashboard to view live audit logs and the dependency call graph:
```bash
python src/dashboard.py
```
Open `http://127.0.0.1:8000` in your web browser.

### 6. VS Code Extension (Optional)

To package and run the companion VS Code extension:
```bash
npx -y @vscode/vsce package --allow-missing-repository
code --install-extension agentshield-*.vsix
```
The extension automatically runs the AST auditor on Python file save, marks regressions with inline editor diagnostics, provides an "AgentShield Secure Proxy" terminal profile, and embeds the dashboard directly inside an editor webview.

---

## Running Tests

AgentShield includes a test suite covering speculative rules, deobfuscation, Docker command building, the forward filtering proxy, and AST regression auditing:

```bash
python -m unittest discover -s tests -v
```

All 30 unit and integration tests execute in under 1 second:
```text
test_exact_match (test_agentshield.TestASTAuditor) ... ok
test_keyword_only_missing (test_agentshield.TestASTAuditor) ... ok
test_missing_positional (test_agentshield.TestASTAuditor) ... ok
test_missing_positional_with_defaults (test_agentshield.TestASTAuditor) ... ok
test_positional_only_keyword_fail (test_agentshield.TestASTAuditor) ... ok
test_too_many_positional (test_agentshield.TestASTAuditor) ... ok
test_unknown_keyword (test_agentshield.TestASTAuditor) ... ok
test_base64_decode_bash (test_agentshield.TestDeobfuscator) ... ok
test_base64_decode_powershell (test_agentshield.TestDeobfuscator) ... ok
test_quote_stripping_bash (test_agentshield.TestDeobfuscator) ... ok
test_quote_stripping_powershell (test_agentshield.TestDeobfuscator) ... ok
test_speculative_rules (test_agentshield.TestGuard) ... ok
test_sqlite_cache (test_agentshield.TestGuard) ... ok
test_absolute_import_resolve (test_agentshield.TestNamespaceResolver) ... ok
test_relative_import_resolve (test_agentshield.TestNamespaceResolver) ... ok
test_bound_method_self_handling (test_ast_hardening.TestASTHardening) ... ok
test_candidate_module_namespaces (test_ast_hardening.TestASTHardening) ... ok
test_positional_only_and_keyword_only (test_ast_hardening.TestASTHardening) ... ok
test_star_import_with_dunder_all (test_ast_hardening.TestASTHardening) ... ok
test_star_import_without_dunder_all (test_ast_hardening.TestASTHardening) ... ok
test_credential_theft_blocked (test_guard_powershell.TestGuardPowerShell) ... ok
test_powershell_destructive_commands_blocked (test_guard_powershell.TestGuardPowerShell) ... ok
test_safe_developer_tools_allowed (test_guard_powershell.TestGuardPowerShell) ... ok
test_domain_whitelist_matcher (test_proxy.TestFilteringProxy) ... ok
test_proxy_blocks_unauthorized_connect (test_proxy.TestFilteringProxy) ... ok
test_proxy_blocks_unauthorized_http_get (test_proxy.TestFilteringProxy) ... ok
test_build_docker_command_with_full_network (test_sandbox_advanced.TestSandboxAdvanced) ... ok
test_build_docker_command_with_proxy (test_sandbox_advanced.TestSandboxAdvanced) ... ok
test_build_docker_command_without_network (test_sandbox_advanced.TestSandboxAdvanced) ... ok
test_stopped_docker_fails_gracefully (test_sandbox_advanced.TestSandboxAdvanced) ... ok

Ran 30 tests in 0.585s - OK
```

---

## Academic Review & Verification

This project was developed and verified as an individual engineering project for the B.Tech Computer Science & Engineering curriculum at Aditya University.

- **Author**: M. Jaswanth Kumar
- **Department**: Computer Science & Engineering
- **Institution**: Aditya University

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
