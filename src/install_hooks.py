import os
import sys
import stat

def install_pre_commit_hook():
    workspace_root = os.getcwd()
    git_dir = os.path.join(workspace_root, ".git")
    
    if not os.path.exists(git_dir):
        sys.stderr.write("[!] Error: Not a git repository (could not find .git folder).\n")
        sys.exit(1)
        
    hooks_dir = os.path.join(git_dir, "hooks")
    if not os.path.exists(hooks_dir):
        os.makedirs(hooks_dir, exist_ok=True)
        
    hook_path = os.path.join(hooks_dir, "pre-commit")
    
    # Cross-platform bash hook executable script
    hook_content = """#!/bin/sh
# AgentShield AST pre-commit hook to block semantic signature regressions
echo "[*] AgentShield: Auditing codebase call-sites..."

if command -v python3 >/dev/null 2>&1; then
    python3 src/auditor.py
else
    python src/auditor.py
fi

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo "[!] AgentShield blocked commit due to AST regressions."
    exit $EXIT_CODE
fi

exit 0
"""
    
    try:
        with open(hook_path, "w", newline="\n", encoding="utf-8") as f:
            f.write(hook_content)
            
        # Make the file executable (important for Unix-like systems and Git Bash)
        st = os.stat(hook_path)
        os.chmod(hook_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        
        print(f"[+] AgentShield git pre-commit hook successfully installed at: {hook_path}")
    except Exception as e:
        sys.stderr.write(f"[!] Error installing pre-commit hook: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    install_pre_commit_hook()
