const vscode = require('vscode');
const child_process = require('child_process');
const path = require('path');
const fs = require('fs');

let dashboardProcess = null;
let diagnosticCollection = null;
let outputChannel = null;

/**
 * Resolves the absolute path to a Python engine script bundled with this extension.
 * Uses context.extensionPath so it works whether developing locally or installed from .vsix.
 */
function resolveEngineScript(extensionPath, scriptName) {
    return path.join(extensionPath, 'src', scriptName);
}

/**
 * Returns the user's workspace root folder, or null if no workspace is open.
 */
function getWorkspaceRoot() {
    const folders = vscode.workspace.workspaceFolders;
    if (folders && folders.length > 0) {
        return folders[0].uri.fsPath;
    }
    return null;
}

function activate(context) {
    outputChannel = vscode.window.createOutputChannel("AgentShield");
    outputChannel.appendLine("[*] AgentShield Extension v1.1.0 Activated.");

    const extensionRoot = context.extensionPath;
    outputChannel.appendLine(`[*] Extension root: ${extensionRoot}`);

    // Retrieve user settings
    const config = vscode.workspace.getConfiguration('agentshield');
    const pythonPath = config.get('pythonPath') || 'python';
    const enableAutostart = config.get('enableAutostartDashboard');
    const dashboardPort = config.get('dashboardPort') || 8000;

    // Workspace root is the user's open project (used as CWD for commands)
    const workspaceRoot = getWorkspaceRoot();
    if (!workspaceRoot) {
        outputChannel.appendLine("[!] No workspace folder open. Some AgentShield features require a workspace.");
    }

    // Verify the Python engine scripts exist inside the extension bundle
    const agentshScript = resolveEngineScript(extensionRoot, 'agentsh.py');
    const dashboardScript = resolveEngineScript(extensionRoot, 'dashboard.py');
    const auditorScript = resolveEngineScript(extensionRoot, 'auditor.py');

    if (!fs.existsSync(agentshScript)) {
        outputChannel.appendLine(`[!] CRITICAL: Engine file not found: ${agentshScript}`);
        outputChannel.appendLine(`[!] The extension may be improperly packaged. Engine files must exist in src/ relative to extension root.`);
        vscode.window.showErrorMessage("AgentShield: Engine files not found. The extension may need to be reinstalled.");
        return;
    }
    outputChannel.appendLine(`[+] Engine files verified at: ${path.join(extensionRoot, 'src')}`);

    // 1. Initialize diagnostics collection for AST regression markers
    diagnosticCollection = vscode.languages.createDiagnosticCollection('agentshield');
    context.subscriptions.push(diagnosticCollection);

    // 2. Start Dashboard server in background (if enabled and script exists)
    if (enableAutostart && fs.existsSync(dashboardScript)) {
        startDashboardServer(pythonPath, extensionRoot, dashboardScript, dashboardPort);
    }

    // 3. Register "Open Dashboard" command
    const openDashboardCmd = vscode.commands.registerCommand('agentshield.openDashboard', () => {
        // Ensure dashboard server is running
        if (!dashboardProcess && fs.existsSync(dashboardScript)) {
            startDashboardServer(pythonPath, extensionRoot, dashboardScript, dashboardPort);
        }

        const panel = vscode.window.createWebviewPanel(
            'agentshieldDashboard',
            'AgentShield Dashboard',
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true
            }
        );

        panel.webview.html = `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>AgentShield Dashboard</title>
                <style>
                    body, html {
                        margin: 0; padding: 0; height: 100%; width: 100%;
                        overflow: hidden; background-color: #0B0C10;
                    }
                    iframe {
                        border: none; width: 100%; height: 100%;
                    }
                    .loading {
                        display: flex; align-items: center; justify-content: center;
                        height: 100%; color: #66FCF1; font-family: 'Segoe UI', sans-serif;
                        font-size: 1.2em;
                    }
                </style>
            </head>
            <body>
                <div class="loading" id="loader">Starting AgentShield Dashboard on port ${dashboardPort}...</div>
                <iframe id="dash-frame" src="http://127.0.0.1:${dashboardPort}" style="display:none"
                    onload="document.getElementById('loader').style.display='none'; this.style.display='block';">
                </iframe>
                <script>
                    // Retry loading the iframe after a short delay if server isn't ready yet
                    setTimeout(() => {
                        const frame = document.getElementById('dash-frame');
                        frame.src = "http://127.0.0.1:${dashboardPort}";
                    }, 2000);
                </script>
            </body>
            </html>
        `;
    });
    context.subscriptions.push(openDashboardCmd);

    // 4. Register "Scan Workspace" command
    const scanWorkspaceCmd = vscode.commands.registerCommand('agentshield.scanWorkspace', () => {
        if (!workspaceRoot) {
            vscode.window.showWarningMessage("AgentShield: No workspace folder open to scan.");
            return;
        }
        if (!fs.existsSync(auditorScript)) {
            vscode.window.showErrorMessage("AgentShield: Auditor engine (auditor.py) not found.");
            return;
        }

        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "AgentShield: Auditing codebase call-sites...",
            cancellable: false
        }, () => {
            return new Promise((resolve) => {
                runAuditor(pythonPath, workspaceRoot, auditorScript, () => {
                    resolve();
                });
            });
        });
    });
    context.subscriptions.push(scanWorkspaceCmd);

    // 5. Register save listener to audit Python files on save
    const saveListener = vscode.workspace.onDidSaveTextDocument((document) => {
        if (document.languageId === 'python' && workspaceRoot && fs.existsSync(auditorScript)) {
            runAuditor(pythonPath, workspaceRoot, auditorScript);
        }
    });
    context.subscriptions.push(saveListener);

    // 6. Register Terminal Profile Provider — the key fix
    //    Uses extensionRoot to locate agentsh.py, uses workspaceRoot as CWD
    const terminalProvider = vscode.window.registerTerminalProfileProvider('agentshield.terminalProfile', {
        provideTerminalProfile: () => {
            const cwd = workspaceRoot || extensionRoot;
            outputChannel.appendLine(`[*] Creating AgentShield terminal: python "${agentshScript}" --interactive`);
            outputChannel.appendLine(`[*] Working directory: ${cwd}`);
            return {
                options: {
                    name: "AgentShield Secure Proxy",
                    shellPath: pythonPath,
                    shellArgs: [agentshScript, '--interactive'],
                    cwd: cwd,
                    env: {
                        ...process.env,
                        AGENTSHIELD_EXTENSION_ROOT: extensionRoot,
                        PYTHONUNBUFFERED: "1"
                    }
                }
            };
        }
    });
    context.subscriptions.push(terminalProvider);

    outputChannel.appendLine("[+] All AgentShield features registered successfully.");
}

function startDashboardServer(pythonPath, extensionRoot, dashboardScript, port) {
    if (dashboardProcess) {
        outputChannel.appendLine("[*] Dashboard server already running.");
        return;
    }

    outputChannel.appendLine(`[*] Starting Dashboard: ${pythonPath} "${dashboardScript}" (port ${port})`);

    // Set the CWD to the extension root so the dashboard can find its UI assets
    dashboardProcess = child_process.spawn(pythonPath, [dashboardScript], {
        cwd: extensionRoot,
        env: {
            ...process.env,
            PYTHONUNBUFFERED: "1",
            AGENTSHIELD_PORT: String(port),
            AGENTSHIELD_EXTENSION_ROOT: extensionRoot
        }
    });

    dashboardProcess.stdout.on('data', (data) => {
        outputChannel.append(`[Dashboard] ${data.toString()}`);
    });

    dashboardProcess.stderr.on('data', (data) => {
        outputChannel.append(`[Dashboard] ${data.toString()}`);
    });

    dashboardProcess.on('error', (err) => {
        outputChannel.appendLine(`[!] Dashboard failed to start: ${err.message}`);
        outputChannel.appendLine(`[!] Make sure Python is installed and accessible at: ${pythonPath}`);
        dashboardProcess = null;
    });

    dashboardProcess.on('close', (code) => {
        outputChannel.appendLine(`[*] Dashboard server exited with code: ${code}`);
        dashboardProcess = null;
    });
}

function runAuditor(pythonPath, workspaceRoot, auditorScript, callback) {
    outputChannel.appendLine(`[*] Running AST Auditor on workspace: ${workspaceRoot}`);

    child_process.execFile(pythonPath, [auditorScript], {
        cwd: workspaceRoot,
        env: {
            ...process.env,
            PYTHONUNBUFFERED: "1"
        },
        timeout: 30000
    }, (error, stdout, stderr) => {
        // Clear previous diagnostics
        diagnosticCollection.clear();

        if (stdout) {
            outputChannel.append(`[Auditor] ${stdout}`);
        }

        const regressionMarker = "[!] AgentShield AST Code Auditor detected regressions:";
        if (stderr && stderr.includes(regressionMarker)) {
            const jsonPart = stderr.substring(stderr.indexOf(regressionMarker) + regressionMarker.length).trim();
            try {
                const regressions = JSON.parse(jsonPart);
                const fileDiagnostics = {};

                regressions.forEach(reg => {
                    const filePath = reg.file;
                    const line = Math.max(0, reg.line - 1); // VS Code lines are 0-indexed
                    const col = reg.col || 0;

                    const range = new vscode.Range(line, col, line, col + 25);
                    const msg = `[AgentShield AST Regression] Target: ${reg.target_function}\nMismatches:\n${reg.mismatches.map(m => ` - ${m}`).join('\n')}`;

                    const diag = new vscode.Diagnostic(
                        range,
                        msg,
                        vscode.DiagnosticSeverity.Error
                    );
                    diag.source = 'AgentShield';

                    if (!fileDiagnostics[filePath]) {
                        fileDiagnostics[filePath] = [];
                    }
                    fileDiagnostics[filePath].push(diag);
                });

                Object.keys(fileDiagnostics).forEach(file => {
                    const uri = vscode.Uri.file(file);
                    diagnosticCollection.set(uri, fileDiagnostics[file]);
                });

                vscode.window.showWarningMessage(
                    `AgentShield: Blocked ${Object.keys(fileDiagnostics).length} file(s) with AST regressions.`
                );
            } catch (e) {
                outputChannel.appendLine(`[!] Failed to parse auditor JSON: ${e}. Raw: ${jsonPart.substring(0, 200)}`);
            }
        } else if (stderr) {
            outputChannel.append(`[Auditor STDERR] ${stderr}`);
        }

        if (!stderr || !stderr.includes(regressionMarker)) {
            outputChannel.appendLine("[+] Codebase audit clean. No regressions.");
        }

        if (callback) callback();
    });
}

function deactivate() {
    if (dashboardProcess) {
        outputChannel.appendLine("[*] Deactivating AgentShield: stopping dashboard server...");
        dashboardProcess.kill();
        dashboardProcess = null;
    }
}

module.exports = {
    activate,
    deactivate
};
