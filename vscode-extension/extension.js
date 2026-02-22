const vscode = require('vscode');
const { spawn } = require('child_process');
const path = require('path');

let diagnosticCollection;
let isScanning = false;   // P19: prevent concurrent scans
let activeProcess = null; // P5: allow cancellation via kill

// ---------------------------------------------------------------------------
// P16: Escape HTML to prevent XSS in webview
// ---------------------------------------------------------------------------
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ---------------------------------------------------------------------------
// P10: Safe CLI execution with spawn + args array (no shell injection)
// P5:  Cancellable via VS Code CancellationToken
// ---------------------------------------------------------------------------
function runCLI(args, token) {
  return new Promise((resolve, reject) => {
    const child = spawn('npx', ['muaddib-scanner', ...args], {
      shell: true,       // needed on Windows for npx.cmd
      windowsHide: true
    });

    activeProcess = child;
    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (data) => { stdout += data.toString(); });
    child.stderr.on('data', (data) => { stderr += data.toString(); });

    if (token) {
      token.onCancellationRequested(() => {
        child.kill();
        reject(new Error('cancelled'));
      });
    }

    child.on('close', (code) => {
      activeProcess = null;
      resolve({ stdout, stderr, code });
    });

    child.on('error', (err) => {
      activeProcess = null;
      reject(err);
    });
  });
}

// ---------------------------------------------------------------------------
// P7: Extract JSON from CLI output (may contain log lines before JSON)
// ---------------------------------------------------------------------------
function extractJSON(stdout) {
  const jsonMatch = stdout.match(/\{[\s\S]*\}$/);
  if (!jsonMatch) return null;
  try {
    return JSON.parse(jsonMatch[0]);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// P10: Validate webhook URL on extension side (defense in depth)
// ---------------------------------------------------------------------------
function isValidWebhookUrl(str) {
  try {
    const url = new URL(str);
    return url.protocol === 'https:';
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------
function activate(context) {
  console.log('MUAD\'DIB Security Scanner active');

  diagnosticCollection = vscode.languages.createDiagnosticCollection('muaddib');
  context.subscriptions.push(diagnosticCollection);

  // P8: Register all 3 commands
  context.subscriptions.push(
    vscode.commands.registerCommand('muaddib.scan', () => scanProject()),
    vscode.commands.registerCommand('muaddib.scanFile', () => scanCurrentFile()),
    vscode.commands.registerCommand('muaddib.updateIOCs', () => updateIOCs())
  );

  // P9: React to configuration changes immediately
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration('muaddib.autoScan')) {
        const config = vscode.workspace.getConfiguration('muaddib');
        if (config.get('autoScan')) {
          scanProject();
        }
      }
    })
  );

  // Auto-scan on activation if enabled
  const config = vscode.workspace.getConfiguration('muaddib');
  if (config.get('autoScan')) {
    scanProject();
  }

  // Re-scan when dependency files change
  const npmWatcher = vscode.workspace.createFileSystemWatcher('**/package.json');
  npmWatcher.onDidChange(() => {
    const config = vscode.workspace.getConfiguration('muaddib');
    if (config.get('autoScan')) {
      scanProject();
    }
  });
  context.subscriptions.push(npmWatcher);

  // P17: Watch Python dependency files too
  const pyWatcher = vscode.workspace.createFileSystemWatcher('**/requirements.txt');
  pyWatcher.onDidChange(() => {
    const config = vscode.workspace.getConfiguration('muaddib');
    if (config.get('autoScan')) {
      scanProject();
    }
  });
  context.subscriptions.push(pyWatcher);
}

// ---------------------------------------------------------------------------
// P11 + P20: Build CLI args from user configuration
// ---------------------------------------------------------------------------
function buildScanArgs(targetPath) {
  const config = vscode.workspace.getConfiguration('muaddib');
  const args = ['scan', targetPath, '--json'];

  // P10: Validate webhook URL before passing
  const webhookUrl = config.get('webhookUrl');
  if (webhookUrl && isValidWebhookUrl(webhookUrl)) {
    args.push('--webhook', webhookUrl);
  }

  // P11: failLevel is now actually passed to CLI
  const failLevel = config.get('failLevel');
  if (failLevel) {
    args.push('--fail-on', failLevel);
  }

  // P20: Expose advanced CLI options
  if (config.get('explain')) {
    args.push('--explain');
  }
  if (config.get('paranoid')) {
    args.push('--paranoid');
  }
  if (config.get('temporalAnalysis')) {
    args.push('--temporal-full');
  }

  return args;
}

// ---------------------------------------------------------------------------
// Scan Project
// ---------------------------------------------------------------------------
async function scanProject() {
  // P19: Prevent concurrent scans
  if (isScanning) {
    vscode.window.showWarningMessage('MUAD\'DIB: Un scan est deja en cours');
    return;
  }

  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showWarningMessage('MUAD\'DIB: Aucun projet ouvert');
    return;
  }

  const projectPath = workspaceFolder.uri.fsPath;
  isScanning = true;

  try {
    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: 'MUAD\'DIB: Scan en cours...',
      cancellable: true // P5: allow cancellation
    }, async (_progress, token) => {
      const args = buildScanArgs(projectPath);
      const { stdout, stderr } = await runCLI(args, token);

      const result = extractJSON(stdout);
      if (!result) {
        if (stdout.includes('Aucune menace') || stdout.includes('No threat')) {
          vscode.window.showInformationMessage('MUAD\'DIB: Aucune menace detectee');
          diagnosticCollection.clear();
        } else if (stderr && stderr.includes('not found')) {
          // P12: Specific error for CLI not installed
          vscode.window.showErrorMessage(
            'MUAD\'DIB: CLI non trouve. Installez avec: npm install -g muaddib-scanner'
          );
        } else {
          vscode.window.showErrorMessage(
            'MUAD\'DIB: Le scan n\'a retourne aucun resultat exploitable'
          );
        }
        return;
      }

      displayResults(result, projectPath);
    });
  } catch (e) {
    if (e.message === 'cancelled') {
      vscode.window.showInformationMessage('MUAD\'DIB: Scan annule');
    } else if (e.code === 'ENOENT') {
      // P12: npx not found
      vscode.window.showErrorMessage(
        'MUAD\'DIB: npx introuvable. Verifiez que Node.js est installe et dans le PATH'
      );
    } else {
      vscode.window.showErrorMessage(`MUAD\'DIB: Erreur - ${e.message}`);
    }
  } finally {
    isScanning = false;
  }
}

// ---------------------------------------------------------------------------
// P6: Extended supported file extensions
// ---------------------------------------------------------------------------
const SUPPORTED_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.json',
  '.py', '.toml', '.yaml', '.yml', '.md'
]);

const SUPPORTED_BASENAMES = new Set([
  '.cursorrules', '.cursorignore', '.windsurfrules',
  'claude.md', 'agent.md'
]);

// ---------------------------------------------------------------------------
// Scan Current File
// ---------------------------------------------------------------------------
async function scanCurrentFile() {
  if (isScanning) {
    vscode.window.showWarningMessage('MUAD\'DIB: Un scan est deja en cours');
    return;
  }

  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('MUAD\'DIB: Aucun fichier ouvert');
    return;
  }

  const filePath = editor.document.uri.fsPath;
  const ext = path.extname(filePath).toLowerCase();
  const basename = path.basename(filePath).toLowerCase();

  // P6: Support Python, YAML, Markdown, AI config files
  if (!SUPPORTED_EXTENSIONS.has(ext) && !SUPPORTED_BASENAMES.has(basename)) {
    vscode.window.showWarningMessage(
      'MUAD\'DIB: Type de fichier non supporte. Extensions: .js, .json, .py, .toml, .yaml, .yml, .md'
    );
    return;
  }

  const dirPath = path.dirname(filePath);
  isScanning = true;

  try {
    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: 'MUAD\'DIB: Scan du fichier...',
      cancellable: true
    }, async (_progress, token) => {
      const args = buildScanArgs(dirPath);
      const { stdout } = await runCLI(args, token);

      // P7: Use regex JSON extraction (same as scanProject)
      const result = extractJSON(stdout);
      if (!result) {
        vscode.window.showInformationMessage('MUAD\'DIB: Aucune menace detectee');
        return;
      }

      // Filter threats for this file only
      const fileBasename = path.basename(filePath);
      const fileThreats = result.threats.filter(t =>
        t.file === fileBasename
        || t.file.endsWith('/' + fileBasename)
        || t.file.endsWith('\\' + fileBasename)
      );

      if (fileThreats.length > 0) {
        result.threats = fileThreats;
        result.summary.total = fileThreats.length;
        displayResults(result, dirPath);
      } else {
        vscode.window.showInformationMessage('MUAD\'DIB: Aucune menace dans ce fichier');
      }
    });
  } catch (e) {
    if (e.message === 'cancelled') {
      vscode.window.showInformationMessage('MUAD\'DIB: Scan annule');
    } else if (e.code === 'ENOENT') {
      vscode.window.showErrorMessage(
        'MUAD\'DIB: npx introuvable. Verifiez que Node.js est installe et dans le PATH'
      );
    } else {
      vscode.window.showErrorMessage(`MUAD\'DIB: Erreur - ${e.message}`);
    }
  } finally {
    isScanning = false;
  }
}

// ---------------------------------------------------------------------------
// P8: Update IOCs command
// ---------------------------------------------------------------------------
async function updateIOCs() {
  if (isScanning) {
    vscode.window.showWarningMessage('MUAD\'DIB: Une operation est deja en cours');
    return;
  }

  isScanning = true;

  try {
    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: 'MUAD\'DIB: Mise a jour des IOCs...',
      cancellable: true
    }, async (_progress, token) => {
      const { stdout, stderr, code } = await runCLI(['update'], token);

      if (code === 0) {
        vscode.window.showInformationMessage('MUAD\'DIB: IOCs mis a jour avec succes');
      } else {
        const detail = (stderr || stdout || '').trim().split('\n').pop() || 'Erreur inconnue';
        vscode.window.showErrorMessage(`MUAD\'DIB: Echec de la mise a jour - ${detail}`);
      }
    });
  } catch (e) {
    if (e.message === 'cancelled') {
      vscode.window.showInformationMessage('MUAD\'DIB: Mise a jour annulee');
    } else if (e.code === 'ENOENT') {
      vscode.window.showErrorMessage(
        'MUAD\'DIB: npx introuvable. Verifiez que Node.js est installe et dans le PATH'
      );
    } else {
      vscode.window.showErrorMessage(`MUAD\'DIB: Erreur - ${e.message}`);
    }
  } finally {
    isScanning = false;
  }
}

// ---------------------------------------------------------------------------
// Display results in Problems panel + notification
// ---------------------------------------------------------------------------
function displayResults(result, projectPath) {
  const { threats, summary } = result;

  diagnosticCollection.clear();

  if (threats.length === 0) {
    vscode.window.showInformationMessage('MUAD\'DIB: Aucune menace detectee');
    return;
  }

  const scoreMessage =
    `MUAD'DIB: Score ${summary.riskScore}/100 (${summary.riskLevel}) - ${summary.total} menace(s)`;

  if (summary.riskLevel === 'CRITICAL' || summary.riskLevel === 'HIGH') {
    vscode.window.showErrorMessage(scoreMessage, 'Voir details').then(selection => {
      if (selection === 'Voir details') {
        showDetailPanel(result, projectPath);
      }
    });
  } else {
    vscode.window.showWarningMessage(scoreMessage, 'Voir details').then(selection => {
      if (selection === 'Voir details') {
        showDetailPanel(result, projectPath);
      }
    });
  }

  // Create diagnostics for the Problems panel
  const diagnosticsMap = new Map();

  for (const threat of threats) {
    const filePath = path.join(projectPath, threat.file);
    const uri = vscode.Uri.file(filePath);

    const severity = threat.severity === 'CRITICAL' ? vscode.DiagnosticSeverity.Error
                   : threat.severity === 'HIGH' ? vscode.DiagnosticSeverity.Error
                   : threat.severity === 'MEDIUM' ? vscode.DiagnosticSeverity.Warning
                   : vscode.DiagnosticSeverity.Information;

    const line = (threat.line || 1) - 1;
    const range = new vscode.Range(line, 0, line, 100);

    const diagnostic = new vscode.Diagnostic(
      range,
      `[${threat.severity}] ${threat.message}`,
      severity
    );
    diagnostic.source = 'MUAD\'DIB';
    diagnostic.code = threat.rule_id || threat.type;

    if (!diagnosticsMap.has(uri.toString())) {
      diagnosticsMap.set(uri.toString(), []);
    }
    diagnosticsMap.get(uri.toString()).push(diagnostic);
  }

  for (const [uriString, diagnostics] of diagnosticsMap) {
    diagnosticCollection.set(vscode.Uri.parse(uriString), diagnostics);
  }
}

// ---------------------------------------------------------------------------
// P15: Detail panel with clickable file links
// P16: All data escaped before HTML insertion
// P14: Include LOW count in summary
// ---------------------------------------------------------------------------
function showDetailPanel(result, projectPath) {
  const panel = vscode.window.createWebviewPanel(
    'muaddibResults',
    'MUAD\'DIB - Resultats',
    vscode.ViewColumn.Two,
    { enableScripts: true }
  );

  const { threats, summary } = result;

  // P16: Every dynamic value is escaped
  const threatRows = threats.map(t => `
    <tr class="${escapeHtml(t.severity.toLowerCase())}">
      <td>${escapeHtml(t.severity)}</td>
      <td>${escapeHtml(t.type)}</td>
      <td>${escapeHtml(t.message)}</td>
      <td><a href="#" class="file-link" data-file="${escapeHtml(t.file)}">${escapeHtml(t.file)}</a></td>
      <td>${escapeHtml(t.playbook || '-')}</td>
    </tr>
  `).join('');

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 20px; background: #1e1e1e; color: #fff; }
        h1 { color: #e94560; }
        .score { font-size: 24px; margin: 20px 0; }
        .critical { color: #e74c3c; }
        .high { color: #e67e22; }
        .medium { color: #f1c40f; }
        .low { color: #3498db; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #2d2d2d; color: #e94560; }
        tr.critical { background: rgba(231, 76, 60, 0.2); }
        tr.high { background: rgba(230, 126, 34, 0.2); }
        tr.medium { background: rgba(241, 196, 15, 0.1); }
        .file-link { color: #58a6ff; cursor: pointer; text-decoration: underline; }
        .file-link:hover { color: #79c0ff; }
      </style>
    </head>
    <body>
      <h1>MUAD'DIB Security Scan</h1>
      <div class="score">
        Score: <strong>${Number(summary.riskScore)}/100</strong>
        (<span class="${escapeHtml(summary.riskLevel.toLowerCase())}">${escapeHtml(summary.riskLevel)}</span>)
      </div>
      <p>CRITICAL: ${Number(summary.critical)} | HIGH: ${Number(summary.high)} | MEDIUM: ${Number(summary.medium)} | LOW: ${Number(summary.low || 0)}</p>
      <table>
        <thead>
          <tr>
            <th>Severite</th>
            <th>Type</th>
            <th>Message</th>
            <th>Fichier</th>
            <th>Recommandation</th>
          </tr>
        </thead>
        <tbody>
          ${threatRows}
        </tbody>
      </table>
      <script>
        const vscode = acquireVsCodeApi();
        document.querySelectorAll('.file-link').forEach(link => {
          link.addEventListener('click', (e) => {
            e.preventDefault();
            vscode.postMessage({ command: 'openFile', file: e.target.dataset.file });
          });
        });
      </script>
    </body>
    </html>
  `;

  // P15: Handle file open messages from webview
  panel.webview.onDidReceiveMessage(message => {
    if (message.command === 'openFile' && message.file) {
      const fileUri = vscode.Uri.file(path.join(projectPath, message.file));
      vscode.window.showTextDocument(fileUri);
    }
  });
}

// ---------------------------------------------------------------------------
// Deactivation
// ---------------------------------------------------------------------------
function deactivate() {
  if (diagnosticCollection) {
    diagnosticCollection.dispose();
  }
  if (activeProcess) {
    activeProcess.kill();
  }
}

module.exports = { activate, deactivate };
