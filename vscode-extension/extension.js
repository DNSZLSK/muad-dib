const vscode = require('vscode');
const { exec } = require('child_process');
const path = require('path');

let diagnosticCollection;

function activate(context) {
  console.log('MUAD\'DIB Security Scanner active');

  // Collection de diagnostics pour afficher les erreurs
  diagnosticCollection = vscode.languages.createDiagnosticCollection('muaddib');
  context.subscriptions.push(diagnosticCollection);

  // Commande: Scanner le projet
  const scanCommand = vscode.commands.registerCommand('muaddib.scan', async () => {
    await scanProject();
  });
  context.subscriptions.push(scanCommand);

  // Commande: Scanner le fichier actuel
  const scanFileCommand = vscode.commands.registerCommand('muaddib.scanFile', async () => {
    await scanCurrentFile();
  });
  context.subscriptions.push(scanFileCommand);

  // Auto-scan a l'ouverture si active
  const config = vscode.workspace.getConfiguration('muaddib');
  if (config.get('autoScan')) {
    scanProject();
  }

  // Re-scan quand package.json change
  const watcher = vscode.workspace.createFileSystemWatcher('**/package.json');
  watcher.onDidChange(() => {
    const config = vscode.workspace.getConfiguration('muaddib');
    if (config.get('autoScan')) {
      scanProject();
    }
  });
  context.subscriptions.push(watcher);
}

async function scanProject() {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showWarningMessage('MUAD\'DIB: Aucun projet ouvert');
    return;
  }

  const projectPath = workspaceFolder.uri.fsPath;

  vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: 'MUAD\'DIB: Scan en cours...',
    cancellable: false
  }, async () => {
    return new Promise((resolve) => {
      const config = vscode.workspace.getConfiguration('muaddib');
      const webhookUrl = config.get('webhookUrl');
      const failLevel = config.get('failLevel');

      let cmd = `npx muaddib-scanner scan "${projectPath}" --json`;
      if (webhookUrl) {
        cmd += ` --webhook "${webhookUrl}"`;
      }

exec(cmd, { maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
        try {
          // Extraire uniquement le JSON du stdout (ignorer les logs avant)
          const jsonMatch = stdout.match(/\{[\s\S]*\}$/);
          
          if (!jsonMatch) {
            // Pas de JSON = scan propre ou erreur
            if (stdout.includes('Aucune menace') || stdout.includes('No threat')) {
              vscode.window.showInformationMessage('MUAD\'DIB: Aucune menace detectee');
              diagnosticCollection.clear();
            }
            resolve();
            return;
          }
          
          const result = JSON.parse(jsonMatch[0]);
          displayResults(result, projectPath);
        } catch (e) {
          if (stdout.includes('Aucune menace') || stdout.includes('No threat')) {
            vscode.window.showInformationMessage('MUAD\'DIB: Aucune menace detectee');
            diagnosticCollection.clear();
          } else {
            vscode.window.showErrorMessage(`MUAD\'DIB: Erreur de scan - ${e.message}`);
          }
        }
        resolve();
      });
    });
  });
}

async function scanCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('MUAD\'DIB: Aucun fichier ouvert');
    return;
  }

  const filePath = editor.document.uri.fsPath;
  if (!filePath.endsWith('.js') && !filePath.endsWith('.json')) {
    vscode.window.showWarningMessage('MUAD\'DIB: Seuls les fichiers JS et JSON sont scannes');
    return;
  }

  const dirPath = path.dirname(filePath);
  
  vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: 'MUAD\'DIB: Scan du fichier...',
    cancellable: false
  }, async () => {
    return new Promise((resolve) => {
      exec(`npx muaddib-scanner scan "${dirPath}" --json`, { maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
        try {
          const result = JSON.parse(stdout);
          // Filtrer les menaces pour ce fichier seulement
          const fileThreats = result.threats.filter(t => 
            t.file === path.basename(filePath) || t.file.includes(path.basename(filePath))
          );
          if (fileThreats.length > 0) {
            result.threats = fileThreats;
            result.summary.total = fileThreats.length;
            displayResults(result, dirPath);
          } else {
            vscode.window.showInformationMessage('MUAD\'DIB: Aucune menace dans ce fichier');
          }
        } catch (e) {
          vscode.window.showInformationMessage('MUAD\'DIB: Aucune menace detectee');
        }
        resolve();
      });
    });
  });
}

function displayResults(result, projectPath) {
  const { threats, summary } = result;

  // Clear previous diagnostics
  diagnosticCollection.clear();

  if (threats.length === 0) {
    vscode.window.showInformationMessage('MUAD\'DIB: Aucune menace detectee');
    return;
  }

  // Afficher le score
  const scoreMessage = `MUAD'DIB: Score ${summary.riskScore}/100 (${summary.riskLevel}) - ${summary.total} menace(s)`;
  
  if (summary.riskLevel === 'CRITICAL' || summary.riskLevel === 'HIGH') {
    vscode.window.showErrorMessage(scoreMessage, 'Voir details').then(selection => {
      if (selection === 'Voir details') {
        showDetailPanel(result);
      }
    });
  } else {
    vscode.window.showWarningMessage(scoreMessage, 'Voir details').then(selection => {
      if (selection === 'Voir details') {
        showDetailPanel(result);
      }
    });
  }

  // Creer les diagnostics pour chaque menace
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

  // Appliquer les diagnostics
  for (const [uriString, diagnostics] of diagnosticsMap) {
    diagnosticCollection.set(vscode.Uri.parse(uriString), diagnostics);
  }
}

function showDetailPanel(result) {
  const panel = vscode.window.createWebviewPanel(
    'muaddibResults',
    'MUAD\'DIB - Resultats',
    vscode.ViewColumn.Two,
    { enableScripts: true }
  );

  const { threats, summary } = result;

  const threatRows = threats.map(t => `
    <tr class="${t.severity.toLowerCase()}">
      <td>${t.severity}</td>
      <td>${t.type}</td>
      <td>${t.message}</td>
      <td>${t.file}</td>
      <td>${t.playbook || '-'}</td>
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
      </style>
    </head>
    <body>
      <h1>MUAD'DIB Security Scan</h1>
      <div class="score">
        Score: <strong>${summary.riskScore}/100</strong> 
        (<span class="${summary.riskLevel.toLowerCase()}">${summary.riskLevel}</span>)
      </div>
      <p>CRITICAL: ${summary.critical} | HIGH: ${summary.high} | MEDIUM: ${summary.medium}</p>
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
    </body>
    </html>
  `;
}

function deactivate() {
  if (diagnosticCollection) {
    diagnosticCollection.dispose();
  }
}

module.exports = { activate, deactivate };