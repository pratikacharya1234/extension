const vscode = require('vscode');
const scanner = require('web-vuln-scanner');

/**
 * Generate WebView HTML with secure resource loading
 */
function getWebviewContent(panel, extensionUri) {
  const styleUri = panel.webview.asWebviewUri(
    vscode.Uri.joinPath(extensionUri, 'media', 'style.css')
  );
  const scriptUri = panel.webview.asWebviewUri(
    vscode.Uri.joinPath(extensionUri, 'media', 'script.js')
  );

  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <link href="${styleUri}" rel="stylesheet">
      <title>Web Vulnerability Scanner</title>
    </head>
    <body>
      <div class="terminal">
        <h2>🛡️ Web Vulnerability Scanner</h2>
        <input id="urlInput" type="text" placeholder="Enter your web app URL (e.g. https://example.com)" />
        <button id="scanBtn">Start Scan</button>
        <div id="consoleOutput" class="console-output">Waiting for input...</div>
      </div>
      <script src="${scriptUri}"></script>
    </body>
    </html>
  `;
}

/**
 * Activate the extension
 */
function activate(context) {
  const disposable = vscode.commands.registerCommand('webVulnScanner.start', () => {
    const panel = vscode.window.createWebviewPanel(
      'webVulnScanner',
      '🛡️ Web Vulnerability Scanner',
      vscode.ViewColumn.One,
      { enableScripts: true }
    );

    // ✅ Provide the extensionUri to support loading CSS/JS
    panel.webview.html = getWebviewContent(panel, context.extensionUri);

    // 📩 Handle messages from the WebView
    panel.webview.onDidReceiveMessage(async (message) => {
      if (message.command === 'scan') {
        try {
          const results = await scanner.scan(message.url, {
            timeout: 8000,
            depth: 1,
            concurrency: 3,
            scanModules: ['headers', 'ssl', 'xss']
          });

          panel.webview.postMessage({
            command: 'result',
            data: results.vulnerabilities
          });
        } catch (error) {
          panel.webview.postMessage({
            command: 'error',
            message: error.message
          });
        }
      }
    });
  });

  context.subscriptions.push(disposable);
}

module.exports = { activate };
