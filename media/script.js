(function () {
  const vscode = acquireVsCodeApi();
  const scanBtn = document.getElementById('scanBtn');
  const urlInput = document.getElementById('urlInput');
  const consoleOutput = document.getElementById('consoleOutput');

  scanBtn.addEventListener('click', () => {
    const url = urlInput.value.trim();
    if (!url.startsWith("http")) {
      consoleOutput.textContent = "❌ Invalid URL. Must start with http or https.";
      return;
    }

    consoleOutput.textContent = `🔍 Scanning ${url}...\n`;
    vscode.postMessage({ command: 'scan', url });
  });

  window.addEventListener('message', (event) => {
    const { command, data, message } = event.data;

    if (command === 'result') {
      if (!data || data.length === 0) {
        consoleOutput.textContent += "\n✅ No critical vulnerabilities found.";
        return;
      }

      consoleOutput.textContent += `\n🚨 ${data.length} vulnerabilities found:\n`;

      data.forEach((vuln, i) => {
        consoleOutput.textContent += `\n[${i + 1}] 🔻 ${vuln.name}\n`;
        consoleOutput.textContent += `  ⚠️ ${vuln.description}\n`;
        consoleOutput.textContent += `  🛠️ Recommendation: ${vuln.recommendation || "N/A"}\n`;
      });
    }

    if (command === 'error') {
      consoleOutput.textContent += `\n❌ Error: ${message}`;
    }
  });
})();
