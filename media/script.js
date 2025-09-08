(function () {
  const vscode = acquireVsCodeApi();
  
  // DOM elements
  const scanBtn = document.getElementById('scanBtn');
  const exportBtn = document.getElementById('exportBtn');
  const clearBtn = document.getElementById('clearBtn');
  const urlInput = document.getElementById('urlInput');
  const consoleOutput = document.getElementById('consoleOutput');
  const progressSection = document.getElementById('progressSection');
  const progressFill = document.getElementById('progressFill');
  const progressText = document.getElementById('progressText');
  const stats = document.getElementById('stats');
  const vulnList = document.getElementById('vulnList');
  const summaryContent = document.getElementById('summaryContent');
  
  // Scan options
  const quickScan = document.getElementById('quickScan');
  const deepScan = document.getElementById('deepScan');
  const advancedScans = document.getElementById('advancedScans');
  
  // State
  let currentResults = null;
  let isScanning = false;
  let scanCount = 0;
  let totalVulnerabilities = 0;
  let totalRiskScore = 0;

  // Initialize UI
  updateStats();
  setupTabNavigation();

  // Event listeners
  scanBtn.addEventListener('click', startScan);
  exportBtn.addEventListener('click', exportResults);
  clearBtn.addEventListener('click', clearResults);
  
  urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !isScanning) {
      startScan();
    }
  });

  function startScan() {
    const url = urlInput.value.trim();
    
    if (!url) {
      appendToConsole('❌ Please enter a URL to scan.');
      return;
    }

    if (!isValidUrl(url)) {
      appendToConsole('❌ Invalid URL format. Please use http:// or https://');
      return;
    }

    if (isScanning) {
      appendToConsole('⏳ Scan already in progress...');
      return;
    }

    // Prepare scan options
    const options = {
      quickScan: quickScan.checked,
      deepScan: deepScan.checked,
      advancedScans: advancedScans.checked,
      timeout: deepScan.checked ? 15000 : 8000,
      concurrency: deepScan.checked ? 2 : 5
    };

    // Start scan
    appendToConsole(`🚀 Starting ${deepScan.checked ? 'deep' : 'quick'} scan of: ${url}`);
    appendToConsole('📡 Initializing security modules...\n');
    
    showProgress();
    setScanning(true);
    
    vscode.postMessage({ 
      command: 'scan', 
      url: url,
      options: options
    });
  }

  function exportResults() {
    if (!currentResults || !currentResults.vulnerabilities) {
      appendToConsole('❌ No scan results to export.');
      return;
    }
    
    appendToConsole('📄 Exporting scan results...');
    vscode.postMessage({ command: 'export' });
  }

  function clearResults() {
    if (isScanning) {
      appendToConsole('⏳ Cannot clear results while scanning is in progress.');
      return;
    }

    consoleOutput.innerHTML = `
      🔧 Web Vulnerability Scanner Pro initialized<br>
      Ready to scan web applications for security vulnerabilities...<br>
      <br>
      <span class="highlight">Features:</span><br>
      • HTTP Security Headers Analysis<br>
      • SSL/TLS Configuration Testing<br>
      • XSS Vulnerability Detection<br>
      • SQL Injection Testing<br>
      • CSRF Protection Analysis<br>
      • Directory Traversal Detection<br>
      • Information Disclosure Testing<br>
      • Authentication Bypass Checks<br>
      <br>
      Enter a URL to begin scanning...
    `;
    
    vulnList.innerHTML = 'No vulnerabilities detected yet. Run a scan to see results.';
    summaryContent.innerHTML = `
      <div class="summary-card">
        <h3>📊 Scan Summary</h3>
        <p>No scans completed yet.</p>
      </div>
    `;
    
    hideProgress();
    currentResults = null;
    exportBtn.disabled = true;
    
    vscode.postMessage({ command: 'clear' });
  }

  function setScanning(scanning) {
    isScanning = scanning;
    scanBtn.disabled = scanning;
    scanBtn.textContent = scanning ? '⏳ Scanning...' : '🚀 Start Scan';
    urlInput.disabled = scanning;
    
    [quickScan, deepScan, advancedScans].forEach(checkbox => {
      checkbox.disabled = scanning;
    });
  }

  function showProgress() {
    progressSection.style.display = 'block';
    updateProgress(0, 'Initializing scan...');
  }

  function hideProgress() {
    progressSection.style.display = 'none';
  }

  function updateProgress(percent, text) {
    progressFill.style.width = `${percent}%`;
    progressText.textContent = text;
  }

  function appendToConsole(message) {
    const timestamp = new Date().toLocaleTimeString();
    consoleOutput.innerHTML += `<span style="color: #666;">[${timestamp}]</span> ${message}<br>`;
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
  }

  function isValidUrl(string) {
    try {
      new URL(string);
      return string.startsWith('http://') || string.startsWith('https://');
    } catch (_) {
      return false;
    }
  }

  function updateStats() {
    stats.innerHTML = `
      <span class="stat">🎯 Targets: ${scanCount}</span>
      <span class="stat">🔍 Vulnerabilities: ${totalVulnerabilities}</span>
      <span class="stat">⚡ Risk Score: ${totalRiskScore}</span>
    `;
  }

  function displayVulnerabilities(vulnerabilities) {
    if (!vulnerabilities || vulnerabilities.length === 0) {
      vulnList.innerHTML = '<div class="success-text">✅ No vulnerabilities detected! Your application appears secure.</div>';
      return;
    }

    let html = '';
    vulnerabilities.forEach((vuln, index) => {
      const severityClass = vuln.severity.toLowerCase();
      const severityIcon = getSeverityIcon(vuln.severity);
      
      html += `
        <div class="vuln-item ${severityClass}">
          <div class="vuln-title">${severityIcon} ${vuln.title}</div>
          <span class="vuln-severity ${severityClass}">${vuln.severity}</span>
          <div class="vuln-description">${vuln.description}</div>
          ${vuln.recommendation ? `<div class="vuln-recommendation">💡 <strong>Recommendation:</strong> ${vuln.recommendation}</div>` : ''}
        </div>
      `;
    });
    
    vulnList.innerHTML = html;
  }

  function displaySummary(results) {
    const summary = results.summary;
    const vulnerabilities = results.vulnerabilities || [];
    
    const riskLevel = getRiskLevel(summary.riskScore);
    const riskPercentage = Math.min((summary.riskScore / 100) * 100, 100);
    
    summaryContent.innerHTML = `
      <div class="summary-card">
        <h3>📊 Scan Results</h3>
        <p><strong>Total Vulnerabilities:</strong> ${summary.totalVulnerabilities}</p>
        <p><strong>High Risk:</strong> ${summary.severityBreakdown.HIGH}</p>
        <p><strong>Medium Risk:</strong> ${summary.severityBreakdown.MEDIUM}</p>
        <p><strong>Low Risk:</strong> ${summary.severityBreakdown.LOW}</p>
        <p><strong>Scan Completed:</strong> ${new Date(summary.scanCompleted).toLocaleString()}</p>
      </div>
      
      <div class="summary-card">
        <h3>⚡ Risk Assessment</h3>
        <p><strong>Risk Score:</strong> ${summary.riskScore}</p>
        <div class="risk-meter">
          <span>Low</span>
          <div class="risk-bar">
            <div class="risk-fill ${riskLevel}" style="width: ${riskPercentage}%"></div>
          </div>
          <span>High</span>
        </div>
        <p><strong>Risk Level:</strong> <span class="${riskLevel}">${riskLevel.toUpperCase()}</span></p>
        ${getRiskRecommendation(riskLevel)}
      </div>
      
      <div class="summary-card">
        <h3>🎯 Scan Coverage</h3>
        <p>✅ HTTP Security Headers</p>
        <p>✅ SSL/TLS Configuration</p>
        <p>✅ XSS Vulnerabilities</p>
        <p>✅ SQL Injection</p>
        <p>✅ CSRF Protection</p>
        <p>✅ Directory Traversal</p>
        <p>✅ Information Disclosure</p>
        <p>✅ Authentication Bypass</p>
      </div>
    `;
  }

  function getSeverityIcon(severity) {
    switch (severity) {
      case 'HIGH': return '🚨';
      case 'MEDIUM': return '⚠️';
      case 'LOW': return '📝';
      default: return '❓';
    }
  }

  function getRiskLevel(score) {
    if (score >= 50) return 'high';
    if (score >= 20) return 'medium';
    return 'low';
  }

  function getRiskRecommendation(level) {
    switch (level) {
      case 'high':
        return '<p class="error-text">🚨 <strong>Immediate action required!</strong> Critical vulnerabilities detected.</p>';
      case 'medium':
        return '<p class="warning-text">⚠️ <strong>Review and remediate</strong> identified vulnerabilities soon.</p>';
      case 'low':
        return '<p class="success-text">✅ <strong>Good security posture.</strong> Monitor and maintain current practices.</p>';
      default:
        return '<p>No specific recommendations at this time.</p>';
    }
  }

  function setupTabNavigation() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanels = document.querySelectorAll('.tab-panel');
    
    tabButtons.forEach(button => {
      button.addEventListener('click', () => {
        const targetTab = button.getAttribute('data-tab');
        
        // Remove active class from all tabs and panels
        tabButtons.forEach(btn => btn.classList.remove('active'));
        tabPanels.forEach(panel => panel.classList.remove('active'));
        
        // Add active class to clicked tab and corresponding panel
        button.classList.add('active');
        document.getElementById(targetTab).classList.add('active');
      });
    });
  }

  // Handle messages from extension
  window.addEventListener('message', (event) => {
    const { command, results, error, url } = event.data;

    switch (command) {
      case 'scanStarted':
        updateProgress(5, `Connecting to ${url}...`);
        break;

      case 'scanProgress':
        updateProgress(event.data.progress, event.data.status);
        break;

      case 'scanCompleted':
        handleScanCompleted(results);
        break;

      case 'scanError':
        handleScanError(error);
        break;

      case 'cleared':
        appendToConsole('🗑️ Results cleared successfully.');
        break;

      default:
        console.log('Unknown command:', command);
    }
  });

  function handleScanCompleted(results) {
    setScanning(false);
    hideProgress();
    
    currentResults = results;
    const vulnCount = results.vulnerabilities ? results.vulnerabilities.length : 0;
    
    // Update global stats
    scanCount++;
    totalVulnerabilities += vulnCount;
    totalRiskScore += results.summary ? results.summary.riskScore : 0;
    updateStats();
    
    // Display results
    if (vulnCount === 0) {
      appendToConsole('✅ Scan completed successfully!');
      appendToConsole('🛡️ No vulnerabilities detected. Your application appears secure.');
    } else {
      appendToConsole(`🚨 Scan completed! Found ${vulnCount} vulnerabilities:`);
      
      const severityBreakdown = results.summary.severityBreakdown;
      if (severityBreakdown.HIGH > 0) {
        appendToConsole(`   🚨 High: ${severityBreakdown.HIGH}`);
      }
      if (severityBreakdown.MEDIUM > 0) {
        appendToConsole(`   ⚠️ Medium: ${severityBreakdown.MEDIUM}`);
      }
      if (severityBreakdown.LOW > 0) {
        appendToConsole(`   📝 Low: ${severityBreakdown.LOW}`);
      }
      
      appendToConsole(`⚡ Risk Score: ${results.summary.riskScore}`);
      appendToConsole('👆 Check the Vulnerabilities and Summary tabs for detailed analysis.');
    }
    
    // Update UI tabs
    displayVulnerabilities(results.vulnerabilities);
    displaySummary(results);
    
    // Enable export button
    exportBtn.disabled = false;
    
    appendToConsole(`\n📊 Scan completed at ${new Date().toLocaleString()}\n`);
  }

  function handleScanError(error) {
    setScanning(false);
    hideProgress();
    
    appendToConsole(`❌ Scan failed: ${error}`);
    appendToConsole('💡 Please check the URL and try again.');
    
    // Show error in vulnerabilities tab
    vulnList.innerHTML = `
      <div class="vuln-item high">
        <div class="vuln-title">❌ Scan Error</div>
        <span class="vuln-severity high">ERROR</span>
        <div class="vuln-description">The scan could not be completed: ${error}</div>
        <div class="vuln-recommendation">💡 <strong>Recommendation:</strong> Verify the target URL is accessible and try again.</div>
      </div>
    `;
  }

})();
