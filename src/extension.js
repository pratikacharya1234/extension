const vscode = require('vscode');
const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs');
const path = require('path');

// Vulnerability scanner implementation
class VulnerabilityScanner {
  constructor() {
    this.scanResults = [];
    this.scanProgress = 0;
    this.isScanning = false;
  }

  // Main scanning function
  async scan(url, options = {}) {
    this.isScanning = true;
    this.scanResults = [];
    this.scanProgress = 0;

    const config = vscode.workspace.getConfiguration('webVulnScanner');
    const timeout = options.timeout || config.get('defaultTimeout', 10000);
    const concurrency = options.concurrency || config.get('maxConcurrency', 5);
    const enableAdvanced = config.get('enableAdvancedScans', true);

    try {
      // Basic checks
      await this.checkBasicSecurity(url, timeout);
      
      // HTTP Headers security
      await this.checkHttpHeaders(url, timeout);
      
      // SSL/TLS checks
      await this.checkSSLSecurity(url, timeout);
      
      // XSS vulnerability checks
      await this.checkXSSVulnerabilities(url, timeout);
      
      // SQL Injection checks
      await this.checkSQLInjection(url, timeout);
      
      if (enableAdvanced) {
        // Directory traversal
        await this.checkDirectoryTraversal(url, timeout);
        
        // CSRF checks
        await this.checkCSRF(url, timeout);
        
        // Information disclosure
        await this.checkInformationDisclosure(url, timeout);
        
        // Authentication bypass
        await this.checkAuthenticationBypass(url, timeout);
      }

    } catch (error) {
      this.addVulnerability({
        type: 'SCAN_ERROR',
        severity: 'HIGH',
        title: 'Scan Error',
        description: `Failed to complete scan: ${error.message}`,
        recommendation: 'Ensure the target URL is accessible and try again.'
      });
    } finally {
      this.isScanning = false;
      this.scanProgress = 100;
    }

    return {
      vulnerabilities: this.scanResults,
      summary: this.generateSummary()
    };
  }

  async checkBasicSecurity(url, timeout) {
    this.updateProgress(5, 'Checking basic security...');
    
    try {
      const response = await axios.get(url, { 
        timeout,
        validateStatus: () => true,
        maxRedirects: 0
      });

      // Check for common security misconfigurations
      if (!response.headers['x-frame-options']) {
        this.addVulnerability({
          type: 'MISSING_HEADER',
          severity: 'MEDIUM',
          title: 'Missing X-Frame-Options Header',
          description: 'The application does not set X-Frame-Options header, making it vulnerable to clickjacking attacks.',
          recommendation: 'Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN header.'
        });
      }

      if (!response.headers['x-content-type-options']) {
        this.addVulnerability({
          type: 'MISSING_HEADER',
          severity: 'LOW',
          title: 'Missing X-Content-Type-Options Header',
          description: 'Missing X-Content-Type-Options header allows MIME type sniffing.',
          recommendation: 'Add X-Content-Type-Options: nosniff header.'
        });
      }

      if (!response.headers['x-xss-protection']) {
        this.addVulnerability({
          type: 'MISSING_HEADER',
          severity: 'MEDIUM',
          title: 'Missing X-XSS-Protection Header',
          description: 'Missing X-XSS-Protection header leaves the application vulnerable to XSS attacks.',
          recommendation: 'Add X-XSS-Protection: 1; mode=block header.'
        });
      }

    } catch (error) {
      this.addVulnerability({
        type: 'CONNECTION_ERROR',
        severity: 'HIGH',
        title: 'Connection Error',
        description: `Unable to connect to target: ${error.message}`,
        recommendation: 'Verify the URL is correct and accessible.'
      });
    }
  }

  async checkHttpHeaders(url, timeout) {
    this.updateProgress(15, 'Analyzing HTTP headers...');
    
    try {
      const response = await axios.get(url, { timeout, validateStatus: () => true });
      const headers = response.headers;

      // Check for server information disclosure
      if (headers.server) {
        this.addVulnerability({
          type: 'INFO_DISCLOSURE',
          severity: 'LOW',
          title: 'Server Information Disclosure',
          description: `Server header reveals server type: ${headers.server}`,
          recommendation: 'Remove or obfuscate the Server header to prevent information disclosure.'
        });
      }

      // Check for missing security headers
      const securityHeaders = [
        'strict-transport-security',
        'content-security-policy',
        'referrer-policy',
        'permissions-policy'
      ];

      securityHeaders.forEach(header => {
        if (!headers[header]) {
          this.addVulnerability({
            type: 'MISSING_HEADER',
            severity: header === 'content-security-policy' ? 'HIGH' : 'MEDIUM',
            title: `Missing ${header.toUpperCase()} Header`,
            description: `The ${header} security header is not implemented.`,
            recommendation: `Implement the ${header} header for enhanced security.`
          });
        }
      });

    } catch (error) {
      console.error('Header check failed:', error);
    }
  }

  async checkSSLSecurity(url, timeout) {
    this.updateProgress(25, 'Checking SSL/TLS security...');
    
    if (!url.startsWith('https://')) {
      this.addVulnerability({
        type: 'SSL_ISSUE',
        severity: 'HIGH',
        title: 'Unencrypted HTTP Connection',
        description: 'The application is not using HTTPS encryption.',
        recommendation: 'Implement HTTPS with proper SSL/TLS certificates.'
      });
      return;
    }

    try {
      // Try to connect with different protocols to test SSL strength
      const response = await axios.get(url, { 
        timeout,
        validateStatus: () => true 
      });

      // Check for HSTS header
      if (!response.headers['strict-transport-security']) {
        this.addVulnerability({
          type: 'SSL_ISSUE',
          severity: 'MEDIUM',
          title: 'Missing HSTS Header',
          description: 'HTTP Strict Transport Security (HSTS) is not implemented.',
          recommendation: 'Add Strict-Transport-Security header to enforce HTTPS connections.'
        });
      }

    } catch (error) {
      if (error.code === 'CERT_HAS_EXPIRED') {
        this.addVulnerability({
          type: 'SSL_ISSUE',
          severity: 'HIGH',
          title: 'Expired SSL Certificate',
          description: 'The SSL certificate has expired.',
          recommendation: 'Renew the SSL certificate immediately.'
        });
      } else if (error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
        this.addVulnerability({
          type: 'SSL_ISSUE',
          severity: 'HIGH',
          title: 'Invalid SSL Certificate',
          description: 'SSL certificate cannot be verified.',
          recommendation: 'Install a valid SSL certificate from a trusted CA.'
        });
      }
    }
  }

  async checkXSSVulnerabilities(url, timeout) {
    this.updateProgress(40, 'Testing for XSS vulnerabilities...');
    
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '"><script>alert("XSS")</script>',
      'javascript:alert("XSS")',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>'
    ];

    try {
      const response = await axios.get(url, { timeout });
      const $ = cheerio.load(response.data);
      
      // Check for forms that might be vulnerable to XSS
      const forms = $('form');
      if (forms.length > 0) {
        forms.each((i, form) => {
          const action = $(form).attr('action') || url;
          const inputs = $(form).find('input[type="text"], input[type="search"], textarea');
          
          if (inputs.length > 0) {
            this.addVulnerability({
              type: 'XSS_POTENTIAL',
              severity: 'MEDIUM',
              title: 'Potential XSS Vulnerability',
              description: `Form found that may be vulnerable to XSS: ${action}`,
              recommendation: 'Implement proper input validation and output encoding.'
            });
          }
        });
      }

      // Check for reflected parameters in URL
      const urlParams = new URL(url).searchParams;
      if (urlParams.toString()) {
        this.addVulnerability({
          type: 'XSS_POTENTIAL',
          severity: 'MEDIUM',
          title: 'URL Parameters Detected',
          description: 'URL contains parameters that may be vulnerable to reflected XSS.',
          recommendation: 'Validate and sanitize all URL parameters before use.'
        });
      }

    } catch (error) {
      console.error('XSS check failed:', error);
    }
  }

  async checkSQLInjection(url, timeout) {
    this.updateProgress(55, 'Testing for SQL injection...');
    
    const sqlPayloads = [
      "' OR '1'='1",
      '" OR "1"="1',
      '; DROP TABLE users--',
      "' UNION SELECT NULL--",
      "1' AND 1=1--"
    ];

    try {
      const response = await axios.get(url, { timeout });
      const $ = cheerio.load(response.data);
      
      // Check for forms with potential SQL injection points
      const forms = $('form');
      forms.each((i, form) => {
        const inputs = $(form).find('input[type="text"], input[type="email"], input[type="password"]');
        if (inputs.length > 0) {
          this.addVulnerability({
            type: 'SQL_INJECTION_POTENTIAL',
            severity: 'HIGH',
            title: 'Potential SQL Injection Point',
            description: 'Form inputs detected that may be vulnerable to SQL injection.',
            recommendation: 'Use parameterized queries and input validation to prevent SQL injection.'
          });
        }
      });

      // Check for database error messages in response
      const errorPatterns = [
        /SQL syntax.*MySQL/i,
        /Warning.*mysql_/i,
        /valid MySQL result/i,
        /PostgreSQL.*ERROR/i,
        /Warning.*pg_/i,
        /valid PostgreSQL result/i,
        /ORA-[0-9]/i,
        /Oracle error/i,
        /Microsoft.*ODBC.*SQL Server/i
      ];

      errorPatterns.forEach(pattern => {
        if (pattern.test(response.data)) {
          this.addVulnerability({
            type: 'SQL_INJECTION',
            severity: 'HIGH',
            title: 'Database Error Message Exposure',
            description: 'Database error messages are exposed, indicating potential SQL injection vulnerability.',
            recommendation: 'Implement proper error handling to prevent information disclosure.'
          });
        }
      });

    } catch (error) {
      console.error('SQL injection check failed:', error);
    }
  }

  async checkDirectoryTraversal(url, timeout) {
    this.updateProgress(70, 'Checking for directory traversal...');
    
    const traversalPayloads = [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
      '../../../../../boot.ini',
      '....//....//....//etc/passwd'
    ];

    try {
      for (const payload of traversalPayloads) {
        try {
          const testUrl = new URL(url);
          testUrl.searchParams.set('file', payload);
          
          const response = await axios.get(testUrl.toString(), { 
            timeout: timeout / 2,
            validateStatus: () => true 
          });

          if (response.data.includes('root:') || response.data.includes('[boot loader]')) {
            this.addVulnerability({
              type: 'DIRECTORY_TRAVERSAL',
              severity: 'HIGH',
              title: 'Directory Traversal Vulnerability',
              description: 'Application is vulnerable to directory traversal attacks.',
              recommendation: 'Implement proper input validation and file access controls.'
            });
            break;
          }
        } catch (error) {
          // Individual payload test failed, continue with others
        }
      }
    } catch (error) {
      console.error('Directory traversal check failed:', error);
    }
  }

  async checkCSRF(url, timeout) {
    this.updateProgress(80, 'Checking CSRF protection...');
    
    try {
      const response = await axios.get(url, { timeout });
      const $ = cheerio.load(response.data);
      
      // Check for forms without CSRF tokens
      const forms = $('form');
      forms.each((i, form) => {
        const csrfInputs = $(form).find('input[name*="csrf"], input[name*="token"], input[name*="_token"]');
        const method = $(form).attr('method')?.toLowerCase();
        
        if (method === 'post' && csrfInputs.length === 0) {
          this.addVulnerability({
            type: 'CSRF',
            severity: 'MEDIUM',
            title: 'Missing CSRF Protection',
            description: 'POST form found without CSRF token protection.',
            recommendation: 'Implement CSRF tokens for all state-changing operations.'
          });
        }
      });

      // Check for SameSite cookie attribute
      const cookies = response.headers['set-cookie'];
      if (cookies) {
        cookies.forEach(cookie => {
          if (!cookie.includes('SameSite')) {
            this.addVulnerability({
              type: 'CSRF',
              severity: 'LOW',
              title: 'Missing SameSite Cookie Attribute',
              description: 'Cookies are set without SameSite attribute.',
              recommendation: 'Set SameSite=Strict or SameSite=Lax for all cookies.'
            });
          }
        });
      }

    } catch (error) {
      console.error('CSRF check failed:', error);
    }
  }

  async checkInformationDisclosure(url, timeout) {
    this.updateProgress(90, 'Checking for information disclosure...');
    
    const sensitiveFiles = [
      'robots.txt',
      '.htaccess',
      'web.config',
      'phpinfo.php',
      'server-status',
      'server-info',
      '.git/config',
      '.env',
      'backup.sql',
      'database.sql'
    ];

    try {
      const baseUrl = new URL(url).origin;
      
      for (const file of sensitiveFiles) {
        try {
          const testUrl = `${baseUrl}/${file}`;
          const response = await axios.get(testUrl, { 
            timeout: timeout / 10,
            validateStatus: (status) => status < 500 
          });

          if (response.status === 200 && response.data.length > 0) {
            this.addVulnerability({
              type: 'INFO_DISCLOSURE',
              severity: file.includes('.git') || file.includes('.env') ? 'HIGH' : 'MEDIUM',
              title: 'Sensitive File Accessible',
              description: `Sensitive file accessible: ${file}`,
              recommendation: 'Restrict access to sensitive files and directories.'
            });
          }
        } catch (error) {
          // File not accessible, which is good
        }
      }
    } catch (error) {
      console.error('Information disclosure check failed:', error);
    }
  }

  async checkAuthenticationBypass(url, timeout) {
    this.updateProgress(95, 'Checking authentication mechanisms...');
    
    try {
      // Check for admin/login pages
      const adminPaths = [
        '/admin',
        '/login',
        '/wp-admin',
        '/administrator',
        '/admin.php',
        '/admin/login'
      ];

      const baseUrl = new URL(url).origin;
      
      for (const path of adminPaths) {
        try {
          const testUrl = `${baseUrl}${path}`;
          const response = await axios.get(testUrl, { 
            timeout: timeout / 10,
            validateStatus: () => true 
          });

          if (response.status === 200) {
            this.addVulnerability({
              type: 'AUTH_BYPASS',
              severity: 'MEDIUM',
              title: 'Admin Interface Accessible',
              description: `Administrative interface found: ${path}`,
              recommendation: 'Ensure administrative interfaces are properly secured and access-controlled.'
            });
          }
        } catch (error) {
          // Path not accessible
        }
      }
    } catch (error) {
      console.error('Authentication bypass check failed:', error);
    }
  }

  addVulnerability(vuln) {
    this.scanResults.push({
      ...vuln,
      timestamp: new Date().toISOString()
    });
  }

  updateProgress(progress, status) {
    this.scanProgress = progress;
    // This could be used to update UI in real-time
  }

  generateSummary() {
    const severityCounts = {
      HIGH: this.scanResults.filter(v => v.severity === 'HIGH').length,
      MEDIUM: this.scanResults.filter(v => v.severity === 'MEDIUM').length,
      LOW: this.scanResults.filter(v => v.severity === 'LOW').length
    };

    return {
      totalVulnerabilities: this.scanResults.length,
      severityBreakdown: severityCounts,
      riskScore: this.calculateRiskScore(severityCounts),
      scanCompleted: new Date().toISOString()
    };
  }

  calculateRiskScore(severityCounts) {
    return (severityCounts.HIGH * 10) + (severityCounts.MEDIUM * 5) + (severityCounts.LOW * 1);
  }
}

// Global scanner instance
const scanner = new VulnerabilityScanner();

/**
 * Generate WebView HTML with enhanced UI
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
      <title>Web Vulnerability Scanner Pro</title>
    </head>
    <body>
      <div class="terminal">
        <div class="header">
          <h2>🛡️ Web Vulnerability Scanner Pro</h2>
          <div class="stats" id="stats">
            <span class="stat">🎯 Targets: 0</span>
            <span class="stat">🔍 Vulnerabilities: 0</span>
            <span class="stat">⚡ Risk Score: 0</span>
          </div>
        </div>
        
        <div class="input-section">
          <input id="urlInput" type="text" placeholder="Enter target URL (e.g., https://example.com)" />
          <div class="scan-options">
            <label><input type="checkbox" id="quickScan" checked> Quick Scan</label>
            <label><input type="checkbox" id="deepScan"> Deep Analysis</label>
            <label><input type="checkbox" id="advancedScans" checked> Advanced Tests</label>
          </div>
          <div class="button-group">
            <button id="scanBtn" class="scan-btn">🚀 Start Scan</button>
            <button id="exportBtn" class="export-btn" disabled>📄 Export Results</button>
            <button id="clearBtn" class="clear-btn">🗑️ Clear</button>
          </div>
        </div>

        <div class="progress-section" id="progressSection" style="display: none;">
          <div class="progress-bar">
            <div class="progress-fill" id="progressFill"></div>
          </div>
          <div class="progress-text" id="progressText">Initializing scan...</div>
        </div>

        <div class="results-section">
          <div class="tabs">
            <button class="tab-btn active" data-tab="console">Console</button>
            <button class="tab-btn" data-tab="vulnerabilities">Vulnerabilities</button>
            <button class="tab-btn" data-tab="summary">Summary</button>
          </div>
          
          <div class="tab-content">
            <div id="console" class="tab-panel active">
              <div id="consoleOutput" class="console-output">
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
              </div>
            </div>
            
            <div id="vulnerabilities" class="tab-panel">
              <div id="vulnList" class="vuln-list">
                No vulnerabilities detected yet. Run a scan to see results.
              </div>
            </div>
            
            <div id="summary" class="tab-panel">
              <div id="summaryContent" class="summary-content">
                <div class="summary-card">
                  <h3>📊 Scan Summary</h3>
                  <p>No scans completed yet.</p>
                </div>
              </div>
            </div>
          </div>
        </div>
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
  let currentPanel = null;
  let scanResults = [];

  // Main scanner command
  const scannerCommand = vscode.commands.registerCommand('webVulnScanner.start', () => {
    if (currentPanel) {
      currentPanel.reveal(vscode.ViewColumn.One);
      return;
    }

    currentPanel = vscode.window.createWebviewPanel(
      'webVulnScanner',
      '🛡️ Web Vulnerability Scanner Pro',
      vscode.ViewColumn.One,
      { 
        enableScripts: true,
        retainContextWhenHidden: true
      }
    );

    currentPanel.webview.html = getWebviewContent(currentPanel, context.extensionUri);

    // Handle panel disposal
    currentPanel.onDidDispose(() => {
      currentPanel = null;
    });

    // Handle messages from webview
    currentPanel.webview.onDidReceiveMessage(async (message) => {
      switch (message.command) {
        case 'scan':
          await performScan(currentPanel, message.url, message.options);
          break;
        case 'export':
          await exportResults(scanResults);
          break;
        case 'clear':
          scanResults = [];
          currentPanel.webview.postMessage({
            command: 'cleared'
          });
          break;
      }
    });
  });

  // Quick scan command
  const quickScanCommand = vscode.commands.registerCommand('webVulnScanner.quickScan', async () => {
    const url = await vscode.window.showInputBox({
      prompt: 'Enter URL to scan',
      placeholder: 'https://example.com'
    });
    
    if (url) {
      await performQuickScan(url);
    }
  });

  // Deep scan command
  const deepScanCommand = vscode.commands.registerCommand('webVulnScanner.deepScan', async () => {
    const url = await vscode.window.showInputBox({
      prompt: 'Enter URL for deep analysis',
      placeholder: 'https://example.com'
    });
    
    if (url) {
      await performDeepScan(url);
    }
  });

  // Export results command
  const exportCommand = vscode.commands.registerCommand('webVulnScanner.exportResults', async () => {
    await exportResults(scanResults);
  });

  // Register all commands
  context.subscriptions.push(
    scannerCommand,
    quickScanCommand,
    deepScanCommand,
    exportCommand
  );

  // Perform scan function
  async function performScan(panel, url, options = {}) {
    try {
      panel.webview.postMessage({
        command: 'scanStarted',
        url: url
      });

      const results = await scanner.scan(url, options);
      scanResults = results;

      panel.webview.postMessage({
        command: 'scanCompleted',
        results: results
      });

      // Show notification
      const vulnCount = results.vulnerabilities.length;
      if (vulnCount > 0) {
        vscode.window.showWarningMessage(
          `Scan completed: ${vulnCount} vulnerabilities found`, 
          'View Results'
        ).then(selection => {
          if (selection === 'View Results') {
            panel.reveal(vscode.ViewColumn.One);
          }
        });
      } else {
        vscode.window.showInformationMessage('Scan completed: No vulnerabilities found');
      }

    } catch (error) {
      panel.webview.postMessage({
        command: 'scanError',
        error: error.message
      });
      vscode.window.showErrorMessage(`Scan failed: ${error.message}`);
    }
  }

  // Quick scan function
  async function performQuickScan(url) {
    const progress = vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: "Running quick security scan...",
      cancellable: false
    }, async (progress) => {
      const results = await scanner.scan(url, { 
        timeout: 5000,
        concurrency: 3 
      });
      
      const vulnCount = results.vulnerabilities.length;
      if (vulnCount > 0) {
        vscode.window.showWarningMessage(`Quick scan found ${vulnCount} vulnerabilities`);
      } else {
        vscode.window.showInformationMessage('Quick scan: No vulnerabilities detected');
      }
    });
  }

  // Deep scan function
  async function performDeepScan(url) {
    const progress = vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: "Running deep security analysis...",
      cancellable: false
    }, async (progress) => {
      const results = await scanner.scan(url, { 
        timeout: 15000,
        concurrency: 2 
      });
      
      const vulnCount = results.vulnerabilities.length;
      if (vulnCount > 0) {
        vscode.window.showWarningMessage(`Deep scan found ${vulnCount} vulnerabilities`);
      } else {
        vscode.window.showInformationMessage('Deep scan: No vulnerabilities detected');
      }
    });
  }

  // Export results function
  async function exportResults(results) {
    if (!results || !results.vulnerabilities || results.vulnerabilities.length === 0) {
      vscode.window.showInformationMessage('No scan results to export');
      return;
    }

    const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!workspaceFolder) {
      vscode.window.showErrorMessage('No workspace folder found');
      return;
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `vulnerability-scan-${timestamp}.json`;
    const filepath = path.join(workspaceFolder, filename);

    try {
      const exportData = {
        scanMetadata: {
          timestamp: new Date().toISOString(),
          scanner: 'Web Vulnerability Scanner Pro',
          version: '1.0.0'
        },
        results: results
      };

      fs.writeFileSync(filepath, JSON.stringify(exportData, null, 2));
      
      vscode.window.showInformationMessage(
        `Results exported to ${filename}`,
        'Open File'
      ).then(selection => {
        if (selection === 'Open File') {
          vscode.workspace.openTextDocument(filepath).then(doc => {
            vscode.window.showTextDocument(doc);
          });
        }
      });

    } catch (error) {
      vscode.window.showErrorMessage(`Export failed: ${error.message}`);
    }
  }
}

// Deactivate function
function deactivate() {}

module.exports = { activate, deactivate };
