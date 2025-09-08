# 🛡️ Web Vulnerability Scanner Pro for VS Code

A professional-grade VS Code extension for comprehensive web application security scanning. Detect vulnerabilities, analyze security posture, and get actionable recommendations without leaving your development environment.

![Version](https://img.shields.io/visual-studio-marketplace/v/pratikacharya.web-vuln-scanner-extension)
![Installs](https://img.shields.io/visual-studio-marketplace/i/pratikacharya.web-vuln-scanner-extension)
![License](https://img.shields.io/badge/license-MIT-green)

---

## � Features

### 🔍 Comprehensive Security Testing
- ✅ **HTTP Security Headers Analysis** - Detect missing or misconfigured security headers
- ✅ **SSL/TLS Configuration Testing** - Validate encryption and certificate security
- ✅ **XSS Vulnerability Detection** - Identify Cross-Site Scripting vulnerabilities
- ✅ **SQL Injection Testing** - Detect database injection vulnerabilities
- ✅ **CSRF Protection Analysis** - Check Cross-Site Request Forgery protections
- ✅ **Directory Traversal Detection** - Find path traversal vulnerabilities
- ✅ **Information Disclosure Testing** - Identify exposed sensitive information
- ✅ **Authentication Bypass Checks** - Test for authentication weaknesses

### 🎯 Advanced Capabilities
- ✅ **Multiple Scan Types** - Quick scans or deep security analysis
- ✅ **Real-time Progress Tracking** - Live updates during scanning
- ✅ **Risk Assessment** - Automated risk scoring and severity classification
- ✅ **Export Functionality** - Save scan results in JSON format
- ✅ **Professional UI** - Tabbed interface with console, vulnerabilities, and summary views
- ✅ **Configurable Settings** - Customize timeout, concurrency, and scan depth

### 🛠️ Developer-Friendly
- ✅ **Integrated Workflow** - Scan directly from VS Code
- ✅ **Multiple Commands** - Command palette integration
- ✅ **Workspace Integration** - Auto-save results to workspace
- ✅ **Detailed Recommendations** - Actionable security advice

---

## 📥 Installation

1. **From VS Code Marketplace:**
   - Open VS Code
   - Go to Extensions (Ctrl+Shift+X)
   - Search for "Web Vulnerability Scanner Pro"
   - Click Install

2. **From VSIX File:**
   ```bash
   code --install-extension web-vuln-scanner-extension-1.0.0.vsix
   ```

---

## 🔧 Usage

### Quick Start

1. **Open the Scanner:**
   - Press `Ctrl+Shift+P` (Cmd+Shift+P on Mac)
   - Type "Web Vulnerability Scanner"
   - Select "🛡️ Web Vulnerability Scanner"

2. **Enter Target URL:**
   - Input the website URL (e.g., `https://example.com`)
   - Choose scan options (Quick Scan, Deep Analysis, Advanced Tests)

3. **Start Scanning:**
   - Click "🚀 Start Scan"
   - Monitor real-time progress
   - Review results in multiple tabs

### Available Commands

| Command | Description |
|---------|-------------|
| `🛡️ Web Vulnerability Scanner` | Open main scanner interface |
| `⚡ Quick Security Scan` | Run fast security assessment |
| `🔍 Deep Security Analysis` | Comprehensive vulnerability analysis |
| `📄 Export Scan Results` | Export results to JSON file |

### Scan Options

- **Quick Scan**: Fast security assessment (5-10 seconds)
- **Deep Analysis**: Comprehensive testing (15-30 seconds)
- **Advanced Tests**: Include specialized vulnerability checks

---

## 📊 Understanding Results

### Vulnerability Severity

| Severity | Description | Risk Level |
|----------|-------------|------------|
| 🚨 **HIGH** | Critical security issues requiring immediate attention | High Risk |
| ⚠️ **MEDIUM** | Important security concerns that should be addressed | Medium Risk |
| 📝 **LOW** | Minor security improvements recommended | Low Risk |

### Risk Score Calculation

- **High Severity**: 10 points each
- **Medium Severity**: 5 points each  
- **Low Severity**: 1 point each

### Risk Categories

- **Low Risk (0-19)**: Good security posture
- **Medium Risk (20-49)**: Some security concerns
- **High Risk (50+)**: Critical security issues

---

## ⚙️ Configuration

Access settings via `File > Preferences > Settings` and search for "Web Vulnerability Scanner":

```json
{
  "webVulnScanner.defaultTimeout": 10000,
  "webVulnScanner.maxConcurrency": 5,
  "webVulnScanner.enableAdvancedScans": true,
  "webVulnScanner.autoSaveResults": false
}
```

### Configuration Options

| Setting | Default | Description |
|---------|---------|-------------|
| `defaultTimeout` | 10000 | Request timeout in milliseconds |
| `maxConcurrency` | 5 | Maximum concurrent requests |
| `enableAdvancedScans` | true | Enable advanced vulnerability detection |
| `autoSaveResults` | false | Automatically save results to workspace |

---

## 🔒 Security Testing Coverage

### HTTP Security Headers
- X-Frame-Options
- X-Content-Type-Options  
- X-XSS-Protection
- Strict-Transport-Security
- Content-Security-Policy
- Referrer-Policy
- Permissions-Policy

### SSL/TLS Security
- Certificate validation
- Protocol security
- HSTS implementation
- Certificate expiration

### Application Security
- Cross-Site Scripting (XSS)
- SQL Injection
- Cross-Site Request Forgery (CSRF)
- Directory Traversal
- Authentication bypass
- Information disclosure

---

## 📄 Export Formats

Results can be exported in JSON format containing:

```json
{
  "scanMetadata": {
    "timestamp": "2024-01-01T12:00:00.000Z",
    "scanner": "Web Vulnerability Scanner Pro",
    "version": "1.0.0"
  },
  "results": {
    "vulnerabilities": [...],
    "summary": {
      "totalVulnerabilities": 5,
      "severityBreakdown": {
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 2
      },
      "riskScore": 25,
      "scanCompleted": "2024-01-01T12:00:30.000Z"
    }
  }
}
```

---

## 🎨 User Interface

### Main Interface
- **Console Tab**: Real-time scan output and logs
- **Vulnerabilities Tab**: Detailed vulnerability listings with recommendations
- **Summary Tab**: Risk assessment and scan statistics

### Visual Indicators
- **Progress Bar**: Real-time scan progress
- **Risk Meter**: Visual risk level representation
- **Severity Colors**: Color-coded vulnerability severity
- **Statistics Dashboard**: Target count, vulnerability count, risk score

---

## 🔧 Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/pratikacharya1234/Web-Vulnerability-Scanner.git
cd Web-Vulnerability-Scanner

# Install dependencies
npm install

# Package extension
vsce package
```

### Dependencies

- `vscode`: VS Code Extension API
- `axios`: HTTP client for web requests
- `cheerio`: HTML parsing and manipulation

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🐛 Issues & Support

- **Bug Reports**: [GitHub Issues](https://github.com/pratikacharya1234/Web-Vulnerability-Scanner/issues)
- **Feature Requests**: [GitHub Discussions](https://github.com/pratikacharya1234/Web-Vulnerability-Scanner/discussions)
- **Documentation**: [Wiki](https://github.com/pratikacharya1234/Web-Vulnerability-Scanner/wiki)

---

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have proper authorization before scanning any web application. The developers are not responsible for any misuse of this tool.

---

## 🙏 Acknowledgments

- VS Code Extension API documentation
- Security testing methodologies from OWASP
- Community feedback and contributions

---

**Happy Scanning! 🛡️**

## 🚀 How to Use

1. Open Command Palette (`Ctrl + Shift + P`)
2. Type: `🛡️ Start Web Vulnerability Scan`
3. Enter your web app or software URL
4. View live scan results directly in the extension panel

---

## 📸 Screenshots

> Add screenshots here if you'd like – just drag them into this section on GitHub, and GitHub will create the Markdown image embed.

---

## ⚙️ Requirements

- VS Code v1.80+
- Internet access (to scan external URLs)

---

## 📦 Installation

- Search for **"Web Vulnerability Scanner"** in the VS Code Marketplace
- Or install manually:
  ```bash
  code --install-extension pratikacharya.web-vuln-scanner-extension
  ---
  
  🧠 Why This Was Built
Web security should be easy and developer-friendly. This extension puts real vulnerability scanning into your editor — with no setup or server required.


📝 License
MIT © Pratik Acharya



---

## ✅ Next Steps (Optional but Powerful)

| Upgrade                          | You want it? |
|----------------------------------|--------------|
| 🎨 Generate `icon.png` logo      | 🖼️ Custom style |
| 📊 Add auto-export as `.html`    | 📁 Save scan result |
| 🤖 AI Suggestions with Gemini    | 💡 Smart fixes |
| 🔄 GitHub Actions auto-release   | 🚀 CI/CD deploy |
| 🌐 GitHub repo & badge setup     | 📦 Developer-friendly |

Just tell me **what you want next** — and I’ll prep it. Want the logo now?
