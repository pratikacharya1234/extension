// Test file for Web Vulnerability Scanner Extension
// This file contains test scenarios to validate the extension functionality

const testScenarios = [
  // Test case 1: Valid HTTPS URL
  {
    name: "Valid HTTPS URL Test",
    url: "https://httpbin.org/",
    expectedVulnerabilities: ["Missing security headers"],
    description: "Test scanning a valid HTTPS endpoint"
  },
  
  // Test case 2: HTTP (insecure) URL
  {
    name: "HTTP Insecure Connection Test",
    url: "http://httpbin.org/",
    expectedVulnerabilities: ["Unencrypted HTTP Connection"],
    description: "Test detection of HTTP instead of HTTPS"
  },
  
  // Test case 3: URL with potential XSS parameters
  {
    name: "XSS Parameter Test", 
    url: "https://httpbin.org/get?search=<script>alert('xss')</script>",
    expectedVulnerabilities: ["URL Parameters Detected"],
    description: "Test detection of potential XSS in URL parameters"
  },
  
  // Test case 4: Invalid URL format
  {
    name: "Invalid URL Test",
    url: "not-a-valid-url",
    expectedResult: "Invalid URL format error",
    description: "Test handling of invalid URL formats"
  },
  
  // Test case 5: URL with missing protocol
  {
    name: "Missing Protocol Test",
    url: "example.com",
    expectedResult: "Invalid URL format error", 
    description: "Test handling of URLs without protocol"
  },
  
  // Test case 6: Localhost testing
  {
    name: "Localhost Test",
    url: "http://localhost:3000",
    expectedResult: "Connection error or scan results",
    description: "Test scanning of local development server"
  }
];

/**
 * Manual Testing Instructions:
 * 
 * 1. Install the extension in VS Code
 * 2. Press Ctrl+Shift+P and run "Web Vulnerability Scanner"
 * 3. Test each scenario above:
 *    - Enter the test URL
 *    - Select appropriate scan options
 *    - Verify expected results
 * 
 * Expected Behaviors:
 * 
 * For Valid URLs:
 * - Progress bar should appear and animate
 * - Console should show real-time scanning status
 * - Vulnerabilities tab should populate with findings
 * - Summary tab should show risk assessment
 * - Export button should become enabled after scan
 * 
 * For Invalid URLs:
 * - Clear error messages should appear
 * - UI should remain responsive
 * - No progress bar should appear
 * 
 * UI Components to Test:
 * - Tab navigation (Console, Vulnerabilities, Summary)
 * - Scan options checkboxes
 * - Button states (disabled during scan)
 * - Progress indicators
 * - Export functionality
 * - Clear results functionality
 * 
 * Performance Expectations:
 * - Quick scans: 5-15 seconds
 * - Deep scans: 15-45 seconds
 * - UI should remain responsive during scans
 * - Memory usage should be reasonable
 */

// Example expected vulnerability structure
const exampleVulnerability = {
  type: "MISSING_HEADER",
  severity: "MEDIUM", // HIGH, MEDIUM, LOW
  title: "Missing X-Frame-Options Header", 
  description: "The application does not set X-Frame-Options header...",
  recommendation: "Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN header.",
  timestamp: "2024-01-01T12:00:00.000Z"
};

// Example expected summary structure
const exampleSummary = {
  totalVulnerabilities: 5,
  severityBreakdown: {
    HIGH: 1,
    MEDIUM: 2, 
    LOW: 2
  },
  riskScore: 25,
  scanCompleted: "2024-01-01T12:00:30.000Z"
};

module.exports = {
  testScenarios,
  exampleVulnerability,
  exampleSummary
};
