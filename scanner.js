// Core security scanner engine — no LLM needed, pure pattern matching
// Detects: secrets, injection, agent vulns, unicode attacks, dependency issues

const SEVERITY = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'info' };

const SECRET_PATTERNS = [
  { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})['"`]/gi, name: 'API Key', severity: SEVERITY.CRITICAL },
  { pattern: /(?:secret|password|passwd|pwd)\s*[:=]\s*['"`]([^'"`\s]{8,})['"`]/gi, name: 'Hardcoded Secret', severity: SEVERITY.CRITICAL },
  { pattern: /sk-[a-zA-Z0-9]{32,}/g, name: 'OpenAI API Key', severity: SEVERITY.CRITICAL },
  { pattern: /sk-ant-api[a-zA-Z0-9\-_]{40,}/g, name: 'Anthropic API Key', severity: SEVERITY.CRITICAL },
  { pattern: /ghp_[a-zA-Z0-9]{36}/g, name: 'GitHub PAT', severity: SEVERITY.CRITICAL },
  { pattern: /glpat-[a-zA-Z0-9\-_]{20,}/g, name: 'GitLab PAT', severity: SEVERITY.CRITICAL },
  { pattern: /xox[bpors]-[a-zA-Z0-9\-]{10,}/g, name: 'Slack Token', severity: SEVERITY.CRITICAL },
  { pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, name: 'Private Key', severity: SEVERITY.CRITICAL },
  { pattern: /AKIA[0-9A-Z]{16}/g, name: 'AWS Access Key', severity: SEVERITY.CRITICAL },
  { pattern: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, name: 'JWT Token', severity: SEVERITY.HIGH },
];

const INJECTION_PATTERNS = [
  { pattern: /eval\s*\(/g, name: 'eval() usage', severity: SEVERITY.HIGH, desc: 'Dynamic code execution — potential RCE if user input reaches eval' },
  { pattern: /new\s+Function\s*\(/g, name: 'Function constructor', severity: SEVERITY.HIGH, desc: 'Dynamic function creation — equivalent to eval' },
  { pattern: /child_process|exec\s*\(|execSync|spawn\s*\(/g, name: 'Command execution', severity: SEVERITY.HIGH, desc: 'Shell command execution — check for user input in command strings' },
  { pattern: /innerHTML\s*=/g, name: 'innerHTML assignment', severity: SEVERITY.MEDIUM, desc: 'DOM XSS risk if user content is assigned to innerHTML' },
  { pattern: /\$\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE|DROP)/gi, name: 'SQL injection risk', severity: SEVERITY.HIGH, desc: 'Template literal in SQL query — use parameterized queries' },
  { pattern: /document\.write\s*\(/g, name: 'document.write', severity: SEVERITY.MEDIUM, desc: 'Can enable XSS if writing user-controlled content' },
];

const AGENT_PATTERNS = [
  { pattern: /system[_\s]?prompt|system[_\s]?message/gi, name: 'System prompt exposed', severity: SEVERITY.MEDIUM, desc: 'System prompt in client-accessible code — prompt injection risk' },
  { pattern: /(?:tool|function)[_\s]?call.*user[_\s]?input/gi, name: 'Unvalidated tool call', severity: SEVERITY.HIGH, desc: 'Tool/function calls with user input — validate and sanitize' },
  { pattern: /(?:allow|enable).*(?:code[_\s]?execution|shell|eval)/gi, name: 'Code execution enabled', severity: SEVERITY.CRITICAL, desc: 'Agent has code execution capability — ensure sandboxing' },
  { pattern: /(?:fetch|axios|request)\s*\(.*(?:user|input|param)/gi, name: 'SSRF risk', severity: SEVERITY.HIGH, desc: 'HTTP request with user-controlled URL — SSRF vulnerability' },
  { pattern: /\.env|process\.env|dotenv/g, name: 'Environment variable access', severity: SEVERITY.INFO, desc: 'Environment variable usage — ensure .env is in .gitignore' },
];

const UNICODE_PATTERNS = [
  { pattern: /[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF]/g, name: 'Invisible Unicode character', severity: SEVERITY.CRITICAL, desc: 'Glassworm attack — invisible characters can hide malicious code' },
  { pattern: /[\u202A-\u202E\u2066-\u2069]/g, name: 'Bidi override character', severity: SEVERITY.CRITICAL, desc: 'Trojan Source — bidirectional text can make code appear different than it executes' },
];

export function scanCode(code, filename = 'unknown') {
  const findings = [];
  const lines = code.split('\n');

  const allPatterns = [
    ...SECRET_PATTERNS.map(p => ({ ...p, category: 'secrets' })),
    ...INJECTION_PATTERNS.map(p => ({ ...p, category: 'injection' })),
    ...AGENT_PATTERNS.map(p => ({ ...p, category: 'agent-security' })),
    ...UNICODE_PATTERNS.map(p => ({ ...p, category: 'unicode-attack' })),
  ];

  for (const patternDef of allPatterns) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const matches = line.matchAll(new RegExp(patternDef.pattern.source, patternDef.pattern.flags));
      for (const match of matches) {
        findings.push({
          file: filename,
          line: i + 1,
          column: match.index + 1,
          severity: patternDef.severity,
          category: patternDef.category,
          name: patternDef.name,
          description: patternDef.desc || `Found ${patternDef.name}`,
          snippet: line.trim().substring(0, 120),
          match: match[0].substring(0, 50),
        });
      }
    }
  }

  return findings;
}

export function scanRepo(files) {
  const allFindings = [];
  const stats = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const [filename, content] of Object.entries(files)) {
    const findings = scanCode(content, filename);
    allFindings.push(...findings);
  }

  for (const f of allFindings) {
    stats.total++;
    stats[f.severity]++;
  }

  const grade = stats.critical > 0 ? 'F' :
                stats.high > 2 ? 'D' :
                stats.high > 0 ? 'C' :
                stats.medium > 3 ? 'B' :
                stats.medium > 0 ? 'B+' : 'A';

  return { findings: allFindings, stats, grade, scannedFiles: Object.keys(files).length };
}

export function generateReport(result) {
  let report = `# Security Audit Report\n\n`;
  report += `**Grade: ${result.grade}** | Files scanned: ${result.scannedFiles}\n\n`;
  report += `| Severity | Count |\n|----------|-------|\n`;
  report += `| 🔴 Critical | ${result.stats.critical} |\n`;
  report += `| 🟠 High | ${result.stats.high} |\n`;
  report += `| 🟡 Medium | ${result.stats.medium} |\n`;
  report += `| 🔵 Low | ${result.stats.low} |\n`;
  report += `| ⚪ Info | ${result.stats.info} |\n\n`;

  if (result.findings.length === 0) {
    report += `✅ No security issues found.\n`;
    return report;
  }

  const grouped = {};
  for (const f of result.findings) {
    if (!grouped[f.category]) grouped[f.category] = [];
    grouped[f.category].push(f);
  }

  for (const [category, findings] of Object.entries(grouped)) {
    report += `## ${category}\n\n`;
    for (const f of findings) {
      const icon = f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'medium' ? '🟡' : '🔵';
      report += `### ${icon} ${f.name}\n`;
      report += `- **File:** \`${f.file}\` line ${f.line}\n`;
      report += `- **Severity:** ${f.severity}\n`;
      report += `- **Description:** ${f.description}\n`;
      report += `- **Code:** \`${f.snippet}\`\n\n`;
    }
  }

  return report;
}
