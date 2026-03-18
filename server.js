import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { cors } from 'hono/cors';
import { scanCode, scanRepo, generateReport } from './scanner.js';
import { readFileSync } from 'fs';

const app = new Hono();
app.use('*', cors());

// Landing page
app.get('/', (c) => {
  return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Apex Security Auditor</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0a; color: #e0e0e0; min-height: 100vh; }
  .container { max-width: 800px; margin: 0 auto; padding: 40px 20px; }
  h1 { color: #D4621A; font-size: 2.5em; margin-bottom: 8px; }
  .subtitle { color: #888; font-size: 1.1em; margin-bottom: 40px; }
  .badge { display: inline-block; background: #D4621A22; color: #D4621A; padding: 4px 12px; border-radius: 4px; font-size: 0.85em; margin-bottom: 24px; }
  .endpoint { background: #111; border: 1px solid #222; border-radius: 8px; padding: 24px; margin-bottom: 20px; }
  .endpoint h3 { color: #D4621A; margin-bottom: 8px; }
  .method { display: inline-block; background: #1a3a1a; color: #4ade80; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; margin-right: 8px; }
  code { background: #1a1a1a; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
  pre { background: #111; border: 1px solid #222; border-radius: 6px; padding: 16px; overflow-x: auto; margin: 12px 0; font-size: 0.85em; line-height: 1.5; }
  .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 30px 0; }
  .stat { background: #111; border: 1px solid #222; border-radius: 8px; padding: 20px; text-align: center; }
  .stat .number { font-size: 2em; color: #D4621A; font-weight: bold; }
  .stat .label { color: #666; font-size: 0.85em; margin-top: 4px; }
  a { color: #D4621A; }
  .footer { margin-top: 60px; padding-top: 20px; border-top: 1px solid #222; color: #555; font-size: 0.85em; }
  .try-it { background: #111; border: 1px solid #D4621A; border-radius: 8px; padding: 24px; margin: 30px 0; }
  .try-it h3 { color: #D4621A; margin-bottom: 16px; }
  textarea { width: 100%; background: #0a0a0a; color: #e0e0e0; border: 1px solid #333; border-radius: 6px; padding: 12px; font-family: monospace; font-size: 0.9em; min-height: 120px; resize: vertical; }
  button { background: #D4621A; color: white; border: none; padding: 10px 24px; border-radius: 6px; cursor: pointer; font-size: 1em; margin-top: 12px; }
  button:hover { background: #b5521a; }
  #result { margin-top: 16px; white-space: pre-wrap; font-family: monospace; font-size: 0.85em; }
</style>
</head>
<body>
<div class="container">
  <div class="badge">🏗️ Synthesis Hackathon Submission</div>
  <h1>Apex Security Auditor</h1>
  <p class="subtitle">Autonomous AI agent that discovers, audits, and reports security vulnerabilities. Zero humans involved.</p>

  <div class="stats">
    <div class="stat"><div class="number">30+</div><div class="label">Detection rules</div></div>
    <div class="stat"><div class="number">6</div><div class="label">Vuln categories</div></div>
    <div class="stat"><div class="number">0</div><div class="label">Humans required</div></div>
  </div>

  <div class="try-it">
    <h3>Try it — paste code below</h3>
    <textarea id="code" placeholder="Paste code to scan...">const API_KEY = "sk-abc123456789";
const db = eval(userInput);
fetch(req.query.url);</textarea>
    <button onclick="scan()">Scan</button>
    <div id="result"></div>
  </div>

  <div class="endpoint">
    <h3><span class="method">POST</span>/scan</h3>
    <p>Scan a single code snippet</p>
    <pre>curl -X POST ${'{URL}'}/scan \\
  -H "Content-Type: application/json" \\
  -d '{"code": "const key = \\"sk-abc123\\""}'</pre>
  </div>

  <div class="endpoint">
    <h3><span class="method">POST</span>/scan/repo</h3>
    <p>Scan multiple files at once</p>
    <pre>curl -X POST ${'{URL}'}/scan/repo \\
  -H "Content-Type: application/json" \\
  -d '{"files": {"app.js": "...", "config.js": "..."}}'</pre>
  </div>

  <div class="endpoint">
    <h3><span class="method">POST</span>/scan/github</h3>
    <p>Scan a public GitHub repository</p>
    <pre>curl -X POST ${'{URL}'}/scan/github \\
  -H "Content-Type: application/json" \\
  -d '{"repo": "owner/repo", "branch": "main"}'</pre>
  </div>

  <div class="footer">
    Built autonomously by <a href="https://x.com/ApextheBossAI">@ApextheBossAI</a> — an AI agent running on OpenClaw + Claude Opus<br>
    <a href="https://github.com/ApextheBoss/apex-autonomous-auditor">Source</a> · <a href="https://synthesis.md">Synthesis Hackathon</a>
  </div>
</div>
<script>
async function scan() {
  const code = document.getElementById('code').value;
  const el = document.getElementById('result');
  el.textContent = 'Scanning...';
  try {
    const res = await fetch('/scan', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({code}) });
    const data = await res.json();
    el.textContent = JSON.stringify(data, null, 2);
  } catch(e) { el.textContent = 'Error: ' + e.message; }
}
</script>
</body>
</html>`);
});

// Scan single code snippet
app.post('/scan', async (c) => {
  const body = await c.req.json();
  const { code, filename } = body;
  if (!code) return c.json({ error: 'Missing "code" field' }, 400);
  const findings = scanCode(code, filename || 'snippet');
  const stats = { total: findings.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) stats[f.severity]++;
  const grade = stats.critical > 0 ? 'F' : stats.high > 2 ? 'D' : stats.high > 0 ? 'C' : stats.medium > 3 ? 'B' : stats.medium > 0 ? 'B+' : 'A';
  return c.json({ grade, stats, findings });
});

// Scan multiple files
app.post('/scan/repo', async (c) => {
  const body = await c.req.json();
  const { files } = body;
  if (!files || typeof files !== 'object') return c.json({ error: 'Missing "files" object' }, 400);
  const result = scanRepo(files);
  return c.json(result);
});

// Scan GitHub repo
app.post('/scan/github', async (c) => {
  const body = await c.req.json();
  const { repo, branch = 'main', path = '' } = body;
  if (!repo) return c.json({ error: 'Missing "repo" field (e.g., "owner/repo")' }, 400);

  try {
    // Fetch repo tree
    const treeUrl = `https://api.github.com/repos/${repo}/git/trees/${branch}?recursive=1`;
    const treeRes = await fetch(treeUrl);
    if (!treeRes.ok) return c.json({ error: `GitHub API error: ${treeRes.status}` }, 400);
    const tree = await treeRes.json();

    // Filter scannable files
    const scanExts = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.go', '.rs', '.java', '.php', '.sol', '.env', '.yml', '.yaml', '.json', '.toml'];
    const scannable = tree.tree
      .filter(f => f.type === 'blob' && f.size < 100000 && scanExts.some(ext => f.path.endsWith(ext)))
      .filter(f => !f.path.includes('node_modules') && !f.path.includes('vendor') && !f.path.includes('.min.'))
      .slice(0, 50); // limit to 50 files

    const files = {};
    for (const file of scannable) {
      try {
        const rawUrl = `https://raw.githubusercontent.com/${repo}/${branch}/${file.path}`;
        const res = await fetch(rawUrl);
        if (res.ok) files[file.path] = await res.text();
      } catch (e) { /* skip unreadable files */ }
    }

    const result = scanRepo(files);
    result.repo = repo;
    result.branch = branch;
    result.report = generateReport(result);
    return c.json(result);
  } catch (e) {
    return c.json({ error: e.message }, 500);
  }
});

// Health check
app.get('/health', (c) => c.json({ status: 'ok', agent: 'apex', version: '1.0.0' }));

const port = process.env.PORT || 3000;
serve({ fetch: app.fetch, port }, () => {
  console.log(`Apex Security Auditor running on port ${port}`);
});
