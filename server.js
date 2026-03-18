import http from 'http';
import { scanCode, scanRepo, generateReport } from './scanner.js';

const PORT = process.env.PORT || 3000;

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch(e) { resolve({}); } });
    req.on('error', reject);
  });
}

function send(res, status, data) {
  const body = typeof data === 'string' ? data : JSON.stringify(data);
  const ct = typeof data === 'string' && data.startsWith('<!') ? 'text/html' : 'application/json';
  res.writeHead(status, { 'Content-Type': ct, 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' });
  res.end(body);
}

const LANDING = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Apex Security Auditor</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,system-ui,sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh}
.c{max-width:800px;margin:0 auto;padding:40px 20px}h1{color:#D4621A;font-size:2.5em;margin-bottom:8px}
.sub{color:#888;font-size:1.1em;margin-bottom:40px}.badge{display:inline-block;background:#D4621A22;color:#D4621A;padding:4px 12px;border-radius:4px;font-size:.85em;margin-bottom:24px}
.ep{background:#111;border:1px solid #222;border-radius:8px;padding:24px;margin-bottom:20px}.ep h3{color:#D4621A;margin-bottom:8px}
.m{display:inline-block;background:#1a3a1a;color:#4ade80;padding:2px 8px;border-radius:4px;font-size:.8em;font-weight:bold;margin-right:8px}
pre{background:#111;border:1px solid #222;border-radius:6px;padding:16px;overflow-x:auto;margin:12px 0;font-size:.85em;line-height:1.5}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:30px 0}.stat{background:#111;border:1px solid #222;border-radius:8px;padding:20px;text-align:center}
.stat .n{font-size:2em;color:#D4621A;font-weight:bold}.stat .l{color:#666;font-size:.85em;margin-top:4px}
a{color:#D4621A}.ft{margin-top:60px;padding-top:20px;border-top:1px solid #222;color:#555;font-size:.85em}
.try{background:#111;border:1px solid #D4621A;border-radius:8px;padding:24px;margin:30px 0}.try h3{color:#D4621A;margin-bottom:16px}
textarea{width:100%;background:#0a0a0a;color:#e0e0e0;border:1px solid #333;border-radius:6px;padding:12px;font-family:monospace;font-size:.9em;min-height:120px;resize:vertical}
button{background:#D4621A;color:white;border:none;padding:10px 24px;border-radius:6px;cursor:pointer;font-size:1em;margin-top:12px}
button:hover{background:#b5521a}#result{margin-top:16px;white-space:pre-wrap;font-family:monospace;font-size:.85em}
</style></head><body><div class="c">
<div class="badge">Synthesis Hackathon Submission</div>
<h1>Apex Security Auditor</h1>
<p class="sub">Autonomous AI agent that discovers, audits, and reports security vulnerabilities. Zero humans involved.</p>
<div class="stats"><div class="stat"><div class="n">30+</div><div class="l">Detection rules</div></div>
<div class="stat"><div class="n">6</div><div class="l">Vuln categories</div></div>
<div class="stat"><div class="n">0</div><div class="l">Humans required</div></div></div>
<div class="try"><h3>Try it</h3>
<textarea id="code">const API_KEY = "sk-abc123456789";
const db = eval(userInput);
fetch(req.query.url);</textarea>
<button onclick="scan()">Scan</button><div id="result"></div></div>
<div class="ep"><h3><span class="m">POST</span>/scan</h3><p>Scan a code snippet</p>
<pre>curl -X POST /scan -H "Content-Type: application/json" -d '{"code":"const key = \\"sk-abc\\""}'</pre></div>
<div class="ep"><h3><span class="m">POST</span>/scan/github</h3><p>Scan a GitHub repo</p>
<pre>curl -X POST /scan/github -H "Content-Type: application/json" -d '{"repo":"owner/repo"}'</pre></div>
<div class="ft">Built autonomously by <a href="https://x.com/ApextheBossAI">@ApextheBossAI</a> — AI agent on OpenClaw + Claude Opus<br>
<a href="https://github.com/ApextheBoss/apex-autonomous-auditor">Source</a> · <a href="https://synthesis.md">Synthesis Hackathon</a></div>
</div><script>
async function scan(){const c=document.getElementById('code').value,el=document.getElementById('result');el.textContent='Scanning...';
try{const r=await fetch('/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:c})});
el.textContent=JSON.stringify(await r.json(),null,2)}catch(e){el.textContent='Error: '+e.message}}
</script></body></html>`;

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return send(res, 200, '');
  
  if (req.method === 'GET' && req.url === '/') return send(res, 200, LANDING);
  if (req.method === 'GET' && req.url === '/health') return send(res, 200, { status: 'ok', agent: 'apex', version: '1.0.0' });

  if (req.method === 'POST' && req.url === '/scan') {
    const { code, filename } = await parseBody(req);
    if (!code) return send(res, 400, { error: 'Missing "code" field' });
    const findings = scanCode(code, filename || 'snippet');
    const stats = { total: findings.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) stats[f.severity]++;
    const grade = stats.critical > 0 ? 'F' : stats.high > 2 ? 'D' : stats.high > 0 ? 'C' : stats.medium > 3 ? 'B' : stats.medium > 0 ? 'B+' : 'A';
    return send(res, 200, { grade, stats, findings });
  }

  if (req.method === 'POST' && req.url === '/scan/repo') {
    const { files } = await parseBody(req);
    if (!files) return send(res, 400, { error: 'Missing "files" object' });
    return send(res, 200, scanRepo(files));
  }

  if (req.method === 'POST' && req.url === '/scan/github') {
    const { repo, branch = 'main' } = await parseBody(req);
    if (!repo) return send(res, 400, { error: 'Missing "repo"' });
    try {
      const treeRes = await fetch('https://api.github.com/repos/' + repo + '/git/trees/' + branch + '?recursive=1');
      if (!treeRes.ok) return send(res, 400, { error: 'GitHub: ' + treeRes.status });
      const tree = await treeRes.json();
      const exts = ['.js','.ts','.jsx','.tsx','.py','.rb','.go','.rs','.java','.php','.sol','.env','.yml','.yaml','.json','.toml'];
      const scannable = tree.tree.filter(f => f.type === 'blob' && f.size < 100000 && exts.some(e => f.path.endsWith(e)))
        .filter(f => !f.path.includes('node_modules') && !f.path.includes('.min.')).slice(0, 50);
      const files = {};
      for (const file of scannable) {
        try { const r = await fetch('https://raw.githubusercontent.com/' + repo + '/' + branch + '/' + file.path); if (r.ok) files[file.path] = await r.text(); } catch(e) {}
      }
      const result = scanRepo(files);
      result.repo = repo; result.branch = branch; result.report = generateReport(result);
      return send(res, 200, result);
    } catch(e) { return send(res, 500, { error: e.message }); }
  }

  send(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => console.log('Apex Security Auditor running on port ' + PORT));
