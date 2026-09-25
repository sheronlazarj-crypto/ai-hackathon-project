// scripts/detect-secrets.js
const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: '.env.local' });
const Groq = require('groq-sdk');

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

const IGNORE_DIRS = ['node_modules', '.next', '.git', 'scripts'];
const SCAN_EXTENSIONS = ['.js', '.jsx', '.ts', '.tsx'];

const SECRET_PATTERNS = [
  { name: 'Generic API key assignment', regex: /(api[_-]?key|apikey|secret|token|password)\s*[:=]\s*["'`][A-Za-z0-9_\-]{16,}["'`]/gi },
  { name: 'Supabase service_role key', regex: /service_role.{0,20}["'`]eyJ[A-Za-z0-9_\-.]{20,}["'`]/gi },
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'Groq API key', regex: /gsk_[A-Za-z0-9]{20,}/g },
  { name: 'Generic JWT-looking secret hardcoded', regex: /["'`]eyJ[A-Za-z0-9_\-.]{30,}["'`]/g },
];

let findings = [];

function scanFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  lines.forEach((line, index) => {
    SECRET_PATTERNS.forEach(({ name, regex }) => {
      const matches = line.match(regex);
      if (matches) {
        findings.push({ file: filePath, line: index + 1, type: name, snippet: line.trim().slice(0, 80) });
      }
    });
  });
}

function walkDir(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!IGNORE_DIRS.includes(entry.name)) walkDir(path.join(dir, entry.name));
    } else if (SCAN_EXTENSIONS.includes(path.extname(entry.name))) {
      scanFile(path.join(dir, entry.name));
    }
  }
}

async function explainFinding(finding) {
  const prompt = `You are a security reviewer. In 2-3 short sentences, explain to a developer why this is a security risk and exactly how to fix it. Be direct and practical, no fluff.

Vulnerability type: ${finding.type}
Code: ${finding.snippet}`;

  const response = await groq.chat.completions.create({
    model: 'openai/gpt-oss-120b',
    messages: [{ role: 'user', content: prompt }],
    max_tokens: 150,
  });

  return response.choices[0].message.content.trim();
}

async function main() {
  console.log('🔍 Scanning for hardcoded secrets...\n');
  walkDir(process.cwd());

  if (findings.length === 0) {
    console.log('✅ No hardcoded secrets found.');
    return;
  }

  console.log(`🚨 Found ${findings.length} potential issue(s):\n`);

  for (const f of findings) {
    console.log(`  [${f.type}]`);
    console.log(`  File: ${f.file}:${f.line}`);
    console.log(`  Snippet: ${f.snippet}`);
    console.log('  🤖 Analyzing with Groq...');
    try {
      const explanation = await explainFinding(f);
      console.log(`  Explanation: ${explanation}\n`);
    } catch (err) {
      console.log(`  ⚠️ Could not get AI explanation: ${err.message}\n`);
    }
  }
}

main();