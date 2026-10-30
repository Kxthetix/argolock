import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distDir = path.resolve(__dirname, '../dist');

const FORBIDDEN_PATTERNS = [
  'mission-primary-nptel',
  'sample-scan-1',
  'argolock_v17_missions',
  'argolock_kill_switch_active',
  'mission-nmap-discovery',
  'mission-dvwa-validation',
];

if (!fs.existsSync(distDir)) {
  console.error('Error: dist/ directory does not exist. Run "npm run build" first.');
  process.exit(1);
}

function scanDir(dir) {
  let foundViolations = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      foundViolations = foundViolations.concat(scanDir(fullPath));
    } else if (entry.isFile() && (entry.name.endsWith('.js') || entry.name.endsWith('.html'))) {
      const content = fs.readFileSync(fullPath, 'utf8');
      for (const pattern of FORBIDDEN_PATTERNS) {
        if (content.includes(pattern)) {
          foundViolations.push({ file: fullPath, pattern });
        }
      }
    }
  }
  return foundViolations;
}

const violations = scanDir(distDir);
if (violations.length > 0) {
  console.error('❌ CI GATE FAILURE: Mock / fabricated data discovered in production build:');
  for (const v of violations) {
    console.error(`  - Found "${v.pattern}" in ${v.file}`);
  }
  process.exit(1);
}

console.log('✅ CI GATE PASSED: Production build is 100% clean of mock/fabricated data.');
process.exit(0);
