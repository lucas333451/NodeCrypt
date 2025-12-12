#!/usr/bin/env node
/**
 * Auto-create D1 and inject database_id into wrangler.toml if placeholder is present.
 * Safe to re-run: if database_id is already set (no placeholder), it exits quietly.
 */
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const TOML_PATH = path.join(ROOT, 'wrangler.toml');
const PLACEHOLDER = 'REPLACE_WITH_D1_ID';

function log(msg) {
  console.log(`[setup-d1] ${msg}`);
}

function run(cmd) {
  log(`$ ${cmd}`);
  return execSync(cmd, { stdio: 'pipe', encoding: 'utf8' });
}

// Prefer local wrangler via npx to avoid global dependency issues
const WRANGLER = process.platform === 'win32' ? 'npx wrangler.cmd' : 'npx wrangler';

function main() {
  if (!fs.existsSync(TOML_PATH)) {
    throw new Error('wrangler.toml not found');
  }
  const toml = fs.readFileSync(TOML_PATH, 'utf8');

  if (!toml.includes(PLACEHOLDER)) {
    log('database_id already set; skipping auto-create.');
    return;
  }

  log('Placeholder detected; creating D1 database...');
  let output = '';
  try {
    // Request JSON output for easy parsing
    output = run(`${WRANGLER} d1 create nodecrypt-db --json`);
  } catch (err) {
    console.error(err.stdout || err.message);
    throw new Error('Failed to create D1 database');
  }

  let json;
  try {
    json = JSON.parse(output);
  } catch (err) {
    throw new Error(`Cannot parse wrangler output: ${output}`);
  }

  const dbId = json?.uuid || json?.database?.uuid || json?.database_id;
  if (!dbId) {
    throw new Error(`database_id not found in wrangler output: ${output}`);
  }

  const updated = toml.replace(PLACEHOLDER, dbId);
  fs.writeFileSync(TOML_PATH, updated, 'utf8');
  log(`Injected database_id=${dbId} into wrangler.toml`);
}

main();
