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
const ACCOUNT_PLACEHOLDER = 'REPLACE_WITH_ACCOUNT_ID';
const ENV_ID = process.env.D1_ID || process.env.D1_DATABASE_ID;
const ENV_ACCOUNT_ID = process.env.ACCOUNT_ID || process.env.CF_ACCOUNT_ID;
const ENV_LOCATION = process.env.D1_LOCATION || 'weur'; // default region hint

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

  // Fill account_id if placeholder present and env provided
  if (toml.includes(ACCOUNT_PLACEHOLDER)) {
    if (ENV_ACCOUNT_ID) {
      const updated = toml.replace(ACCOUNT_PLACEHOLDER, ENV_ACCOUNT_ID.trim());
      fs.writeFileSync(TOML_PATH, updated, 'utf8');
      log(`Injected ACCOUNT_ID=${ENV_ACCOUNT_ID.trim()} into wrangler.toml`);
    } else {
      log(`WARNING: wrangler.toml has account_id placeholder. Set env ACCOUNT_ID or CF_ACCOUNT_ID to fill automatically.`);
    }
  }

  if (!toml.includes(PLACEHOLDER)) {
    log('database_id already set; skipping auto-create.');
    return;
  }

  if (ENV_ID) {
    log(`ENV provided D1 id detected: ${ENV_ID}`);
    const updated = toml.replace(PLACEHOLDER, ENV_ID.trim());
    fs.writeFileSync(TOML_PATH, updated, 'utf8');
    log('Injected ENV D1 id into wrangler.toml');
    return;
  }

  log('Placeholder detected; creating D1 database...');
  let output = '';
  try {
    // Older wrangler may not support --json; use plain text and regex
    output = run(`${WRANGLER} d1 create nodecrypt-db --location ${ENV_LOCATION}`);
  } catch (err) {
    console.error('Failed to create D1 database');
    if (err.stdout) console.error('stdout:', err.stdout);
    if (err.stderr) console.error('stderr:', err.stderr);
    throw err;
  }

  // Try to extract UUID from output
  const match = output.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
  const dbId = match && match[0];
  if (!dbId) {
    throw new Error(`database_id not found in wrangler output: ${output}`);
  }

  const updated = toml.replace(PLACEHOLDER, dbId);
  fs.writeFileSync(TOML_PATH, updated, 'utf8');
  log(`Injected database_id=${dbId} into wrangler.toml`);
}

main();
