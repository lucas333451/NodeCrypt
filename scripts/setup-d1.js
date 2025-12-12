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

// Accept lowercase env names (some platforms disallow uppercase)
if (process.env.id && !process.env.ACCOUNT_ID) process.env.ACCOUNT_ID = process.env.id;
if (process.env.cf_account_id && !process.env.CF_ACCOUNT_ID) process.env.CF_ACCOUNT_ID = process.env.cf_account_id;
if (process.env.d1_id && !process.env.D1_ID) process.env.D1_ID = process.env.d1_id;
if (process.env.d1_database_id && !process.env.D1_DATABASE_ID) process.env.D1_DATABASE_ID = process.env.d1_database_id;
if (process.env.token && !process.env.CLOUDFLARE_API_TOKEN) process.env.CLOUDFLARE_API_TOKEN = process.env.token;
if (process.env.mail && !process.env.MAIL_FROM) process.env.MAIL_FROM = process.env.mail;
if (process.env.d1_location && !process.env.D1_LOCATION) process.env.D1_LOCATION = process.env.d1_location;

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

  // Fill/replace account_id if env exists or placeholder present
  let accountId = ENV_ACCOUNT_ID && ENV_ACCOUNT_ID.trim();

  // Try wrangler whoami --json as fallback to discover account id
  if (!accountId) {
    try {
      const whoami = run(`${WRANGLER} whoami --json`);
      try {
        const info = JSON.parse(whoami);
        accountId =
          info.account_id ||
          info.account?.id ||
          (Array.isArray(info.accounts) && info.accounts[0]?.id) ||
          (Array.isArray(info.accounts) && info.accounts[0]?.account_id);
        if (accountId) {
          log(`Discovered account_id via wrangler whoami: ${accountId}`);
        }
      } catch (err) {
        console.error('Failed to parse wrangler whoami output:', err);
      }
    } catch (err) {
      console.error('wrangler whoami failed; set ACCOUNT_ID env to skip this.', err.stdout || err.message);
    }
  }

  if (accountId) {
    let newToml = toml;
    const acctRegex = /account_id\s*=\s*"([^"]*)"/;
    if (acctRegex.test(newToml)) {
      newToml = newToml.replace(acctRegex, `account_id = "${accountId}"`);
    } else if (newToml.includes(ACCOUNT_PLACEHOLDER)) {
      newToml = newToml.replace(ACCOUNT_PLACEHOLDER, accountId);
    } else {
      newToml = `account_id = "${accountId}"\n` + newToml;
    }
    fs.writeFileSync(TOML_PATH, newToml, 'utf8');
    log(`Injected/updated ACCOUNT_ID=${accountId} into wrangler.toml`);
  } else if (toml.includes(ACCOUNT_PLACEHOLDER)) {
    log(
      `WARNING: wrangler.toml has account_id placeholder. Set env ACCOUNT_ID/CF_ACCOUNT_ID or ensure 'wrangler whoami --json' works.`
    );
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
