#!/usr/bin/env node
import { readFileSync, writeFileSync, statSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { bootstrap, loadConfiguration } from './bootstrap.mjs';
import { Fabric } from './fabric.mjs';
import { createServer } from './server.mjs';
import { canonical, parseStrict } from './canonical.mjs';
import { signed } from './crypto.mjs';
import { requireThat } from './errors.mjs';

const [command, ...args] = process.argv.slice(2);
const option = (name, fallback) => { const index = args.indexOf(`--${name}`); return index < 0 ? fallback : args[index + 1]; };
try {
  if (command === 'init') {
    const directory = option('dir', './var/local');
    console.log(JSON.stringify(bootstrap(directory, option('tenants', 'acme').split(',')), null, 2));
    console.log('ENGINEERING ONLY: synthetic target resources and software keys. Move custodian keys to independently controlled offline locations before assurance testing. Tokens and configured health expire after 24 hours.');
  } else if (command === 'serve') {
    const directory = resolve(option('dir', './var/local')), port = Number(option('port', '8080'));
    requireThat(Number.isInteger(port) && port >= 1024 && port <= 65535, 'INV-400-SCHEMA', 'Port must be in 1024–65535');
    requireThat((statSync(join(directory, 'config.json')).mode & 0o077) === 0, 'INV-503-CONFIG', 'config.json must not be readable by group or other users', 503);
    const fabric = new Fabric(loadConfiguration(directory), directory), origin = option('origin', `http://127.0.0.1:${port}`);
    const app = createServer(fabric, { port, origin }); await app.listen();
    console.log(`Invariant Fabric engineering console: ${origin} (loopback only; no production guarantee)`);
    let closing = false;
    const close = async () => { if (closing) return; closing = true; await app.close(); fabric.close(); process.exitCode = 0; };
    process.on('SIGINT', close); process.on('SIGTERM', close);
  } else if (command === 'sign') {
    const keyPath = option('key'), inputPath = option('input'), outputPath = option('output'), purpose = option('purpose', 'action-approval');
    requireThat(keyPath && inputPath && outputPath, 'INV-400-SCHEMA', 'sign requires --key, --input and --output');
    requireThat(['action-approval', 'evidence', 'root-policy'].includes(purpose), 'INV-400-SCHEMA', 'Unsupported signing purpose');
    requireThat((statSync(keyPath).mode & 0o077) === 0, 'INV-503-CONFIG', 'Signing key file permissions must be 0600', 503);
    const payload = parseStrict(readFileSync(inputPath, 'utf8')), key = parseStrict(readFileSync(keyPath, 'utf8'));
    writeFileSync(outputPath, canonical(signed(payload, key, purpose)) + '\n', { flag: 'wx', mode: 0o600 });
    console.log(`Signed ${purpose} to ${resolve(outputPath)}. Software signature only; not trusted-display or WebAuthn confirmation.`);
  } else {
    console.log('Usage:\n  node src/cli.mjs init --dir ./var/local [--tenants acme,globex]\n  node src/cli.mjs serve --dir ./var/local [--port 8080] [--origin http://127.0.0.1:8080]\n  node src/cli.mjs sign --key PATH --input PATH --output PATH [--purpose action-approval|evidence|root-policy]');
    if (command) process.exitCode = 2;
  }
} catch (e) { console.error(JSON.stringify({ error: e.code ?? 'INV-500-CLI', message: e.code ? e.message : 'Command failed; verify local paths and file permissions. No secret values were printed.' })); process.exitCode = 1; }
