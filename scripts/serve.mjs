#!/usr/bin/env node
// scripts/serve.mjs — a zero-dependency static server for local preview (localhost = a secure context, so
// WebCrypto Ed25519 and BroadcastChannel work). node scripts/serve.mjs [port]
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
const root = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const port = Number(process.argv[2]) || 8099;
const TYPES = { '.html': 'text/html', '.mjs': 'text/javascript', '.js': 'text/javascript', '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.txt': 'text/plain', '.xml': 'application/xml', '.svg': 'image/svg+xml' };
createServer(async (req, res) => {
  try {
    let p = decodeURIComponent(req.url.split('?')[0]);
    if (p === '/' || p === '') p = '/index.html';
    const file = normalize(join(root, p));
    if (!file.startsWith(normalize(root))) { res.writeHead(403); return res.end('no'); }
    const body = await readFile(file);
    res.writeHead(200, { 'content-type': TYPES[extname(file)] || 'application/octet-stream' });
    res.end(body);
  } catch { res.writeHead(404); res.end('404'); }
}).listen(port, () => console.log('serving ' + root + ' on http://localhost:' + port + '/'));
