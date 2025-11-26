# K13 Protected Scripts — Strong Protection (Option A)

This repository is a **GitHub-ready project** implementing **Option A — Strongest Protection**:

* Files are **encrypted at rest** (AES-256-GCM). Decrypted only in-memory when served.
* **Signed, expiring URLs** (HMAC-SHA256)
* **Optional single-use tokens** (max_uses)
* **API-key protected** upload & signing endpoints
* **"404 skid"** responses on all failures
* SQLite metadata for tokens and files
* Small admin **uploader.html** UI for uploading and creating signed links

---

## Included files (what you'll find below)

* `server.js` — main Node.js server (Express)
* `package.json` — dependencies
* `uploader.html` — admin web UI
* `README.md` — deploy & run instructions
* `.env.example` — environment variables to set on Render

---

## server.js (encrypted storage + signed links)

```js
// server.js
// Node 18+ (ESM). AES-256-GCM encrypted storage, signed expiring URLs, optional single-use tokens.

import express from 'express';
import multer from 'multer';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Config (from env)
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || 'replace_me';
const SIGNING_SECRET = process.env.SIGNING_SECRET || 'replace_me_too';
const FILE_ENC_KEY = process.env.FILE_ENC_KEY || null; // 32 bytes hex (64 hex chars) required
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

if (!FILE_ENC_KEY) {
  console.error('ERROR: FILE_ENC_KEY environment variable must be set (64 hex chars).');
  process.exit(1);
}

const ENC_KEY = Buffer.from(FILE_ENC_KEY, 'hex');
if (ENC_KEY.length !== 32) {
  console.error('ERROR: FILE_ENC_KEY must decode to 32 bytes (64 hex chars).');
  process.exit(1);
}

// Helper: encrypt buffer -> returns { iv, authTag, data }
function encryptBuffer(buf) {
  const iv = crypto.randomBytes(12); // 96-bit for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(buf), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { iv: iv.toString('hex'), authTag: authTag.toString('hex'), data: encrypted.toString('hex') };
}

// Helper: decrypt object -> Buffer
function decryptObject(obj) {
  const iv = Buffer.from(obj.iv, 'hex');
  const authTag = Buffer.from(obj.authTag, 'hex');
  const data = Buffer.from(obj.data, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
  decipher.setAuthTag(authTag);
  const out = Buffer.concat([decipher.update(data), decipher.final()]);
  return out;
}

// HMAC signing for URLs
function signPayload(payload) {
  return crypto.createHmac('sha256', SIGNING_SECRET).update(payload).digest('hex');
}

// multer
const storage = multer.memoryStorage(); // we encrypt in-memory before writing
const upload = multer({ storage });

// init sqlite
async function initDb() {
  const db = await open({ filename: path.join(__dirname, 'k13.db'), driver: sqlite3.Database });
  await db.exec(`
    CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY,
      original_name TEXT,
      stored_name TEXT,
      created_at INTEGER
    );
  `);
  await db.exec(`
    CREATE TABLE IF NOT EXISTS tokens (
      token_id TEXT PRIMARY KEY,
      file_id TEXT,
      expires INTEGER,
      max_uses INTEGER,
      uses INTEGER DEFAULT 0,
      signature TEXT
    );
  `);
  return db;
}

const app = express();
app.use(express.json());

function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'] || req.query.apikey;
  if (!key || key !== API_KEY) return res.status(401).json({ error: '401' });
  next();
}

(async () => {
  const db = await initDb();

  // Upload: encrypt file and store as JSON blob
  app.post('/upload', requireApiKey, upload.single('script'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: '400' });
      const id = crypto.randomUUID();
      const ext = path.extname(req.file.originalname) || '.txt';
      const storedName = id + ext;

      // encrypt buffer
      const enc = encryptBuffer(req.file.buffer);
      const payload = { iv: enc.iv, authTag: enc.authTag, data: enc.data };
      fs.writeFileSync(path.join(UPLOAD_DIR, storedName + '.enc'), JSON.stringify(payload), { flag: 'wx' });

      await db.run('INSERT INTO files (id, original_name, stored_name, created_at) VALUES (?, ?, ?, ?)', [id, req.file.originalname, storedName, Date.now()]);

      res.json({ id, originalName: req.file.originalname, storedName });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: '500' });
    }
  });

  // Sign token (create signed, expiring URL). maxUses default 1.
  app.post('/sign', requireApiKey, async (req, res) => {
    try {
      const { fileId, validForSeconds = 300, maxUses = 1 } = req.body;
      if (!fileId) return res.status(400).json({ error: '400' });
      const file = await db.get('SELECT * FROM files WHERE id = ?', [fileId]);
      if (!file) return res.status(404).json({ error: '404' });

      const expires = Math.floor(Date.now() / 1000) + Number(validForSeconds);
      const tokenId = crypto.randomUUID();
      const payload = `${tokenId}:${fileId}:${expires}:${maxUses}`;
      const signature = signPayload(payload);

      await db.run('INSERT INTO tokens (token_id, file_id, expires, max_uses, signature) VALUES (?, ?, ?, ?, ?)', [tokenId, fileId, expires, maxUses, signature]);

      const rawUrl = `${req.protocol}://${req.get('host')}/raw/${encodeURIComponent(tokenId)}?sig=${signature}&expires=${expires}`;
      res.json({ tokenId, rawUrl, expires, maxUses });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: '500' });
    }
  });

  // Raw endpoint: validate token signature, expiry, max_uses, then decrypt and stream plaintext
  app.get('/raw/:tokenId', async (req, res) => {
    try {
      const tokenId = req.params.tokenId;
      const { sig, expires } = req.query;
      if (!sig || !expires) return res.status(404).send('404 skid');

      const token = await db.get('SELECT * FROM tokens WHERE token_id = ?', [tokenId]);
      if (!token) return res.status(404).send('404 skid');

      const now = Math.floor(Date.now() / 1000);
      if (Number(expires) < now || Number(token.expires) < now) return res.status(404).send('404 skid');

      const expectedPayload = `${tokenId}:${token.file_id}:${token.expires}:${token.max_uses}`;
      const expectedSig = signPayload(expectedPayload);
      let ok = false;
      try {
        ok = crypto.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(String(sig)));
      } catch (e) {
        return res.status(404).send('404 skid');
      }
      if (!ok) return res.status(404).send('404 skid');

      if (token.uses >= token.max_uses) return res.status(404).send('404 skid');

      // load encrypted file
      const fileRow = await db.get('SELECT * FROM files WHERE id = ?', [token.file_id]);
      if (!fileRow) return res.status(404).send('404 skid');
      const encPath = path.join(UPLOAD_DIR, fileRow.stored_name + '.enc');
      if (!fs.existsSync(encPath)) return res.status(404).send('404 skid');

      const raw = fs.readFileSync(encPath, 'utf8');
      const payload = JSON.parse(raw);
      const decrypted = decryptObject(payload); // Buffer

      // increment uses
      await db.run('UPDATE tokens SET uses = uses + 1 WHERE token_id = ?', [tokenId]);

      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.send(decrypted.toString('utf8'));
    } catch (e) {
      console.error(e);
      res.status(404).send('404 skid');
    }
  });

  // revoke token
  app.post('/revoke', requireApiKey, async (req, res) => {
    const { tokenId } = req.body;
    if (!tokenId) return res.status(400).json({ error: '400' });
    await db.run('DELETE FROM tokens WHERE token_id = ?', [tokenId]);
    res.json({ ok: true });
  });

  app.listen(PORT, () => console.log(`K13 server listening on http://localhost:${PORT}`));
})();
```

---

## package.json

```json
{
  "name": "k13-protected-scripts",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "multer": "^1.4.5-lts.1",
    "sqlite": "^4.1.2",
    "sqlite3": "^5.1.6"
  }
}
```

---

## uploader.html (admin UI)

```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>K13 Protected — Uploader</title>
  <style>
    body{font-family:Inter,system-ui,Arial;background:#0b0b0b;color:#e6e6e6;padding:20px}
    .card{background:#0f0f10;padding:16px;border-radius:10px;max-width:700px}
    input,button{padding:8px;margin:6px 0;width:100%}
    a{color:#7fe0a5;word-break:break-all}
  </style>
</head>
<body>
  <h1>K13 Protected — Admin Uploader</h1>
  <div class="card">
    <label>API Key (your secret): <input id="apikey" type="text" placeholder="x-api-key"/></label>
    <label>Choose script file: <input id="file" type="file" accept=".lua,.txt"/></label>
    <label>Validity (seconds): <input id="ttl" type="number" value="300"/></label>
    <label>Max uses: <input id="maxUses" type="number" value="1" min="1"/></label>
    <button id="uploadBtn">Upload & Create Signed Link</button>
    <p id="status"></p>
    <p>Signed URL: <a id="rawLink" href="#" target="_blank"></a></p>
  </div>
  <script>
    document.getElementById('uploadBtn').addEventListener('click', async () => {
      const apikey = document.getElementById('apikey').value.trim();
      if (!apikey) return alert('Provide API key');
      const fileEl = document.getElementById('file');
      if (!fileEl.files.length) return alert('Choose a file');
      const f = fileEl.files[0];

      const form = new FormData();
      form.append('script', f);

      const API_BASE = window.location.origin;
      document.getElementById('status').textContent = 'Uploading...';
      try {
        const up = await fetch(API_BASE + '/upload', { method: 'POST', headers: { 'x-api-key': apikey }, body: form });
        if (!up.ok) throw new Error('upload failed');
        const upData = await up.json();

        const signRes = await fetch(API_BASE + '/sign', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': apikey }, body: JSON.stringify({ fileId: upData.id, validForSeconds: Number(document.getElementById('ttl').value), maxUses: Number(document.getElementById('maxUses').value) }) });
        if (!signRes.ok) throw new Error('sign failed');
        const sign = await signRes.json();

        document.getElementById('status').textContent = 'Done.';
        const a = document.getElementById('rawLink'); a.href = sign.rawUrl; a.textContent = sign.rawUrl;
      } catch (e) {
        document.getElementById('status').textContent = 'Error: ' + e.message;
      }
    });
  </script>
</body>
</html>
```

---

## .env.example

```
# copy to .env and set real values in Render/your host
PORT=3000
API_KEY=replace_with_strong_api_key
SIGNING_SECRET=replace_with_signing_secret
# FILE_ENC_KEY must be 64 hex chars (32 bytes). Generate with: openssl rand -hex 32
FILE_ENC_KEY=<64-hex-chars>
```

---

## README.md (deploy to Render quick steps)

````md
# K13 Protected Scripts — Strongest Protection

## Quick start (local)

1. Copy `.env.example` to `.env` and fill values. Make sure FILE_ENC_KEY is 64 hex chars.
2. Install dependencies:
   ```bash
   npm install
````

3. Run:

   ```bash
   npm start
   ```
4. Open `http://localhost:3000/uploader.html` and upload scripts with your API key.

## Deploy to Render (free)

1. Create a GitHub repo with these files.
2. Sign in to Render and create a new **Web Service**.
3. Connect the repo and set build command `npm install` and start command `npm start`.
4. Add environment variables in Render dashboard: `API_KEY`, `SIGNING_SECRET`, `FILE_ENC_KEY` (generate with `openssl rand -hex 32`).
5. Deploy. Your service URL will be like `https://yourapp.onrender.com`.

## Usage from Roblox

Use the signed raw URL returned by the uploader's Sign step.

```lua
local url = "https://yourapp.onrender.com/raw/<tokenId>?sig=<signature>&expires=<timestamp>"
local ok, body = pcall(function() return game:HttpGet(url) end)
if ok then
  local f, err = loadstring(body)
  if f then pcall(f) else warn(err) end
else
  warn('fetch failed')
end
```

## Security notes

* Keep `API_KEY`, `SIGNING_SECRET`, `FILE_ENC_KEY` secret and in environment variables.
* Use short expiry times and `maxUses=1` for highest protection.
* Use HTTPS (Render provides TLS).
* Rotate FILE_ENC_KEY and SIGNING_SECRET if compromised.

```

---

## What I can produce next (pick one)

- A ZIP of the repo you can download (I can paste steps to create it locally).  
- A `Dockerfile` + `docker-compose.yml` for easy deployment.  
- Convert storage to S3 with server-side encryption and S3 presigned URLs.  
- Add user accounts + JWT admin panel so multiple uploaders can have their own keys.

Tell me which of the above you want next and I'll create it.

```
