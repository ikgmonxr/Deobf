'use strict';

const express = require('express');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');

const app = express();
const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '0.0.0.0';
const MAX_BODY = process.env.MAX_BODY || '6mb';
const MAX_SCRIPT_CHARS = Number(process.env.MAX_SCRIPT_CHARS || 5_000_000);
const JOB_TIMEOUT_MS = Number(process.env.JOB_TIMEOUT_MS || 90_000);
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = Number(process.env.RATE_LIMIT || 12);
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT || 2);

const ROOT = __dirname;
const ENGINE = path.join(ROOT, 'engine');
const LEGACY = path.join(ROOT, 'legacy');
const PUBLIC = path.join(ROOT, 'public');
const TMP_ROOT = path.join(os.tmpdir(), 'qyrex-deobf');

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*')
  .split(',')
  .map((v) => v.trim())
  .filter(Boolean);

const rate = new Map();
let activeJobs = 0;

function requestIp(req) {
  return (req.headers['x-forwarded-for'] || req.ip || 'unknown').split(',')[0].trim();
}

function cleanupRate() {
  const now = Date.now();
  for (const [key, value] of rate) {
    if (value.expires < now) rate.delete(key);
  }
}

setInterval(cleanupRate, RATE_WINDOW_MS).unref();

function rateLimit(req, res, next) {
  const key = requestIp(req);
  const now = Date.now();
  const entry = rate.get(key);
  if (!entry || entry.expires < now) {
    rate.set(key, { count: 1, expires: now + RATE_WINDOW_MS });
    return next();
  }
  entry.count += 1;
  if (entry.count > RATE_LIMIT) {
    const retry = Math.max(1, Math.ceil((entry.expires - now) / 1000));
    res.set('Retry-After', String(retry));
    return res.status(429).json({ ok: false, error: 'Rate limit exceeded.' });
  }
  return next();
}

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes('*')) {
    res.set('Access-Control-Allow-Origin', '*');
  } else if (origin && allowedOrigins.includes(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Vary', 'Origin');
  }
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: MAX_BODY, strict: true }));
app.use(rateLimit);

function validEngine(engine) {
  return ['auto', 'fusion', 'prometheus', 'envlog', 'legacy-lph'].includes(engine);
}

function detectLocal(source) {
  const head = source.slice(0, 20000);
  if (/return\s*\(\s*function\s*\(\s*\.\.\.\s*\)/i.test(head) &&
      (/local\s+\w+\s*=\s*\{\s*["'`\\]/i.test(head) ||
       /for\s+\w+\s*,\s*\w+\s+in\s+ipairs\s*\(/i.test(head))) {
    return 'prometheus';
  }
  if (/Luraph\s+Obfuscator/i.test(head) || /LPH_/i.test(head) || /anti.?tamper/i.test(head)) {
    return 'legacy-lph';
  }
  return 'envlog';
}

function safeName(value, fallback) {
  const clean = String(value || fallback).replace(/[^a-zA-Z0-9._-]/g, '_');
  return clean.slice(0, 80) || fallback;
}

async function createJob(source, extension = 'lua') {
  await fsp.mkdir(TMP_ROOT, { recursive: true });
  const id = `${Date.now().toString(36)}-${crypto.randomBytes(5).toString('hex')}`;
  const dir = path.join(TMP_ROOT, id);
  await fsp.mkdir(dir, { recursive: true });
  const input = path.join(dir, `input.${extension}`);
  const output = path.join(dir, 'out.lua');
  await fsp.writeFile(input, source, 'utf8');
  return { id, dir, input, output };
}

async function removeJob(job) {
  if (!job) return;
  try { await fsp.rm(job.dir, { recursive: true, force: true }); } catch {}
}

function runProcess(command, args, options = {}) {
  const cwd = options.cwd || ROOT;
  const timeout = options.timeout || JOB_TIMEOUT_MS;

  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...(options.env || {}) },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: process.platform !== 'win32',
      windowsHide: true,
    });

    let stdout = '';
    let stderr = '';
    let settled = false;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
      if (stdout.length > 1_000_000) stdout = stdout.slice(-1_000_000);
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
      if (stderr.length > 1_000_000) stderr = stderr.slice(-1_000_000);
    });

    const timer = setTimeout(() => {
      try {
        if (process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch {}
      finish({ ok: false, code: null, stdout, stderr, timeout: true });
    }, timeout);

    child.on('error', (error) => {
      clearTimeout(timer);
      finish({ ok: false, code: null, stdout, stderr: `${stderr}\n${error.message}`, timeout: false });
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      finish({ ok: code === 0, code, stdout, stderr, timeout: false });
    });
  });
}

async function readOutput(output) {
  try {
    const stat = await fsp.stat(output);
    if (stat.size > MAX_SCRIPT_CHARS * 2) throw new Error('Engine output is too large.');
    return await fsp.readFile(output, 'utf8');
  } catch {
    return '';
  }
}

async function runV3Router(job, engine) {
  const args = [path.join(ENGINE, 'router.py'), job.input, job.output];
  if (engine === 'prometheus') args.push('--prom');
  if (engine === 'envlog') args.push('--envlog');
  const result = await runProcess(process.env.PYTHON_BIN || 'python3', args, { cwd: ENGINE });
  const output = await readOutput(job.output);
  return { ...result, output };
}

async function runLegacy(job) {
  const legacyOut = path.join(job.dir, 'legacy.lua');
  const result = await runProcess(process.env.PYTHON_BIN || 'python3',
    [path.join(LEGACY, 'deobfuscator.py'), job.input, '-o', legacyOut],
    { cwd: LEGACY });
  const output = await readOutput(legacyOut);
  return { ...result, output };
}

function normalizedOutput(output) {
  const text = String(output || '').trim();
  return text.replace(/^--\s*\[\[.*?\]\]\s*/s, '').trim();
}

function similarityScore(original, output) {
  const a = normalizedOutput(original);
  const b = normalizedOutput(output);
  if (!b) return 0;
  if (a === b) return 0;
  const originalTokens = new Set((a.match(/[A-Za-z_][A-Za-z0-9_]*/g) || []).slice(0, 30000));
  const outputTokens = new Set((b.match(/[A-Za-z_][A-Za-z0-9_]*/g) || []).slice(0, 30000));
  let shared = 0;
  for (const token of originalTokens) if (outputTokens.has(token)) shared++;
  return Math.max(0, Math.min(100, Math.round((shared / Math.max(1, originalTokens.size)) * 100)));
}

function stats(source, output) {
  const lines = String(output || '').split(/\r?\n/).length;
  const functions = (String(output || '').match(/\bfunction\b/g) || []).length;
  const locals = (String(output || '').match(/\blocal\b/g) || []).length;
  return {
    inputChars: source.length,
    outputChars: String(output || '').length,
    outputLines: lines,
    functions,
    locals,
    tokenOverlap: similarityScore(source, output),
  };
}

async function executeEngine(source, engine) {
  const job = await createJob(source);
  try {
    if (engine === 'legacy-lph') {
      const legacy = await runLegacy(job);
      return {
        usedEngine: 'legacy-lph',
        ok: legacy.ok && !!legacy.output,
        output: legacy.output,
        log: `${legacy.stdout}\n${legacy.stderr}`.trim(),
        timedOut: legacy.timeout,
      };
    }

    if (engine === 'prometheus' || engine === 'envlog') {
      const primary = await runV3Router(job, engine);
      return {
        usedEngine: engine,
        ok: primary.ok && !!primary.output,
        output: primary.output,
        log: `${primary.stdout}\n${primary.stderr}`.trim(),
        timedOut: primary.timeout,
      };
    }

    if (engine === 'fusion') {
      const detected = detectLocal(source);
      const primaryEngine = detected === 'legacy-lph' ? 'envlog' : detected;
      const primary = await runV3Router(job, primaryEngine);
      if (primary.ok && primary.output) {
        return {
          usedEngine: `fusion:${primaryEngine}`,
          ok: true,
          output: primary.output,
          log: `${primary.stdout}\n${primary.stderr}`.trim(),
          timedOut: primary.timeout,
        };
      }
      const legacy = await runLegacy(job);
      return {
        usedEngine: `fusion:${primaryEngine}->legacy-lph`,
        ok: legacy.ok && !!legacy.output,
        output: legacy.output,
        log: `${primary.stdout}\n${primary.stderr}\n${legacy.stdout}\n${legacy.stderr}`.trim(),
        timedOut: Boolean(primary.timeout || legacy.timeout),
      };
    }

    throw new Error('Unsupported engine.');
  } finally {
    await removeJob(job);
  }
}

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    name: 'Qyrex Deobfuscator',
    version: '1.0.0',
    engines: ['auto', 'fusion', 'prometheus', 'envlog', 'legacy-lph'],
    activeJobs,
    maxConcurrent: MAX_CONCURRENT,
    maxScriptChars: MAX_SCRIPT_CHARS,
  });
});

app.post('/api/deobfuscate', async (req, res) => {
  if (activeJobs >= MAX_CONCURRENT) {
    return res.status(429).json({ ok: false, error: 'Server is busy. Try again in a moment.' });
  }

  const source = typeof req.body?.script === 'string' ? req.body.script : '';
  const requested = typeof req.body?.engine === 'string' ? req.body.engine.toLowerCase() : 'auto';

  if (!source.trim()) return res.status(400).json({ ok: false, error: 'No Lua/Luau source was supplied.' });
  if (source.length > MAX_SCRIPT_CHARS) {
    return res.status(413).json({ ok: false, error: `Script exceeds the ${MAX_SCRIPT_CHARS.toLocaleString()} character limit.` });
  }
  if (!validEngine(requested)) return res.status(400).json({ ok: false, error: 'Invalid engine.' });

  const engine = requested === 'auto' ? detectLocal(source) : requested;
  activeJobs++;
  const started = Date.now();

  try {
    const result = await executeEngine(source, engine);
    if (!result.ok) {
      return res.status(result.timedOut ? 504 : 422).json({
        ok: false,
        engine: result.usedEngine,
        error: result.timedOut ? 'Deobfuscation timed out.' : 'The selected engine could not produce output.',
        diagnostics: result.log.slice(-4000),
        ms: Date.now() - started,
      });
    }

    return res.json({
      ok: true,
      engine: result.usedEngine,
      output: result.output,
      stats: stats(source, result.output),
      ms: Date.now() - started,
    });
  } catch (error) {
    console.error('[deobfuscate]', error);
    return res.status(500).json({ ok: false, error: 'Unexpected server error.' });
  } finally {
    activeJobs--;
  }
});

if (fs.existsSync(PUBLIC)) {
  app.use(express.static(PUBLIC, { etag: true, maxAge: '1h' }));
  app.use((req, res, next) => {
    if (req.path.startsWith('/api/')) return res.status(404).json({ ok: false, error: 'API route not found.' });
    if (req.method !== 'GET' && req.method !== 'HEAD') return next();
    return res.sendFile(path.join(PUBLIC, 'index.html'));
  });
}

app.use((err, _req, res, _next) => {
  if (err?.type === 'entity.too.large') return res.status(413).json({ ok: false, error: 'Request body too large.' });
  console.error('[server]', err);
  res.status(500).json({ ok: false, error: 'Internal server error.' });
});

app.listen(PORT, HOST, () => {
  console.log(`Qyrex Deobfuscator listening on ${HOST}:${PORT}`);
});
