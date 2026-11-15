'use strict';
/**
 * Proof Gatekeeper agent — zkVerify Agent Games.
 * No framework: Node built-in http/crypto/fs only.
 * Spec: ./SPEC.md (extracted from https://agentgames.zkverify.io/build).
 *
 * Behaviour:
 *  - GET  /health            -> { ok: true, ... }
 *  - POST /task | /agent | / -> preflight handshake or gatekeeper task
 *  - Inbound HMAC (x-agent-games-signature, HMAC-SHA256 hex over the RAW body)
 *    is verified BEFORE JSON parsing whenever the header is present and a
 *    secret is configured. With no secret configured (local test mode)
 *    verification is skipped and logged.
 *  - Every response body is signed the same way when a secret is configured.
 *  - Decisions are deterministic (7 official checks) and fail closed.
 */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { generateDecisionProof } = require('./proof');

const PORT = Number(process.env.PORT || 8787);
// Official env name per /build is AGENT_GAMES_HMAC_SECRET; AGENT_GAMES_SECRET
// is accepted as a fallback alias.
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || process.env.AGENT_GAMES_SECRET || '';
const SEEN_FILE = process.env.SEEN_FILE || path.join(__dirname, 'seen.json');
const PROOF_ENABLED = process.env.PROOF_ENABLED !== '0';
const MAX_BODY = 1024 * 1024;

if (!SECRET) {
  console.log('[agent] LOCAL TEST MODE: no AGENT_GAMES_HMAC_SECRET set — inbound signature verification skipped, responses unsigned.');
}

// ---------- persistent seen-set for proof_tx ----------
function loadSeen() {
  try {
    const arr = JSON.parse(fs.readFileSync(SEEN_FILE, 'utf8'));
    if (Array.isArray(arr)) return new Set(arr);
  } catch { /* first run */ }
  return new Set();
}
const seen = loadSeen();
function persistSeen() {
  const tmp = SEEN_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify([...seen], null, 2));
  fs.renameSync(tmp, SEEN_FILE);
}

// ---------- idempotency: task_id -> exact response body ----------
const responseCache = new Map();

// ---------- HMAC helpers ----------
function hmacHex(rawBodyBuffer) {
  return crypto.createHmac('sha256', SECRET).update(rawBodyBuffer).digest('hex');
}
function signatureValid(rawBodyBuffer, headerValue) {
  if (!SECRET) {
    console.log('[agent] signature check skipped (no secret configured)');
    return true;
  }
  if (!headerValue) {
    console.log('[agent] no x-agent-games-signature header present — proceeding (header-absent case)');
    return true;
  }
  const expected = hmacHex(rawBodyBuffer);
  const got = String(headerValue).trim().toLowerCase();
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(got, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function sendJson(res, status, obj) {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  if (SECRET) headers['x-agent-games-signature'] = hmacHex(Buffer.from(body, 'utf8'));
  res.writeHead(status, headers);
  res.end(body);
  return body;
}

// ---------- field parsing ----------
function toBigIntOrNull(v) {
  if (v === undefined || v === null) return null;
  if (typeof v === 'number') return Number.isSafeInteger(v) ? BigInt(v) : null;
  if (typeof v === 'string') {
    const s = v.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s) || /^-?\d+$/.test(s)) {
      try { return BigInt(s); } catch { return null; }
    }
  }
  return null;
}
const normAddr = (v) => (typeof v === 'string' ? v.trim().toLowerCase() : '');
const normHex = (v) => (typeof v === 'string' ? v.trim().toLowerCase() : '');

/**
 * The 7 official checks, in the order of the event page's build checklist.
 * Returns { decision, reason_code }.
 * Side effect: a proof_tx that passes the VK + threshold checks is recorded
 * in the seen-set at the reuse checkpoint, so a second submission of the same
 * proof_tx (under any later task) is detected as PROOF_REUSED.
 */
function decide(input) {
  if (!input || typeof input !== 'object') {
    return { decision: 'REJECT', reason_code: 'INVALID_TASK' };
  }
  const registeredVk = normHex(input.registered_vk);
  const proofVk = normHex(input.proof_vk);
  const minimum = toBigIntOrNull(input.minimum);
  const publicBalance = toBigIntOrNull(input.public_balance);
  const expiryBlock = toBigIntOrNull(input.expiry_block);
  const currentBlock = toBigIntOrNull(input.current_block);
  const recipient = normAddr(input.recipient);
  const conditionRecipient = normAddr(input.condition_recipient);
  const amount = toBigIntOrNull(input.amount);
  const maxTransfer = toBigIntOrNull(input.max_transfer);
  const proofTx = normHex(input.proof_tx);

  const fieldsOk = registeredVk && proofVk && recipient && conditionRecipient && proofTx &&
    minimum !== null && publicBalance !== null && expiryBlock !== null &&
    currentBlock !== null && amount !== null && maxTransfer !== null;
  if (!fieldsOk) {
    // Fail closed: an unparseable task is never approved.
    return { decision: 'REJECT', reason_code: 'INVALID_TASK' };
  }

  // 1. Verification key substitution
  if (proofVk !== registeredVk) return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  // 2. Threshold mismatch
  if (publicBalance < minimum) return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  // 3. Proof reuse — checkpoint: record first-time proof references here.
  if (seen.has(proofTx)) return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
  seen.add(proofTx);
  persistSeen();
  // 4. Expired condition
  if (currentBlock > expiryBlock) return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  // 5. Recipient mismatch
  if (recipient !== conditionRecipient) return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  // 6. Amount overflow
  if (amount > maxTransfer) return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  // 7. Everything passed
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

// ---------- request handling ----------
async function handleTask(req, res, rawBody) {
  let body;
  try {
    body = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return sendJson(res, 400, { ok: false, error: 'invalid_json' });
  }

  // Preflight handshake (SPEC.md §3)
  if (body && body.type === 'agent-games.preflight.v1') {
    console.log('[agent] preflight received — responding ok');
    return sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
  }

  if (!body || (body.type !== 'agent-games.proof-gatekeeper.v1' && !body.input)) {
    return sendJson(res, 400, { ok: false, error: 'unknown_type' });
  }

  const taskId = typeof body.task_id === 'string' ? body.task_id : null;
  if (taskId && responseCache.has(taskId)) {
    console.log(`[agent] idempotent retry for task ${taskId} — returning cached response`);
    return sendJson(res, 200, responseCache.get(taskId));
  }
  if (body.deadline_at) {
    const dl = Date.parse(body.deadline_at);
    if (!Number.isNaN(dl) && Date.now() > dl) {
      console.log(`[agent] WARNING: task ${taskId || '?'} arrived after its deadline_at`);
    }
  }

  const { decision, reason_code } = decide(body.input);

  // Groth16 proof: required on every provable task; PROOF_REUSED tasks have
  // no proof to submit (event page). Proof module returns null gracefully if
  // generation is unavailable — the decision is still returned (fail-closed
  // scoring impact is documented in README, never a crash).
  let proof = null;
  let publicSignals = null;
  if (PROOF_ENABLED && reason_code !== 'PROOF_REUSED' && reason_code !== 'INVALID_TASK') {
    try {
      const out = await generateDecisionProof(body.input, decision === 'APPROVE' ? 1 : 0, taskId);
      if (out) { proof = out.proof; publicSignals = out.publicSignals; }
    } catch (e) {
      console.log('[agent] proof generation error (returning decision without proof):', e.message);
    }
  }

  const responseBody = sendJson(res, 200, {
    decision,
    reason_code,
    proof,
    public_signals: publicSignals,
    proof_tx: typeof body.input.proof_tx === 'string' ? body.input.proof_tx : null,
  });
  if (taskId) responseCache.set(taskId, responseBody);
  console.log(`[agent] task ${taskId || '?'} -> ${decision}/${reason_code} proof=${proof ? 'yes' : 'no'}`);
  return responseBody;
}

const server = http.createServer((req, res) => {
  const url = (req.url || '/').split('?')[0];
  if (req.method === 'GET' && url === '/health') {
    return sendJson(res, 200, { ok: true, service: 'proof-gatekeeper', protocolVersion: 'v1' });
  }
  if (req.method === 'POST' && (url === '/task' || url === '/agent' || url === '/')) {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const rawBody = Buffer.concat(chunks);
      // Verify BEFORE parsing (official requirement).
      if (!signatureValid(rawBody, req.headers['x-agent-games-signature'])) {
        console.log('[agent] inbound signature mismatch — 401');
        return sendJson(res, 401, { ok: false, error: 'invalid_signature' });
      }
      handleTask(req, res, rawBody).catch((e) => {
        console.error('[agent] handler error:', e);
        // Fail closed.
        if (!res.headersSent) sendJson(res, 200, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR', proof: null, public_signals: null, proof_tx: null });
      });
    });
    req.on('error', () => { try { res.destroy(); } catch { /* noop */ } });
    return;
  }
  return sendJson(res, 404, { ok: false, error: 'not_found' });
});

if (require.main === module) {
  server.listen(PORT, () => console.log(`[agent] proof-gatekeeper listening on :${PORT}`));
}

module.exports = { server, decide };
