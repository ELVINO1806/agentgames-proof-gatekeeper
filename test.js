'use strict';
/**
 * Local end-to-end test for the Proof Gatekeeper agent.
 * Starts index.js as a child process (test port, test HMAC secret, temp
 * seen-set file), then replays: health, preflight, bad signature, the valid
 * case, each of the 6 trap types, a proof-reuse second submission, and an
 * idempotent retry of the original task.
 * Run: node test.js   (exit code 0 = all pass)
 */
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PORT = 8899;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = 'test-secret-for-local-tests';
const SEEN_FILE = path.join(os.tmpdir(), `gatekeeper-test-seen-${Date.now()}.json`);

const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const ADDR = '0x1234567890aBcdef1234567890Abcdef12345678';
const ADDR2 = '0x1234567890aBcdef1234567890Abcdef12345679';
const tx = (n) => '0x' + 'a'.repeat(62) + String(n).padStart(2, '0');

function envelope(taskId, overrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: ADDR,
      condition_recipient: ADDR,
      amount: '500',
      max_transfer: '1000',
      proof_tx: tx(1),
      ...overrides,
    },
  };
}

function sign(raw) {
  return crypto.createHmac('sha256', SECRET).update(raw, 'utf8').digest('hex');
}

async function post(bodyObj, { signed = true, badSig = false } = {}) {
  const raw = JSON.stringify(bodyObj);
  const headers = { 'content-type': 'application/json' };
  if (signed) headers['x-agent-games-signature'] = badSig ? 'deadbeef'.repeat(8) : sign(raw);
  const res = await fetch(`${BASE}/task`, { method: 'POST', headers, body: raw });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* keep null */ }
  return { status: res.status, json, sigHeader: res.headers.get('x-agent-games-signature'), rawBody: text };
}

const results = [];
function check(name, cond, extra = '') {
  results.push({ name, pass: !!cond });
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? ' — ' + extra : ''}`);
}

async function waitForHealth(tries = 50) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

(async () => {
  const child = spawn('node', ['index.js'], {
    cwd: __dirname,
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: SECRET,
      SEEN_FILE,
      GATEKEEPER_WASM: path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm'),
      GATEKEEPER_ZKEY: path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stderr.on('data', (d) => process.stderr.write(`[server] ${d}`));

  try {
    check('server starts and /health responds', await waitForHealth());

    // Preflight handshake
    const pf = await post({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
    check('preflight -> { ok: true, protocolVersion: "v1" }', pf.status === 200 && pf.json && pf.json.ok === true && pf.json.protocolVersion === 'v1');
    check('preflight response is HMAC-signed', pf.sigHeader === sign(pf.rawBody));

    // Bad signature -> 401 before any processing
    const bad = await post(envelope('gk_bad_sig'), { badSig: true });
    check('bad inbound signature -> 401', bad.status === 401);

    // Valid case
    const valid = await post(envelope('gk_valid_1'));
    check('VALID_CONDITION -> APPROVE', valid.json && valid.json.decision === 'APPROVE' && valid.json.reason_code === 'VALID_CONDITION',
      valid.json ? `${valid.json.decision}/${valid.json.reason_code}` : 'no json');
    check('valid case carries a Groth16 proof', !!(valid.json && valid.json.proof && valid.json.proof.pi_a));
    check('valid case carries 13 public signals', !!(valid.json && Array.isArray(valid.json.public_signals) && valid.json.public_signals.length === 13));
    check('task response is HMAC-signed', valid.sigHeader === sign(valid.rawBody));

    // Trap cases: distinct task_id + distinct proof_tx each
    const traps = [
      ['VK_SUBSTITUTION', { proof_vk: '0x1111111111111111111111111111111111111111111111111111111111111111', proof_tx: tx(2) }],
      ['THRESHOLD_MISMATCH', { public_balance: '900', proof_tx: tx(3) }],
      ['EXPIRED_CONDITION', { current_block: 8430001, proof_tx: tx(4) }],
      ['RECIPIENT_MISMATCH', { condition_recipient: ADDR2, proof_tx: tx(5) }],
      ['AMOUNT_OVERFLOW', { amount: '1500', proof_tx: tx(6) }],
    ];
    let n = 10;
    for (const [reason, overrides] of traps) {
      const r = await post(envelope(`gk_trap_${n++}`, overrides));
      check(`${reason} -> REJECT/${reason}`, r.json && r.json.decision === 'REJECT' && r.json.reason_code === reason,
        r.json ? `${r.json.decision}/${r.json.reason_code}` : 'no json');
      check(`${reason} response carries a proof (decision=0 is provable)`, !!(r.json && r.json.proof && r.json.proof.pi_a));
    }

    // Proof reuse: same proof_tx as the valid case, NEW task_id
    const reuse = await post(envelope('gk_reuse_1'));
    check('PROOF_REUSED -> REJECT/PROOF_REUSED', reuse.json && reuse.json.decision === 'REJECT' && reuse.json.reason_code === 'PROOF_REUSED',
      reuse.json ? `${reuse.json.decision}/${reuse.json.reason_code}` : 'no json');
    check('PROOF_REUSED response has no proof (per official scoring note)', !!(reuse.json && reuse.json.proof === null));

    // Idempotent retry: exact same task_id as the valid case -> cached APPROVE
    const retry = await post(envelope('gk_valid_1'));
    check('idempotent retry of same task_id -> cached APPROVE (not PROOF_REUSED)',
      retry.json && retry.json.decision === 'APPROVE' && retry.json.reason_code === 'VALID_CONDITION');

    // Seen-set persisted to disk
    const seenOnDisk = JSON.parse(fs.readFileSync(SEEN_FILE, 'utf8'));
    check('seen-set persisted to file', Array.isArray(seenOnDisk) && seenOnDisk.includes(tx(1).toLowerCase()));
  } finally {
    child.kill('SIGTERM');
    try { fs.unlinkSync(SEEN_FILE); } catch { /* noop */ }
  }

  const failed = results.filter((r) => !r.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  process.exit(failed.length ? 1 : 0);
})().catch((e) => { console.error('TEST CRASH', e); process.exit(2); });
