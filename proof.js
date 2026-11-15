'use strict';
/**
 * Groth16 proof generation for the gatekeeper circuit — isolated module.
 *
 * Circuit input signal names are NOT published on agentgames.zkverify.io and
 * are NOT stored in the wasm/zkey (the wasm only carries FNV-1a hashes of the
 * names). The names below were recovered by a prior participant by probing
 * the wasm (Creator Track write-up, @djarot) and — decisively — CONFIRMED
 * locally on 15 Nov 2026: with these names, snarkjs groth16.fullProve builds
 * a witness for the valid scenario and groth16.verify returns OK against the
 * official verification key (see work/winning-input.json, work/verify-proof.js).
 *
 * Signals (13): registeredVkHash, proofVkHash, minimum, publicBalance,
 *   expiryBlock, currentBlock, recipient, conditionRecipient, amount,
 *   maxTransfer, decision, taskId, salt (private).
 *
 * Encodings confirmed locally:
 *  - vk hashes: 32-byte hex -> BigInt -> reduced mod the BN128 field prime.
 *  - addresses: hex -> BigInt -> decimal string.
 *  - decision: "1" = APPROVE, "0" = REJECT. The circuit enforces
 *    decision == 1 IFF every check passes, so a proof can only be generated
 *    when the decision matches the field values; fullProve throws otherwise
 *    and this module returns null.
 *  - salt: free private input; any value works locally (proven: "12345",
 *    default below). The platform cannot check a private input.
 *
 * NOT yet confirmed against the live platform (needs a practice task):
 *  - the taskId mapping (envelope task_id is a string like "gk_24_9d1";
 *    below: numeric ids pass through, other strings are sha256-hashed into
 *    the field). If the platform expects a different taskId public signal,
 *    proofs would fail platform-side re-verification — check with practice
 *    mode first at go-live.
 *
 * This module NEVER throws to its caller: any failure returns null and the
 * agent still returns its (fail-closed) decision without a proof.
 */
const path = require('path');
const crypto = require('crypto');

let snarkjs = null;
try { snarkjs = require('snarkjs'); } catch { snarkjs = null; }

const WASM = process.env.GATEKEEPER_WASM || path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm');
const ZKEY = process.env.GATEKEEPER_ZKEY || path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey');
// Registered gatekeeper vk hash, from https://agentgames.zkverify.io/api/circuit-info
const GATEKEEPER_VK_HASH =
  process.env.GATEKEEPER_VK_HASH ||
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const SALT = process.env.GATEKEEPER_SALT || '0';

function fieldFromValue(v) {
  if (v === undefined || v === null) return null;
  try {
    if (typeof v === 'number') {
      if (!Number.isSafeInteger(v)) return null;
      return (BigInt(v) % FIELD_P).toString();
    }
    if (typeof v === 'string') {
      const s = v.trim();
      if (/^0x[0-9a-fA-F]+$/.test(s) || /^-?\d+$/.test(s)) {
        return (BigInt(s) % FIELD_P).toString();
      }
    }
  } catch { /* fall through */ }
  return null;
}

function taskIdField(taskId) {
  if (taskId === undefined || taskId === null) return '0';
  const s = String(taskId);
  if (/^\d+$/.test(s)) return (BigInt(s) % FIELD_P).toString();
  const h = crypto.createHash('sha256').update(s, 'utf8').digest('hex');
  return (BigInt('0x' + h) % FIELD_P).toString();
}

function buildCircuitInput(input, decision, taskId) {
  if (!input || typeof input !== 'object') return null;
  const registeredVkHash = fieldFromValue(input.registered_vk) || fieldFromValue(GATEKEEPER_VK_HASH);
  const proofVkHash = fieldFromValue(input.proof_vk);
  const minimum = fieldFromValue(input.minimum);
  const publicBalance = fieldFromValue(input.public_balance);
  const expiryBlock = fieldFromValue(input.expiry_block);
  const currentBlock = fieldFromValue(input.current_block);
  const recipient = fieldFromValue(input.recipient);
  const conditionRecipient = fieldFromValue(input.condition_recipient);
  const amount = fieldFromValue(input.amount);
  const maxTransfer = fieldFromValue(input.max_transfer);
  const parts = {
    registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
    currentBlock, recipient, conditionRecipient, amount, maxTransfer,
  };
  if (Object.values(parts).some((x) => x === null)) return null;
  return {
    ...parts,
    decision: decision ? '1' : '0',
    taskId: taskIdField(taskId),
    salt: SALT,
  };
}

async function generateDecisionProof(input, decision, taskId) {
  if (!snarkjs) {
    console.log('[proof] snarkjs not available — proof skipped');
    return null;
  }
  const circuitInput = buildCircuitInput(input, decision, taskId);
  if (!circuitInput) {
    console.log('[proof] could not map task fields to circuit inputs — proof skipped');
    return null;
  }
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM, ZKEY);
    return { proof, publicSignals };
  } catch (e) {
    console.log('[proof] fullProve failed:', String((e && e.message) || e).slice(0, 200));
    return null;
  }
}

module.exports = { generateDecisionProof, buildCircuitInput };
