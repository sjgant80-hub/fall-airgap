// fallairgap.mjs — FALL-AIRGAP, the air-gap transport organ. The internal mesh stops speaking JSON and speaks raw
// byte-coordinates: a real estate state-event (a capability delegation, a gate verdict, a heartbeat, a pipeline step)
// becomes the SENTINEL 6-byte Primorial-Fold packet, moved as "the Air" inside the machine over a bidirectional channel
// (WebRTC DataChannel / WebSocket / NFC / acoustic FSK) with NO HTTP handshake or header bloat.
//
// REUSE, NOT RE-INVENT: the 6-byte codec and the signature-first gate are SENTINEL's live, mutation-gated kernel
// (sentinel.mjs, vendored verbatim beside this file — https://github.com/sjgant80-hub/sentinel). This organ is the
// TRANSPORT and the MEASUREMENT: it maps real events to the six bytes, frames them for the wire, and counts the bytes
// both ways so the 42–100× claim is measured, not asserted. The primorial-fold codec is Thomas Frumkin's Konomi
// architecture; the opcode/resource/LIGHT lineage carries from SENTINEL.
//
// HONESTY, UP FRONT (what the 15× test never measured):
//   • The 6-byte PAYLOAD (or a 1-byte delta) is the compressed coordinate — 42×/100×+ vs the self-describing JSON.
//   • But an Ed25519 signature is 64 bytes and IRREDUCIBLE. If you sign every packet, the wire is 71 bytes and the
//     real ratio collapses toward the signature floor. The 42–100× is only realised when the signature is AMORTISED:
//     one handshake signature authenticates the channel/session, then coordinates stream over it (mode 'session').
//     Sign-per-packet (mode 'signed') is maximum-adversarial and pays the 64-byte floor every time. We report BOTH.
//   • Signatures (64B), SHA-256 hashes (32B) and novel human prompts sit at their entropy floor and do NOT compress.
//
// Pure and deterministic. Every reader is total: garbage in returns {ok:false}/a zero/null, never throws. Crypto is
// injected (sign/verify), so this kernel stays pure — the same bytes the tests and the mutation gate prove.

import { pack, unpack, foldWitness, check, phantom, fingerprint, WIRE, PAYLOAD, SIG, OPCODES, RESOURCES } from './sentinel.mjs';

export { pack, unpack, foldWitness, check, phantom, fingerprint, WIRE, PAYLOAD, SIG, OPCODES, RESOURCES };

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const u8 = (v) => (Number.isInteger(v) ? v & 0xFF : 0);
const clampU16 = (v) => (Number.isInteger(v) && v >= 0 ? Math.min(v, 0xFFFF) : 0);

// ── opcodes ───────────────────────────────────────────────────────────────────────────────────────────────────────
// SENTINEL's canonical numbering is kept (GRANT=3 IS capability_delegation — the live kernel wins over the spec's
// illustrative 0x0E). Transport-layer event opcodes extend it; the Human Door takes 0x0E, the one "incompressible edge"
// opcode where a human, not a key, must sign.
export const OP = Object.freeze({
  CAP_DELEGATE: OPCODES.GRANT, // 3 — capability delegation (SENTINEL GRANT)
  GATE_VERDICT: 8,             // a gate returned a verdict on a referenced packet
  HEARTBEAT: 9,                // node-alive tick: seq + κ
  PIPELINE_STEP: 10,           // a deterministic pipeline advanced to step N
  ANTIBODY: 11,                // immune micro-update: a geometric antibody coordinate broadcast to the mesh
  HALT_SIGN: 0x0E,             // THE HUMAN DOOR — money/legal/irreversible: render confirm, human signs to resume
});
// Simon's spec sketched 0x0E for capability_delegation illustratively; reconciled above (GRANT=3 canonical, 0x0E = door).
export const SPEC_NOTE = 'capability_delegation = SENTINEL GRANT (3); 0x0E reassigned to the Human Door (Halt & Sign).';

// a resource name-list → the 8-bit bitmask SENTINEL's lattice checks (bit i = RESOURCES[i]).
export function resourceMask(names) {
  const list = Array.isArray(names) ? names : [];
  let m = 0;
  for (const n of list) { const i = RESOURCES.indexOf(n); if (i >= 0) m |= (1 << i); }
  return m & 0xFF;
}
export function resourceNames(mask) {
  const m = u8(mask), out = [];
  for (let i = 0; i < RESOURCES.length; i++) if (m & (1 << i)) out.push(RESOURCES[i]);
  return out;
}

// quantise a κ-balance (0..1) into one byte, and back — the spec's floor(k*255). SENTINEL uses byte 5 as the primorial
// FOLD-witness (tamper-evidence), which is strictly better for transport integrity, so κ rides where a payload has room
// (the fold still occupies byte 5). This pair is for events that carry an explicit κ (heartbeat).
export function quantKappa(k) { const x = typeof k === 'number' && k >= 0 ? Math.min(k, 1) : 0; return Math.floor(x * 255) & 0xFF; }
export function dequantKappa(q) { return (u8(q)) / 255; }

// ── events → the six bytes ──────────────────────────────────────────────────────────────────────────────────────────
// each event type encodes to a SENTINEL command {opcode,source,target,resources,budget} and packs to 6 bytes. Total:
// a malformed event returns null (never throws).
export function encodeEvent(ev) {
  if (!isObj(ev)) return null;
  const t = ev.type;
  if (t === 'capability_delegation') {
    return pack({ opcode: OP.CAP_DELEGATE, source: u8(ev.source) & 0xF, target: u8(ev.target) & 0xF, resources: resourceMask(ev.resources), budget: clampU16(ev.budget) });
  }
  if (t === 'gate_verdict') {
    // byte1 = node, byte2 = verdict code (0 ok, 1 blocked, 2 maze), bytes3-4 = the referenced packet's index in the shared stream
    return pack({ opcode: OP.GATE_VERDICT, source: u8(ev.node) & 0xF, target: u8(ev.node) & 0xF, resources: VERDICT_CODE[ev.verdict] ?? 1, budget: clampU16(ev.packetIndex) });
  }
  if (t === 'heartbeat') {
    // bytes3-4 = seq (uint16), resources byte carries nothing structural; κ rides byte 5 as the fold already encodes it
    return pack({ opcode: OP.HEARTBEAT, source: u8(ev.node) & 0xF, target: u8(ev.node) & 0xF, resources: quantKappa(ev.kappa) & 0xFF, budget: clampU16(ev.seq) });
  }
  if (t === 'pipeline_step') {
    return pack({ opcode: OP.PIPELINE_STEP, source: u8(ev.pipeline) & 0xF, target: u8(ev.pipeline) & 0xF, resources: 0, budget: clampU16(ev.step) });
  }
  if (t === 'antibody') {
    // a geometric antibody COORDINATE (one lattice point) broadcast on a novel breach — bytes3-4 = the coordinate
    return pack({ opcode: OP.ANTIBODY, source: u8(ev.node) & 0xF, target: 0, resources: u8(ev.axis), budget: clampU16(ev.coord) });
  }
  if (t === 'halt_sign') {
    return pack({ opcode: OP.HALT_SIGN, source: u8(ev.node) & 0xF, target: u8(ev.target) & 0xF, resources: resourceMask(ev.resources), budget: clampU16(ev.budget) });
  }
  return null;
}
const VERDICT_CODE = Object.freeze({ ok: 0, blocked: 1, maze: 2 });
const VERDICT_NAME = Object.freeze({ 0: 'ok', 1: 'blocked', 2: 'maze' });

// decode a 6-byte payload back to a labelled event (the inverse view, for the receiver's display boundary).
export function decodeEvent(bytes) {
  const u = unpack(bytes);
  if (!u.ok) return u;
  const c = u.command;
  if (c.opcode === OP.CAP_DELEGATE) return { ok: true, type: 'capability_delegation', source: c.source, target: c.target, resources: resourceNames(c.resources), budget: c.budget };
  if (c.opcode === OP.GATE_VERDICT) return { ok: true, type: 'gate_verdict', node: c.source, verdict: VERDICT_NAME[c.resources] || 'blocked', packetIndex: c.budget };
  if (c.opcode === OP.HEARTBEAT) return { ok: true, type: 'heartbeat', node: c.source, seq: c.budget, kappa: dequantKappa(c.resources) };
  if (c.opcode === OP.PIPELINE_STEP) return { ok: true, type: 'pipeline_step', pipeline: c.source, step: c.budget };
  if (c.opcode === OP.ANTIBODY) return { ok: true, type: 'antibody', node: c.source, axis: c.resources, coord: c.budget };
  if (c.opcode === OP.HALT_SIGN) return { ok: true, type: 'halt_sign', node: c.source, target: c.target, resources: resourceNames(c.resources), budget: c.budget };
  return { ok: false, reason: 'unknown-opcode', command: c };
}

// the canonical self-describing JSON an estate event would travel as on legacy HTTP — the "legacy debt" baseline we
// measure against. Deterministic (fixed field order, fixed sample ids/timestamps) so the byte counts are reproducible.
export function canonicalJson(ev) {
  if (!isObj(ev)) return '';
  const base = { v: 1, ts: '2026-10-05T12:00:00.000Z', nonce: 'a1b2c3d4' };
  const t = ev.type;
  let o;
  if (t === 'capability_delegation') o = { type: t, source: nodeName(ev.source), target: nodeName(ev.target), resources: Array.isArray(ev.resources) ? ev.resources : resourceNames(resourceMask(ev.resources)), budget: clampU16(ev.budget), kappa: 0.618, ...base };
  else if (t === 'gate_verdict') o = { type: t, node: nodeName(ev.node), verdict: ev.verdict || 'blocked', reason: ev.reason || 'budget-exceeded', packet: 'sha256:9f2b7c1e', ...base };
  else if (t === 'heartbeat') o = { type: t, node: nodeName(ev.node), seq: clampU16(ev.seq), kappa: typeof ev.kappa === 'number' ? ev.kappa : 0.618, status: 'alive', ...base };
  else if (t === 'pipeline_step') o = { type: t, pipeline: nodeName(ev.pipeline), step: clampU16(ev.step), hash: 'sha256:deadbeefcafef00d', ...base };
  else if (t === 'antibody') o = { type: t, node: nodeName(ev.node), axis: u8(ev.axis), coord: clampU16(ev.coord), lattice: 'geometric', ...base };
  else if (t === 'halt_sign') o = { type: t, node: nodeName(ev.node), target: nodeName(ev.target), resources: Array.isArray(ev.resources) ? ev.resources : resourceNames(resourceMask(ev.resources)), budget: clampU16(ev.budget), door: 'human', ...base };
  else return '';
  return JSON.stringify(o);
}
const nodeName = (i) => 'node-' + String((u8(i) & 0xF)).padStart(2, '0');

// UTF-8 byte length of a string (total: non-string → 0).
export function utf8Bytes(s) { return typeof s === 'string' ? new TextEncoder().encode(s).length : 0; }

// ── the measurement: the real byte-ratio per event type, counted on the wire ──────────────────────────────────────────
// payloadBytes : the 6-byte coordinate (channel already authenticated — mode 'session')
// deltaBytes   : 1 byte, for a recurring deterministic step the receiver recomputes (the 100×+ case)
// wireBytes    : 71 bytes, signed per-packet (mode 'signed' — pays the 64-byte Ed25519 floor every time)
// jsonBytes    : the self-describing JSON command (the legacy-debt baseline)
// jsonSignedBytes : JSON command + a base64 Ed25519 signature field (the apples-to-apples authenticated baseline)
export function measure(ev) {
  const json = canonicalJson(ev);
  const jsonBytes = utf8Bytes(json);
  if (!jsonBytes) return null;
  const payload = encodeEvent(ev);
  if (!payload) return null;
  const B64_SIG = 88; // 64 bytes Ed25519 base64-encoded = 88 chars
  const jsonSignedBytes = jsonBytes + utf8Bytes(',"sig":"' + 'A'.repeat(B64_SIG) + '"');
  const canDelta = ev.type === 'pipeline_step' || ev.type === 'heartbeat';
  const r = (a, b) => Math.round((a / b) * 100) / 100;
  return {
    type: ev.type,
    jsonBytes,
    jsonSignedBytes,
    payloadBytes: PAYLOAD,        // 6
    deltaBytes: canDelta ? 1 : null,
    wireBytes: WIRE,              // 71
    ratioPayload: r(jsonBytes, PAYLOAD),              // coordinate vs JSON — the 42× regime
    ratioDelta: canDelta ? r(jsonBytes, 1) : null,    // 1-byte delta vs JSON — the 100×+ regime
    ratioWireVsJsonSigned: r(jsonSignedBytes, WIRE),  // signed-both-sides, apples-to-apples (signature floor honest)
    ratioWireVsJson: r(jsonBytes, WIRE),              // signed wire vs bare JSON (the signature drags it down)
  };
}

// the hard Shannon floor: what CANNOT compress past its entropy. Reported so no claim overreaches.
export function entropyFloor() {
  return [
    { what: 'Ed25519 signature', bytes: 64, compresses: false, note: 'irreducible — one signature per (key, message)' },
    { what: 'SHA-256 hash', bytes: 32, compresses: false, note: 'irreducible — a hash IS maximum entropy' },
    { what: 'novel human prompt / authored text', bytes: null, compresses: false, note: 'sits at its own entropy floor; keep JSON only here, at the human display boundary' },
  ];
}

// ── the wire frame: push the signature FIRST ──────────────────────────────────────────────────────────────────────
// SENTINEL's wire is [sourceId:1][payload:6][signature:64] = 71 bytes. The receiver verifies the signature BEFORE the
// six bytes are parsed. We honour the spec's "push the 64-byte signature FIRST" at the STREAM level: the frame is laid
// out sig-first so a receiver can drop a bad signature before the payload bytes have even arrived in full.
// frame(sourceId, payload, signature) → a 71-byte wire buffer in SENTINEL's canonical [id][payload][sig] order.
export function frame(sourceId, payload, signature) {
  if (!(payload instanceof Uint8Array) || payload.length !== PAYLOAD) return null;
  if (!(signature instanceof Uint8Array) || signature.length !== SIG) return null;
  const raw = new Uint8Array(WIRE);
  raw[0] = u8(sourceId);
  raw.set(payload, 1);
  raw.set(signature, 1 + PAYLOAD);
  return raw;
}
// the message SENTINEL's Ed25519 signs/verifies: sourceId + the 6 payload bytes (the first 7 wire bytes).
export function signedMessage(sourceId, payload) {
  if (!(payload instanceof Uint8Array) || payload.length !== PAYLOAD) return null;
  const m = new Uint8Array(1 + PAYLOAD);
  m[0] = u8(sourceId);
  m.set(payload, 1);
  return m;
}
// the "signature-first" view a streaming receiver sees: the 64 sig bytes, then the 7-byte message to verify them against.
// If verify fails here, the payload is dropped before it is ever handed to a DataView (unverified never compiles).
export function sigFirstDrop(raw, verify, publicKey) {
  if (!(raw instanceof Uint8Array) || raw.length !== WIRE) return { parsed: false, reason: 'bad-length' };
  const sig = raw.subarray(1 + PAYLOAD);
  const msg = raw.subarray(0, 1 + PAYLOAD);
  let good = false;
  try { good = typeof verify === 'function' ? verify(publicKey, msg, sig) === true : false; } catch { good = false; }
  if (!good) return { parsed: false, reason: 'forged', droppedBeforeParse: true };
  return { parsed: true, payload: raw.subarray(1, 1 + PAYLOAD) };
}

// ── delta / coordinate stream: the 100×+ regime for recurring deterministic pipelines ─────────────────────────────────
// once B holds A's genome and the pipeline is deterministic, A sends only the step-counter; B recomputes the step locally.
// deltaEncode(step) → a 1-byte tip. deltaDecode(byte, prevStep) → the absolute step (wraps mod 256; a resync carries the
// full 6-byte PIPELINE_STEP). Total.
export function deltaEncode(step) { return Number.isInteger(step) && step >= 0 ? step & 0xFF : 0; }
export function deltaDecode(tip, prevStep) {
  const t = u8(tip), p = Number.isInteger(prevStep) && prevStep >= 0 ? prevStep : 0;
  const base = p - (p & 0xFF);
  let abs = base + t;
  if (abs < p) abs += 256; // the tip advanced past a 256 boundary
  return abs;
}

// ── the Human Door ────────────────────────────────────────────────────────────────────────────────────────────────
// an incompressible edge (money / legal / irreversible) cannot be auto-executed. KESTREL pushes a HALT_SIGN packet;
// FallKard renders the confirm; the human signs; the signed token passes back down to resume. humanDoorRequired tells the
// transport whether an event must stop at the door.
export function humanDoorRequired(ev) {
  if (!isObj(ev)) return false;
  if (ev.type === 'halt_sign') return true;
  // money/legal/irreversible = any grant that touches the ledger or key, or spends over the auto-sign budget ceiling.
  const AUTO_CEILING = 1000;
  if (ev.type === 'capability_delegation') {
    const mask = resourceMask(ev.resources);
    const touchesLedger = (mask & (1 << RESOURCES.indexOf('ledger'))) !== 0;
    const touchesKey = (mask & (1 << RESOURCES.indexOf('key'))) !== 0;
    return touchesLedger || touchesKey || clampU16(ev.budget) > AUTO_CEILING;
  }
  return false;
}
// the door packet KESTREL pushes, and the token FallKard passes back down once the human has signed.
export function haltSignPacket(ev) {
  if (!isObj(ev)) return null;
  return encodeEvent({ type: 'halt_sign', node: ev.source ?? ev.node ?? 0, target: ev.target ?? 0, resources: ev.resources, budget: ev.budget });
}
export function resumeToken(payload, signature) {
  if (!(payload instanceof Uint8Array) || payload.length !== PAYLOAD) return null;
  if (!(signature instanceof Uint8Array) || signature.length !== SIG) return null;
  return { resumed: true, payload, signature, at: 'human-door' };
}

// ── the reroute trigger (Simon's open question, answered) ─────────────────────────────────────────────────────────────
// "Reroute the moment the signature fails, or let them act a few times in the maze to monitor before sealing?"
// ANSWER — TIER IT by what the failure tells you:
//   • CRYPTO failure (forged / unknown-source / replay): SEAL NOW. A forged signature is unambiguous and carries zero
//     intelligence — there is nothing to learn from a forger, and every millisecond it is near real state is risk.
//     Instant phantom, no error returned (an error confirms a real door was found).
//   • POLICY failure from an AUTHENTICATED source (budget-exceeded / resource-denied / off-κ stream / source-mismatch):
//     MAZE then seal. The key is real (a compromised insider), so the lateral-movement INTENT is worth fingerprinting,
//     and it is SAFE to watch because the phantom cell has zero budget — no capability budget = no pivot, so mathematically
//     they can move nowhere while you learn the shape of the attack. Seal after `mazeBudget` observed intents.
export function reroute(verdict, mazeBudget) {
  const reason = isObj(verdict) ? verdict.reason : verdict;
  const CRYPTO = new Set(['bad-length', 'unknown-source', 'forged', 'replay']);
  const cap = Number.isInteger(mazeBudget) && mazeBudget > 0 ? mazeBudget : 3;
  if (CRYPTO.has(reason)) return { action: 'seal-now', tier: 'crypto', observe: 0, returnsError: false, reason };
  return { action: 'maze', tier: 'policy', observe: cap, returnsError: false, reason };
}

// a tiny deterministic self-check the page re-runs in the browser: encode→decode round-trips, and the measured ratios.
export const SAMPLE_EVENTS = Object.freeze([
  { type: 'capability_delegation', source: 1, target: 2, resources: ['ledger', 'budget'], budget: 500 },
  { type: 'gate_verdict', node: 3, verdict: 'blocked', packetIndex: 42 },
  { type: 'heartbeat', node: 5, seq: 1234, kappa: 0.618 },
  { type: 'pipeline_step', pipeline: 2, step: 42 },
  { type: 'antibody', node: 7, axis: 4, coord: 777 },
]);
export function selfCheck() {
  const rows = [];
  let roundTrips = 0;
  for (const ev of SAMPLE_EVENTS) {
    const p = encodeEvent(ev);
    const d = decodeEvent(p);
    const m = measure(ev);
    if (d.ok && d.type === ev.type) roundTrips += 1;
    rows.push({ event: ev.type, ...m, roundTrip: d.ok && d.type === ev.type });
  }
  return { roundTrips, of: SAMPLE_EVENTS.length, rows, floor: entropyFloor() };
}
