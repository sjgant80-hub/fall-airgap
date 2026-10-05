// fallairgap.test.mjs — the proof the mutation gate runs against. Real Ed25519 (node:crypto) drives the SENTINEL
// signature-first gate; the transport readers are checked total (garbage never throws) and reversible.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as edSign, verify as edVerify } from 'node:crypto';
import {
  OP, SPEC_NOTE, resourceMask, resourceNames, quantKappa, dequantKappa,
  encodeEvent, decodeEvent, canonicalJson, utf8Bytes, measure, entropyFloor,
  frame, signedMessage, sigFirstDrop, deltaEncode, deltaDecode,
  humanDoorRequired, haltSignPacket, resumeToken, reroute, selfCheck, SAMPLE_EVENTS,
  pack, unpack, check, WIRE, PAYLOAD, SIG, RESOURCES,
} from './fallairgap.mjs';

// a real Ed25519 keypair + a verify fn shaped for SENTINEL's check(ctx.verify)
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const verify = (key, msg, sig) => edVerify(null, Buffer.from(msg), key, Buffer.from(sig));
const signPayload = (sourceId, payload) => new Uint8Array(edSign(null, Buffer.from(signedMessage(sourceId, payload)), privateKey));

test('OP table keeps SENTINEL GRANT for delegation and 0x0E for the human door', () => {
  assert.equal(OP.CAP_DELEGATE, 3);
  assert.equal(OP.HALT_SIGN, 0x0E);
  assert.equal(OP.HEARTBEAT, 9);
  assert.equal(OP.PIPELINE_STEP, 10);
  assert.match(SPEC_NOTE, /Human Door/);
});

test('resourceMask / resourceNames round-trip and ignore unknowns', () => {
  const mask = resourceMask(['ledger', 'budget']);
  assert.equal(mask, (1 << RESOURCES.indexOf('ledger')) | (1 << RESOURCES.indexOf('budget')));
  assert.deepEqual(resourceNames(mask), ['ledger', 'budget']);
  assert.equal(resourceMask(['not-a-resource']), 0);
  assert.equal(resourceMask('nope'), 0);
  assert.deepEqual(resourceNames(0), []);
});

test('quantKappa / dequantKappa quantise 0..1 to a byte', () => {
  assert.equal(quantKappa(0.618), Math.floor(0.618 * 255));
  assert.equal(quantKappa(1), 255);
  assert.equal(quantKappa(2), 255);      // clamped
  assert.equal(quantKappa(-1), 0);       // clamped
  assert.equal(quantKappa('x'), 0);
  assert.ok(Math.abs(dequantKappa(quantKappa(0.618)) - 0.618) < 0.01);
});

test('encodeEvent produces 6 bytes for every known type and null otherwise', () => {
  for (const ev of SAMPLE_EVENTS) {
    const p = encodeEvent(ev);
    assert.ok(p instanceof Uint8Array, ev.type);
    assert.equal(p.length, PAYLOAD, ev.type);
  }
  assert.equal(encodeEvent({ type: 'halt_sign', node: 1, target: 2, resources: ['ledger'], budget: 9 }).length, 6);
  assert.equal(encodeEvent({ type: 'nope' }), null);
  assert.equal(encodeEvent(null), null);
  assert.equal(encodeEvent('x'), null);
});

test('decodeEvent inverts encodeEvent for each type', () => {
  const cap = decodeEvent(encodeEvent({ type: 'capability_delegation', source: 1, target: 2, resources: ['ledger', 'budget'], budget: 500 }));
  assert.deepEqual(cap, { ok: true, type: 'capability_delegation', source: 1, target: 2, resources: ['ledger', 'budget'], budget: 500 });
  const gv = decodeEvent(encodeEvent({ type: 'gate_verdict', node: 3, verdict: 'blocked', packetIndex: 42 }));
  assert.deepEqual(gv, { ok: true, type: 'gate_verdict', node: 3, verdict: 'blocked', packetIndex: 42 });
  const hb = decodeEvent(encodeEvent({ type: 'heartbeat', node: 5, seq: 1234, kappa: 0.618 }));
  assert.equal(hb.type, 'heartbeat'); assert.equal(hb.seq, 1234); assert.ok(Math.abs(hb.kappa - 0.618) < 0.01);
  const ps = decodeEvent(encodeEvent({ type: 'pipeline_step', pipeline: 2, step: 42 }));
  assert.deepEqual(ps, { ok: true, type: 'pipeline_step', pipeline: 2, step: 42 });
  const ab = decodeEvent(encodeEvent({ type: 'antibody', node: 7, axis: 4, coord: 777 }));
  assert.deepEqual(ab, { ok: true, type: 'antibody', node: 7, axis: 4, coord: 777 });
  assert.equal(decodeEvent(new Uint8Array(3)).ok, false);          // bad length
});

test('gate_verdict codes map ok/blocked/maze', () => {
  assert.equal(decodeEvent(encodeEvent({ type: 'gate_verdict', node: 1, verdict: 'ok', packetIndex: 0 })).verdict, 'ok');
  assert.equal(decodeEvent(encodeEvent({ type: 'gate_verdict', node: 1, verdict: 'maze', packetIndex: 0 })).verdict, 'maze');
});

test('decodeEvent reports unknown opcode on a valid-fold packet that is not a known event', () => {
  const p = pack({ opcode: 200, source: 1, target: 1, resources: 0, budget: 0 });
  const d = decodeEvent(p);
  assert.equal(d.ok, false);
  assert.equal(d.reason, 'unknown-opcode');
});

test('canonicalJson is non-empty for known types, empty otherwise', () => {
  for (const ev of SAMPLE_EVENTS) assert.ok(canonicalJson(ev).length > 20, ev.type);
  assert.equal(canonicalJson({ type: 'nope' }), '');
  assert.equal(canonicalJson(null), '');
  assert.match(canonicalJson(SAMPLE_EVENTS[0]), /capability_delegation/);
});

test('utf8Bytes counts bytes and is total', () => {
  assert.equal(utf8Bytes('abc'), 3);
  assert.equal(utf8Bytes('é'), 2);   // é is 2 UTF-8 bytes
  assert.equal(utf8Bytes(123), 0);
});

test('measure returns real ratios; delta only where a step recurs', () => {
  const cap = measure({ type: 'capability_delegation', source: 1, target: 2, resources: ['ledger', 'budget'], budget: 500 });
  assert.equal(cap.payloadBytes, 6);
  assert.equal(cap.wireBytes, 71);
  assert.ok(cap.ratioPayload > 1);
  assert.equal(cap.deltaBytes, null);
  assert.equal(cap.ratioDelta, null);
  assert.ok(cap.ratioPayload === Math.round((cap.jsonBytes / 6) * 100) / 100);
  const hb = measure({ type: 'heartbeat', node: 5, seq: 1234, kappa: 0.618 });
  assert.equal(hb.deltaBytes, 1);
  assert.ok(hb.ratioDelta > hb.ratioPayload);
  assert.ok(hb.jsonSignedBytes > hb.jsonBytes);
  assert.equal(measure({ type: 'nope' }), null);
  assert.equal(measure(null), null);
});

test('entropyFloor names the irreducibles', () => {
  const f = entropyFloor();
  const sig = f.find((x) => /Ed25519/.test(x.what));
  const hash = f.find((x) => /SHA-256/.test(x.what));
  assert.equal(sig.bytes, 64); assert.equal(sig.compresses, false);
  assert.equal(hash.bytes, 32); assert.equal(hash.compresses, false);
});

test('frame builds the canonical 71-byte [id][payload][sig] wire; rejects wrong sizes', () => {
  const payload = encodeEvent(SAMPLE_EVENTS[0]);
  const sig = new Uint8Array(SIG).fill(7);
  const raw = frame(9, payload, sig);
  assert.equal(raw.length, WIRE);
  assert.equal(raw[0], 9);
  assert.deepEqual(raw.subarray(1, 1 + PAYLOAD), payload);
  assert.deepEqual(raw.subarray(1 + PAYLOAD), sig);
  assert.equal(frame(9, new Uint8Array(5), sig), null);   // bad payload
  assert.equal(frame(9, payload, new Uint8Array(10)), null); // bad sig
});

test('signedMessage is sourceId + the 6 payload bytes', () => {
  const payload = encodeEvent(SAMPLE_EVENTS[0]);
  const m = signedMessage(4, payload);
  assert.equal(m.length, 7);
  assert.equal(m[0], 4);
  assert.deepEqual(m.subarray(1), payload);
  assert.equal(signedMessage(4, new Uint8Array(3)), null);
});

test('sigFirstDrop: a real signature parses, a forged one is dropped BEFORE parse', () => {
  const payload = encodeEvent(SAMPLE_EVENTS[0]);
  const sig = signPayload(9, payload);
  const raw = frame(9, payload, sig);
  const good = sigFirstDrop(raw, verify, publicKey);
  assert.equal(good.parsed, true);
  assert.deepEqual(good.payload, payload);
  // forge: flip a payload byte so the signature no longer maps
  const tampered = raw.slice(); tampered[2] ^= 0xFF;
  const bad = sigFirstDrop(tampered, verify, publicKey);
  assert.equal(bad.parsed, false);
  assert.equal(bad.droppedBeforeParse, true);
  assert.equal(sigFirstDrop(new Uint8Array(10), verify, publicKey).parsed, false); // bad length
  assert.equal(sigFirstDrop(raw, null, publicKey).parsed, false); // no verifier
});

test('end-to-end through the SENTINEL gate: valid accepted, forged rejected before parse, replay caught', () => {
  const ev = { type: 'capability_delegation', source: 9, target: 2, resources: ['budget'], budget: 300 };
  const payload = pack({ opcode: OP.CAP_DELEGATE, source: 9, target: 2, resources: resourceMask(['budget']), budget: 300 });
  const sig = signPayload(9, payload);
  const raw = frame(9, payload, sig);
  const seen = new Set();
  const ctx = { keys: { 9: publicKey }, lattice: { 9: { maxBudget: 1000, resources: resourceMask(['budget']) } }, seen, verify };
  const v = check(raw, ctx);
  assert.equal(v.ok, true, v.reason);
  assert.equal(v.command.budget, 300);
  // replay the exact signed frame
  assert.equal(check(raw, ctx).reason, 'replay');
  // forge: tamper a byte, signature fails → 'forged' (payload never parsed)
  const forged = raw.slice(); forged[1] ^= 0x0F;
  assert.equal(check(forged, { ...ctx, seen: new Set() }).reason, 'forged');
  // over budget from a real key → budget-exceeded (a policy failure, not a crypto one)
  const big = pack({ opcode: OP.CAP_DELEGATE, source: 9, target: 2, resources: resourceMask(['budget']), budget: 5000 });
  const rawBig = frame(9, big, signPayload(9, big));
  assert.equal(check(rawBig, { ...ctx, seen: new Set() }).reason, 'budget-exceeded');
});

test('deltaEncode / deltaDecode: 1-byte tip, resolves across a 256 boundary', () => {
  assert.equal(deltaEncode(42), 42);
  assert.equal(deltaEncode(-1), 0);
  assert.equal(deltaDecode(42, 40), 42);
  assert.equal(deltaDecode(3, 254), 259);   // tip wrapped past 256
  assert.equal(deltaDecode(255, 10), 255);
});

test('humanDoorRequired stops money/legal/irreversible edges', () => {
  assert.equal(humanDoorRequired({ type: 'halt_sign' }), true);
  assert.equal(humanDoorRequired({ type: 'capability_delegation', resources: ['ledger'], budget: 10 }), true);
  assert.equal(humanDoorRequired({ type: 'capability_delegation', resources: ['key'], budget: 10 }), true);
  assert.equal(humanDoorRequired({ type: 'capability_delegation', resources: ['budget'], budget: 2000 }), true); // over ceiling
  assert.equal(humanDoorRequired({ type: 'capability_delegation', resources: ['budget'], budget: 10 }), false);
  assert.equal(humanDoorRequired({ type: 'heartbeat' }), false);
  assert.equal(humanDoorRequired(null), false);
});

test('haltSignPacket + resumeToken complete the door', () => {
  const p = haltSignPacket({ source: 1, target: 2, resources: ['ledger'], budget: 500 });
  assert.equal(decodeEvent(p).type, 'halt_sign');
  assert.equal(haltSignPacket(null), null);
  const sig = new Uint8Array(SIG).fill(1);
  const tok = resumeToken(p, sig);
  assert.equal(tok.resumed, true);
  assert.equal(tok.at, 'human-door');
  assert.equal(resumeToken(new Uint8Array(5), sig), null);
  assert.equal(resumeToken(p, new Uint8Array(5)), null);
});

test('reroute tiers the trigger: crypto = seal-now, policy = maze', () => {
  assert.equal(reroute('forged').action, 'seal-now');
  assert.equal(reroute({ reason: 'replay' }).action, 'seal-now');
  assert.equal(reroute('unknown-source').action, 'seal-now');
  assert.equal(reroute('bad-length').tier, 'crypto');
  const pol = reroute('budget-exceeded');
  assert.equal(pol.action, 'maze');
  assert.equal(pol.tier, 'policy');
  assert.equal(pol.observe, 3);
  assert.equal(reroute('resource-denied', 7).observe, 7);
  assert.equal(reroute('forged').returnsError, false);   // never confirm a real door was found
});

test('selfCheck round-trips all sample events and carries the floor', () => {
  const r = selfCheck();
  assert.equal(r.roundTrips, SAMPLE_EVENTS.length);
  assert.equal(r.of, 5);
  assert.equal(r.rows.length, 5);
  assert.ok(r.rows.every((x) => x.roundTrip));
  assert.ok(r.floor.length >= 2);
});

// ── mutation-gate hardening: boundaries the happy-path tests missed ──────────────────────────────────────────────────
test('resourceMask includes the index-0 resource (memory)', () => {
  // kills `i >= 0` → `i > 0`: 'memory' is RESOURCES[0], so i===0 must still set a bit
  assert.equal(RESOURCES.indexOf('memory'), 0);
  assert.equal(resourceMask(['memory']), 1);
  assert.deepEqual(resourceNames(1), ['memory']);
});

test('clampU16 via encodeEvent rejects a non-integer step by flooring the guard, not passing it', () => {
  // kills clampU16 `&&` → `||`: a non-integer budget/step must become 0 (valid 6 bytes), not pass through to pack as a non-integer (→ null)
  const p = encodeEvent({ type: 'pipeline_step', pipeline: 2, step: 0.5 });
  assert.ok(p instanceof Uint8Array);
  assert.equal(decodeEvent(p).step, 0);
});

test('canonicalJson heartbeat carries its default kappa and status even when absent', () => {
  // kills `typeof ev.kappa === 'number'` → `!==`: a heartbeat with no kappa must still emit 0.618, not undefined
  const j = canonicalJson({ type: 'heartbeat', node: 5, seq: 7 });
  assert.match(j, /"kappa":0\.618/);
  assert.match(j, /"status":"alive"/);
  // and an explicit kappa is used verbatim
  assert.match(canonicalJson({ type: 'heartbeat', node: 5, seq: 7, kappa: 0.5 }), /"kappa":0\.5/);
});

test('canonicalJson gate_verdict fills BOTH defaults when verdict and reason are absent', () => {
  // kills the two `||` on the gate_verdict line
  const j = canonicalJson({ type: 'gate_verdict', node: 3 });
  assert.match(j, /"verdict":"blocked"/);
  assert.match(j, /"reason":"budget-exceeded"/);
});

test('sigFirstDrop reports bad-length (not forged) for a wrong-sized buffer', () => {
  // kills sigFirstDrop `||` → `&&`: a Uint8Array of the wrong length must short-circuit to bad-length BEFORE any verify
  const r = sigFirstDrop(new Uint8Array(10), () => true, null);
  assert.equal(r.parsed, false);
  assert.equal(r.reason, 'bad-length');
});

test('deltaDecode does not over-add at the exact boundary (abs === prev)', () => {
  // kills `abs < p` → `abs <= p`: when the tip equals prev mod 256, abs === prev and must NOT gain 256
  assert.equal(deltaDecode(10, 10), 10);
  assert.equal(deltaDecode(0, 256), 256);
});

test('deltaDecode floors a non-integer prevStep to 0', () => {
  // kills deltaDecode prevStep `&&` → `||`: a non-integer prev must be treated as 0, not used as-is
  assert.equal(deltaDecode(5, 0.5), 5);
});

test('humanDoorRequired budget exactly at the ceiling does NOT trip (strict >)', () => {
  // kills `> AUTO_CEILING` → `>=`: budget === 1000 is under the door; only strictly over trips
  assert.equal(humanDoorRequired({ type: 'capability_delegation', resources: ['budget'], budget: 1000 }), false);
  assert.equal(humanDoorRequired({ type: 'capability_delegation', resources: ['budget'], budget: 1001 }), true);
});

test('reroute mazeBudget of 0 falls back to the default (strict > 0, and && not ||)', () => {
  // kills reroute `> 0` → `>= 0` and `&&` → `||`: a zero/invalid mazeBudget must default to 3, not become 0
  assert.equal(reroute('budget-exceeded', 0).observe, 3);
  assert.equal(reroute('budget-exceeded', 0.5).observe, 3);
  assert.equal(reroute('budget-exceeded', 5).observe, 5);
});
