#!/usr/bin/env node
// scripts/seal.mjs — PROOF-OF-PLAY, part one: pin the inputs BEFORE the measurement, as its own pushed commit.
//
// The byte-ratios are a CLAIM until the record proves the predictions predated the result. So the seal is a
// separate commit: data/prereg.json carries the predictions AND the sha256 of every input that determines the
// ratios — the codec (sentinel.mjs) and the transport kernel that holds the event fixtures and the measurement
// method (fallairgap.mjs). CI goes green on THIS commit (seal --check: the inputs match their sealed hashes)
// BEFORE the measurement commit lands. Then measure.mjs --verify re-derives the ratios on GitHub's own runner
// from exactly these inputs — so nobody can claim the prereg was backfilled to fit the result.
//
//   node scripts/seal.mjs --seal    write data/prereg.json (predictions + input hashes)
//   node scripts/seal.mjs --check   verify the inputs still hash to what the seal pinned (exit 1 on drift)
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const at = (f) => new URL('../' + f, import.meta.url);
const bytes = (f) => readFileSync(at(f));                // hash the RAW bytes as committed
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

// the inputs that fully determine the measured ratios. Hash the raw files; the generator, the event fixtures
// (SAMPLE_EVENTS) and the measurement method all live in fallairgap.mjs; the codec is sentinel.mjs.
export const INPUTS = ['sentinel.mjs', 'fallairgap.mjs'];

// the PREDICTIONS — the substance of the seal. These are committed and pushed before any measurement is taken.
export const PREREG = {
  organ: 'fall-airgap',
  what: 'The 6-byte Primorial-Fold transport. Predictions + input hashes committed as their OWN commit BEFORE the measurement commit (seal-before-measure, provable on the public record). Ratios are measured by fallairgap.mjs measure() in real UTF-8 wire bytes and re-derived on CI from the sealed inputs.',
  sealed: '2026-10-05',
  codec: 'SENTINEL (vendored, mutation-gated) — Thomas Frumkin\'s Konomi primorial-fold codec',
  predictions: [
    { id: 'P1-coordinate', claim: 'Every event\'s 6-byte PAYLOAD beats its self-describing JSON by at least 20x (the coordinate regime). We predicted 20-40x, not Simon\'s headline 42x, because our canonical JSON is leaner than his 252-byte example.', pass_if: 'every ratioPayload >= 20' },
    { id: 'P2-delta', claim: 'A recurring deterministic step sent as a 1-byte delta (heartbeat, pipeline_step) beats JSON by at least 100x (the 100x+ regime).', pass_if: 'every deltaBytes-bearing event has ratioDelta >= 100' },
    { id: 'P3-signature-floor', claim: 'Signed PER-PACKET, the 71-byte wire vs apples-to-apples signed JSON is UNDER 10x. The 64-byte Ed25519 signature dominates, proving the 42-100x is only realised when the signature is AMORTISED over a session, never per packet. This is the honest limit the 15x test never measured.', pass_if: 'every ratioWireVsJsonSigned < 10' },
    { id: 'P4-entropy-floor', claim: 'A raw Ed25519 signature (64B) and a SHA-256 hash (32B) do not compress past their entropy floor.', pass_if: 'entropyFloor lists signature=64 and hash=32 both compresses:false' },
    { id: 'P5-gate', claim: 'A forged or tampered signed frame is dropped by the signature-first gate BEFORE its payload is parsed; a valid frame round-trips. No forged frame ever compiles to a command.', pass_if: 'sigFirstDrop + SENTINEL check reject forged before parse, accept valid' },
    { id: 'P6-roundtrip', claim: 'All 5 sample event types encode to 6 bytes and decode back to the same event type (codec is total and reversible for the event set).', pass_if: 'selfCheck roundTrips == 5 of 5' },
  ],
};

export function inputHashes() {
  const out = {};
  for (const f of INPUTS) out[f] = sha256(bytes(f));
  return out;
}

// only run the CLI when invoked directly — measure.mjs imports inputHashes/PREREG from this module.
const isMain = import.meta.url === pathToFileURL(process.argv[1] || '').href;
const mode = isMain ? (process.argv.includes('--check') ? 'check' : process.argv.includes('--seal') ? 'seal' : null) : 'skip';

if (mode === 'skip') {
  // imported as a library — do nothing
} else if (mode === 'seal') {
  const prereg = { ...PREREG, inputs: inputHashes() };
  writeFileSync(at('data/prereg.json'), JSON.stringify(prereg, null, 2) + '\n');
  console.log('sealed · inputs pinned:');
  for (const [f, h] of Object.entries(prereg.inputs)) console.log('  ' + f + '  ' + h);
} else if (mode === 'check') {
  let prereg;
  try { prereg = JSON.parse(readFileSync(at('data/prereg.json'), 'utf8')); }
  catch { console.error('seal --check: data/prereg.json missing or unreadable — not sealed'); process.exit(1); }
  if (!prereg.inputs) { console.error('seal --check: prereg has no input hashes — re-seal'); process.exit(1); }
  const now = inputHashes();
  let drift = 0;
  for (const f of INPUTS) {
    if (prereg.inputs[f] !== now[f]) { console.error('DRIFT  ' + f + '\n  sealed ' + prereg.inputs[f] + '\n  now    ' + now[f]); drift++; }
    else console.log('in step  ' + f);
  }
  if (drift) { console.error('seal --check: ' + drift + ' input(s) changed since the seal — the sealed inputs no longer match'); process.exit(1); }
  console.log('seal --check: all inputs match the sealed hashes');
} else {
  console.error('usage: node scripts/seal.mjs --seal | --check');
  process.exit(2);
}
