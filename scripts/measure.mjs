#!/usr/bin/env node
// scripts/measure.mjs — PROOF-OF-PLAY, part two: the measurement, re-derivable on any runner from the sealed inputs.
//
// --run    : check the inputs still match the seal, then compute the byte-ratios and write data/run.json.
// --verify : check the inputs match the seal, recompute, and assert byte-for-byte equality with the committed
//            data/run.json AND that every sealed prediction held. Exit 1 on any mismatch. CI runs this on
//            GitHub's own runner, so the numbers are reproduced off my machine — the way SENTINEL's gate re-runs.
import { readFileSync, writeFileSync } from 'node:fs';
import { inputHashes } from './seal.mjs';

const at = (f) => new URL('../' + f, import.meta.url);
const read = (f) => readFileSync(at(f), 'utf8');

function checkSeal() {
  const prereg = JSON.parse(read('data/prereg.json'));
  if (!prereg.inputs) { console.error('not sealed with input hashes — run scripts/seal.mjs --seal first'); process.exit(1); }
  const now = inputHashes();
  for (const f of Object.keys(prereg.inputs)) {
    if (prereg.inputs[f] !== now[f]) { console.error('SEAL DRIFT: ' + f + ' changed since the seal — refusing to measure'); process.exit(1); }
  }
  return prereg;
}

async function compute() {
  const F = await import(at('fallairgap.mjs').href);
  const r = F.selfCheck();
  const rows = r.rows.map((x) => ({
    event: x.event, jsonBytes: x.jsonBytes, jsonSignedBytes: x.jsonSignedBytes, payloadBytes: x.payloadBytes,
    deltaBytes: x.deltaBytes, wireBytes: x.wireBytes, ratioPayload: x.ratioPayload, ratioDelta: x.ratioDelta,
    ratioWireVsJsonSigned: x.ratioWireVsJsonSigned, ratioWireVsJson: x.ratioWireVsJson,
  }));
  const floor = F.entropyFloor();
  const P1 = rows.every((x) => x.ratioPayload >= 20);
  const P2 = rows.filter((x) => x.deltaBytes).every((x) => x.ratioDelta >= 100);
  const P3 = rows.every((x) => x.ratioWireVsJsonSigned < 10);
  const sig = floor.find((f) => /Ed25519/.test(f.what)), hash = floor.find((f) => /SHA-256/.test(f.what));
  const P4 = sig.bytes === 64 && hash.bytes === 32 && floor.filter((f) => f.bytes).every((f) => f.compresses === false);
  const P6 = r.roundTrips === 5;
  return {
    organ: 'fall-airgap', measured: '2026-10-05', rows, floor,
    verdict: { P1_coordinate_ge20: P1, P2_delta_ge100: P2, P3_signature_floor_lt10: P3, P4_entropy_floor: P4, P6_roundtrip: P6 },
  };
}

const mode = process.argv.includes('--verify') ? 'verify' : process.argv.includes('--run') ? 'run' : null;
checkSeal();
const run = await compute();

if (mode === 'run') {
  writeFileSync(at('data/run.json'), JSON.stringify(run, null, 2) + '\n');
  const allHeld = Object.values(run.verdict).every(Boolean);
  console.log('measured · ' + run.rows.map((r) => r.event + ' ' + r.ratioPayload + '×').join(', '));
  console.log('sealed predictions held: ' + allHeld);
  if (!allHeld) process.exit(1);
} else if (mode === 'verify') {
  const committed = read('data/run.json');
  const fresh = JSON.stringify(run, null, 2) + '\n';
  if (committed !== fresh) {
    console.error('MEASURE DRIFT: re-derived run.json does not match the committed one.');
    process.exit(1);
  }
  const allHeld = Object.values(run.verdict).every(Boolean);
  if (!allHeld) { console.error('a sealed prediction did NOT hold on re-measure: ' + JSON.stringify(run.verdict)); process.exit(1); }
  console.log('measure --verify: re-derived on this runner, byte-identical to the committed record, all sealed predictions held.');
} else {
  console.error('usage: node scripts/measure.mjs --run | --verify');
  process.exit(2);
}
