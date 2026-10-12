// UNTESTED: written without network access to npm. Run from your repo root:
//   npm i canonicalize && node tools/run_vectors.mjs spec/test-vectors/receipt-v1.json
// Purpose: confirm @noble/post-quantum (ML-DSA-65) verifies signatures produced by the Python/OpenSSL reference.
import fs from 'node:fs';
import canonicalize from 'canonicalize';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const b64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const d = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const pub = b64u(Object.values(d.pinned)[0].public_key);
let fail = 0;
for (const v of d.vectors) {
  const r = structuredClone(v.receipt);
  const sig = r.approval?.signature;
  if (!sig) continue; // schema-failure vectors without a signature
  delete r.approval.signature;
  const msg = new TextEncoder().encode(canonicalize(r));
  let ok = false;
  try { ok = ml_dsa65.verify(b64u(sig), msg, pub); } catch { ok = false; }
  // Signature-level expectation: only these vectors must have an INVALID signature.
  const expectValid = !['BAD_SIGNATURE'].includes(v.expect.code);
  // Vectors that fail earlier (SCHEMA/ALG) may or may not carry a valid signature; skip those.
  if (['SCHEMA', 'ALG_NOT_ALLOWED', 'KEY_NOT_VALID'].includes(v.expect.code)) continue;
  const pass = ok === expectValid;
  if (!pass) fail++;
  console.log(pass ? 'PASS' : 'FAIL', v.name, 'sigValid=' + ok);
}
console.log('signature-level failures:', fail);
process.exit(fail ? 1 : 0);
