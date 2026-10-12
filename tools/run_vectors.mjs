import fs from 'node:fs';
import canonicalize from 'canonicalize';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const b64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const d = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const pub = b64u(Object.values(d.pinned)[0]);
let fail = 0;
for (const v of d.vectors) {
  const r = structuredClone(v.receipt);
  const sig = r.approval?.signature;
  if (!sig) continue;
  if (['SCHEMA', 'ALG_NOT_ALLOWED'].includes(v.expect.code)) continue;
  delete r.approval.signature;
  const msg = new TextEncoder().encode(canonicalize(r));
  let ok = false;
  try { ok = ml_dsa65.verify(b64u(sig), msg, pub); } catch { ok = false; }
  const expectValid = v.expect.code !== 'BAD_SIGNATURE';
  const pass = ok === expectValid;
  if (!pass) fail++;
  console.log(pass ? 'PASS' : 'FAIL', v.name, 'sigValid=' + ok);
}
console.log('signature-level failures:', fail);
process.exit(fail ? 1 : 0);
