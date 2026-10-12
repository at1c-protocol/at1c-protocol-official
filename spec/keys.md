# AT1C Key Trust Model — format 1 (DRAFT)

Companion to `receipt.md`. Answers one question: **how does a verifier know a public key really belongs to the human?**

## 1. Recommendation (v1)

The verifier keeps its own local list of trusted keys. It is a plain file the verifier's operator controls. No registry, no chain, no DID lookup. [AT1C choice]

Why: it is the smallest thing that is safe. Nothing outside the verifier can add a key to it. The cost is that a human's key has to reach each verifier once, by an out-of-band step (see §4).

Alternatives weighed: `did:web` lookup (adds a web dependency and a way to swap keys by hijacking a domain), a public registry (new trust anchor to defend), an on-chain key list (the chain dependency you removed). All three can come later as *sources* that feed this same local list.

## 2. Key record

```json
{
  "authority": "did:web:example.com#user-1",
  "alg": "ML-DSA-65",
  "public_key": "<b64url, 1952 bytes>",
  "valid_from": "2026-10-12T00:00:00Z",
  "valid_until": "2027-10-12T00:00:00Z",
  "revoked": false
}
```

`authority` is exactly the string in `approval.authority`. Each key has its own authority string (the `#user-1`, `#user-2` part), so two keys never share a name.

## 3. Key validity rule

A key is usable **only if all are true**, judged by the **verifier's own clock** (`now`), never by the receipt's `issued_at`:

- `valid_from ≤ now < valid_until`
- `revoked` is false

Why not `issued_at`: the signer writes `issued_at`. A thief holding a stolen key could set it to any date.

## 4. Lifecycle

| Event | What happens |
|---|---|
| **Enrol** | Human gives the verifier operator the public key through a channel they trust (in person, or a signed message from a key already trusted). Operator adds the record. |
| **Rotate** | Add the new key (`#user-2`). Set the old key's `valid_until` to a few days ahead. Receipts last at most 24 hours, so the overlap is short. |
| **Compromise** | Set `revoked: true` immediately. Every receipt from that key is rejected, including ones signed before the compromise, because the verifier cannot tell which are genuine. The human re-approves what still matters with the new key. |
| **Lost key** | Same as compromise. |

## 5. Needed changes to `receipt.md`

- Add a verification step after `UNKNOWN_AUTHORITY`: `KEY_NOT_VALID` (outside its validity window, or revoked).
- Add test vectors: key expired, key not yet valid, key revoked.

## 6. Gaps, stated plainly

- **First enrolment is manual.** The protocol cannot prove a key belongs to a person; a human or operator decides. This is the same as SSH `authorized_keys`.
- **Revocation depends on the operator.** A stolen key stays valid at every verifier until each operator hears and acts. A shared revocation feed would fix this and is not specified.
- **No multi-device or recovery scheme.** One person with two devices is two authorities. A recovery method (for example m-of-n) is future work.
- **Key storage on the human's device** is outside this document.
