"""AT1C receipt reference verifier + vector generator (spec/receipt.md, format 2).

A second, independent implementation of the checks in packages/sdk/src/verify.ts, written in Python on
top of `cryptography` (OpenSSL, FIPS 204 ML-DSA-65). Its job is to produce and check the conformance
vectors, so the SDK is tested against signatures it did not make itself.

Usage (from the repo root; needs Python `cryptography` 45 or later with ML-DSA support):
    python3 tools/at1c_ref.py gen   spec/test-vectors/receipt-v2.json    # write fresh vectors
    python3 tools/at1c_ref.py check spec/test-vectors/receipt-v2.json    # run every vector

The key used for vectors is a deterministic THROWAWAY. Never use it for anything real.
"""
import base64, copy, hashlib, json, re, sys
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import mldsa

ALG = "ML-DSA-65"
RECEIPT_CONTEXT = b"AT1C/receipt/v2"            # the signing label for receipts (FIPS 204 context string)
IDENTITY_LOG_CONTEXT = b"AT1C/identity-log/v1"  # reserved for identity log entries; used here only as a negative
MAX_TTL_SECONDS = 86400
MAX_SAFE_INT = 2**53 - 1

RE_ID = re.compile(r"^at1c_[0-9A-HJKMNP-TV-Z]{26}$")
RE_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
RE_B64U = re.compile(r"^[A-Za-z0-9_-]+$")
RE_SALT = re.compile(r"^[A-Za-z0-9_-]{43}$")
RE_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
CLASSES = {"compensable", "retriable", "irreversible"}


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def jcs(v):
    """RFC 8785 for the value types receipts may contain. Floats and anything else are refused."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > MAX_SAFE_INT:
            raise ValueError("unsafe integer")
        return str(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        if not all(isinstance(k, str) for k in v):
            raise ValueError("non-string key")
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))  # UTF-16 code unit order, as RFC 8785 requires
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in keys) + "}"
    raise ValueError("unsupported value type")


def attachment_hash_of(attachment):
    """payload_hash for format 2: sha256 of the JCS form of the whole attachment {payload, salt}."""
    if not isinstance(attachment, dict) or set(attachment) != {"payload", "salt"}:
        raise ValueError("attachment must have exactly: payload, salt")
    salt = attachment["salt"]
    if not isinstance(salt, str) or not RE_SALT.match(salt) or len(unb64u(salt)) != 32:
        raise ValueError("salt must be 32 random bytes, base64url")
    return "sha256:" + hashlib.sha256(jcs(attachment).encode()).hexdigest()


def signing_input(receipt):
    r = copy.deepcopy(receipt)
    r["approval"].pop("signature", None)
    return jcs(r).encode()


def schema_ok(r):
    try:
        assert r["version"] == "2" and RE_ID.match(r["receipt_id"])
        assert r["decision"] in ("approved", "denied")
        assert RE_TS.match(r["issued_at"]) and RE_TS.match(r["expires_at"])
        assert isinstance(r["audience"], str) and r["audience"]
        assert isinstance(r["actor"]["agent_id"], str) and r["actor"]["agent_id"]
        a = r["action"]
        assert a["class"] in CLASSES and RE_HASH.match(a["payload_hash"])
        assert isinstance(a["type"], str) and isinstance(a["resource"], str)
        assert RE_HASH.match(r["display_digest"])
        ap = r["approval"]
        assert isinstance(ap["authority"], str) and ap["authority"]
        assert isinstance(ap["alg"], str) and ap["alg"] and RE_B64U.match(ap["signature"])
        assert RE_B64U.match(r["nonce"]) and len(unb64u(r["nonce"])) == 32
        return True
    except (KeyError, AssertionError, TypeError, ValueError):
        return False


def verify(receipt, ctx):
    """ctx: now (datetime), pinned, allowed_algs, expected, seen_nonces (set, mutated), revoked (set)."""
    if not schema_ok(receipt):
        return False, "SCHEMA"
    ap = receipt["approval"]
    if ap["alg"] != ALG or ap["alg"] not in ctx["allowed_algs"]:
        return False, "ALG_NOT_ALLOWED"
    rec = ctx["pinned"].get(ap["authority"])
    if not isinstance(rec, dict):
        return False, "UNKNOWN_AUTHORITY"
    now = ctx["now"]
    if rec["alg"] != ap["alg"] or rec.get("revoked") or not (ts(rec["valid_from"]) <= now < ts(rec["valid_until"])):
        return False, "KEY_NOT_VALID"
    try:
        msg = signing_input(receipt)
        pub = mldsa.MLDSA65PublicKey.from_public_bytes(unb64u(rec["public_key"]))
        pub.verify(unb64u(ap["signature"]), msg, RECEIPT_CONTEXT)
    except ValueError as e:
        if "unsupported" in str(e) or "unsafe" in str(e) or "non-string" in str(e):
            return False, "SCHEMA"
        return False, "BAD_SIGNATURE"
    except Exception:
        return False, "BAD_SIGNATURE"
    if receipt["decision"] != "approved":
        return False, "DENIED"
    iat, exp = ts(receipt["issued_at"]), ts(receipt["expires_at"])
    if exp <= iat or (exp - iat).total_seconds() > MAX_TTL_SECONDS:
        return False, "BAD_TTL"
    if now < iat:
        return False, "NOT_YET_VALID"
    if now >= exp:
        return False, "EXPIRED"
    e, a = ctx["expected"], receipt["action"]
    if receipt["audience"] != e["audience"]:
        return False, "AUDIENCE_MISMATCH"
    if (receipt["actor"]["agent_id"] != e["agent_id"] or a["type"] != e["type"]
            or a["resource"] != e["resource"] or a["payload_hash"] != e["payload_hash"]):
        return False, "CONTEXT_MISMATCH"
    if receipt["receipt_id"] in ctx["revoked"]:
        return False, "REVOKED"
    if receipt["nonce"] in ctx["seen_nonces"]:
        return False, "REPLAY"
    ctx["seen_nonces"].add(receipt["nonce"])
    return True, "OK"


# ── Vector generation ────────────────────────────────────────────────────────────────────────────

AUTH = "did:web:test.at1c.example#user-1"
AUDIENCE = "gate.test.at1c.example"
NOW = "2026-10-12T12:00:00Z"
PAYLOAD = {"to": "alice@example.com", "subject": "Q3 report", "body_sha": "x"}


def _key(label):
    return mldsa.MLDSA65PrivateKey.from_seed_bytes(hashlib.sha256(label).digest())


def _salt(label):
    return b64u(hashlib.sha256(label).digest())  # deterministic for vectors only; real salts are random


def gen(out_path):
    sk = _key(b"at1c-test-approver-key-v2 THROWAWAY")
    other = _key(b"at1c-test-other-key-v2 THROWAWAY")
    pub = b64u(sk.public_key().public_bytes_raw())
    pinned = {AUTH: {"alg": ALG, "public_key": pub, "valid_from": "2026-01-01T00:00:00Z",
                     "valid_until": "2027-01-01T00:00:00Z", "revoked": False}}
    attachment = {"payload": PAYLOAD, "salt": _salt(b"at1c-vector-salt-1")}
    phash = attachment_hash_of(attachment)
    display = "AT1C approval request\n(vector display text)"
    counter = [0]

    def base(**over):
        counter[0] += 1
        r = {
            "version": "2",
            "receipt_id": "at1c_01JA00000000000000000000%02d" % counter[0],
            "decision": "approved",
            "issued_at": "2026-10-12T11:59:00Z",
            "expires_at": "2026-10-12T12:04:00Z",
            "audience": AUDIENCE,
            "actor": {"agent_id": "agent:mail-bot", "public_key": "b64u-agent-key-placeholder"},
            "action": {"type": "send_email", "class": "irreversible", "resource": "mailto:alice@example.com",
                       "payload_hash": phash, "scope_ref": "scope:mail-v1", "description": "Send Q3 report"},
            "display_digest": "sha256:" + hashlib.sha256(display.encode()).hexdigest(),
            "approval": {"authority": AUTH, "alg": ALG},
            "nonce": b64u(hashlib.sha256(b"nonce-%d" % counter[0]).digest()),
        }
        r.update(over)
        return r

    def sign(r, key=sk, context=RECEIPT_CONTEXT):
        r = copy.deepcopy(r)
        msg = signing_input(r)
        r["approval"]["signature"] = b64u(key.sign(msg, context) if context is not None else key.sign(msg))
        return r

    def expected(**over):
        e = {"audience": AUDIENCE, "agent_id": "agent:mail-bot", "type": "send_email",
             "resource": "mailto:alice@example.com", "payload_hash": phash}
        e.update(over)
        return e

    vectors = []

    def add(name, receipt, code, note="", now=NOW, exp=None, pre_seen=(), revoked=(), pinned_over=None):
        v = {"name": name, "note": note, "receipt": receipt, "now": now,
             "expected_action": exp if exp is not None else expected(),
             "pre_seen_nonces": list(pre_seen), "revoked": list(revoked),
             "expect": {"ok": code == "OK", "code": code}}
        if pinned_over is not None:
            v["pinned"] = pinned_over
        vectors.append(v)

    # Accepts and the signed denial
    add("valid-approved", sign(base()), "OK")
    add("valid-approved-with-unknown-extra-field", sign(base(x_note="extra, signed")), "OK",
        "Signed unknown fields are ignored (forward compat).")
    add("denial-receipt", sign(base(decision="denied")), "DENIED", "Valid, signed denial; gate must not execute.")

    # Replay, time
    r = sign(base()); add("replay", r, "REPLAY", pre_seen=[r["nonce"]])
    add("expired", sign(base()), "EXPIRED", now="2026-10-12T12:04:00Z")
    add("not-yet-valid", sign(base()), "NOT_YET_VALID", now="2026-10-12T11:58:00Z")
    add("ttl-too-long", sign(base(expires_at="2026-10-13T12:00:00Z")), "BAD_TTL")

    # Context binding
    changed = {"payload": dict(PAYLOAD, to="mallory@example.com"), "salt": attachment["salt"]}
    add("payload-changed-after-approval", sign(base()), "CONTEXT_MISMATCH",
        exp=expected(payload_hash=attachment_hash_of(changed)))
    resalted = {"payload": PAYLOAD, "salt": _salt(b"at1c-vector-salt-2")}
    add("salt-changed", sign(base()), "CONTEXT_MISMATCH",
        "Same payload, different salt: the fingerprint covers the whole attachment.",
        exp=expected(payload_hash=attachment_hash_of(resalted)))
    add("wrong-resource", sign(base()), "CONTEXT_MISMATCH", exp=expected(resource="mailto:bob@example.com"))
    add("wrong-agent", sign(base()), "CONTEXT_MISMATCH", exp=expected(agent_id="agent:other"))
    add("wrong-action-type", sign(base()), "CONTEXT_MISMATCH", exp=expected(type="delete_all"))
    add("wrong-audience", sign(base()), "AUDIENCE_MISMATCH",
        "A receipt made for one gate is refused by a gate with another name.",
        exp=expected(audience="other-gate.example"))

    # Tampering and signature
    r = sign(base(decision="denied")); r["decision"] = "approved"
    add("denial-flipped-to-approved", r, "BAD_SIGNATURE")
    r = sign(base()); r["expires_at"] = "2026-10-12T20:00:00Z"
    add("expiry-extended-after-signing", r, "BAD_SIGNATURE")
    r = sign(base()); r["audience"] = "other-gate.example"
    add("audience-changed-after-signing", r, "BAD_SIGNATURE", exp=expected(audience="other-gate.example"))
    r = sign(base()); sig = bytearray(unb64u(r["approval"]["signature"])); sig[10] ^= 1
    r["approval"]["signature"] = b64u(bytes(sig))
    add("signature-bit-flipped", r, "BAD_SIGNATURE")
    add("signed-by-a-different-key", sign(base(), key=other), "BAD_SIGNATURE")
    add("signed-without-label", sign(base(), context=None), "BAD_SIGNATURE",
        "Format 2 body signed with the empty context string (as format 1 did).")
    add("signed-under-identity-log-label", sign(base(), context=IDENTITY_LOG_CONTEXT), "BAD_SIGNATURE",
        "A signature made under another kind's label must never pass as a receipt.")

    # Authority, algorithm, key state
    r = base(); r["approval"]["authority"] = "did:web:unknown.example#x"
    add("unknown-authority", sign(r), "UNKNOWN_AUTHORITY")
    r = base(); r["approval"]["authority"] = "constructor"
    add("authority-named-like-a-builtin", sign(r), "UNKNOWN_AUTHORITY",
        "The pinned-key lookup must use own entries only.")
    r = base(); r["approval"]["alg"] = "Ed25519"
    add("alg-downgrade", sign(r), "ALG_NOT_ALLOWED")
    add("key-expired", sign(base()), "KEY_NOT_VALID",
        pinned_over={AUTH: dict(pinned[AUTH], valid_until="2026-10-01T00:00:00Z")})
    add("key-not-yet-valid", sign(base()), "KEY_NOT_VALID",
        pinned_over={AUTH: dict(pinned[AUTH], valid_from="2026-11-01T00:00:00Z")})
    add("key-revoked", sign(base()), "KEY_NOT_VALID", "Compromised key: all its receipts rejected, even older ones.",
        pinned_over={AUTH: dict(pinned[AUTH], revoked=True)})

    # Schema
    r = sign(base()); del r["nonce"]; add("missing-nonce", r, "SCHEMA")
    r = sign(base()); del r["action"]["payload_hash"]; add("missing-payload-hash", r, "SCHEMA")
    r = sign(base()); del r["audience"]; add("missing-audience", r, "SCHEMA")
    add("empty-audience", sign(base(audience="")), "SCHEMA")
    r = base(version="1"); del r["audience"]
    add("format-1-receipt", sign(r, context=None), "SCHEMA",
        "Clean cut: a format 1 receipt (no label, no audience) is refused outright.")

    # Revocation
    r = sign(base()); add("revoked", r, "REVOKED", revoked=[r["receipt_id"]])

    bad_attachments = [
        {"name": "missing-salt", "attachment": {"payload": PAYLOAD}},
        {"name": "short-salt", "attachment": {"payload": PAYLOAD, "salt": "AAAA"}},
        {"name": "extra-field", "attachment": {"payload": PAYLOAD, "salt": attachment["salt"], "note": "x"}},
        {"name": "missing-payload", "attachment": {"salt": attachment["salt"]}},
    ]
    doc = {
        "format": "at1c-receipt-test-vectors",
        "receipt_version": "2",
        "alg": ALG,
        "signing_context": RECEIPT_CONTEXT.decode(),
        "warning": "Throwaway test key. Never use for anything real.",
        "pinned": pinned,
        "allowed_algs": [ALG],
        "attachment_vectors": {
            "accept": [
                {"name": "vector-attachment", "attachment": attachment, "payload_hash": phash},
                {"name": "same-payload-other-salt", "attachment": resalted, "payload_hash": attachment_hash_of(resalted)},
            ],
            "reject": bad_attachments,
        },
        "vectors": vectors,
    }
    with open(out_path, "w") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    print("wrote %d receipt vectors to %s" % (len(vectors), out_path))


def check(path):
    d = json.load(open(path))
    fails = 0
    for v in d["vectors"]:
        ctx = {"now": ts(v["now"]), "pinned": v.get("pinned", d["pinned"]), "allowed_algs": d["allowed_algs"],
               "expected": v["expected_action"], "seen_nonces": set(v["pre_seen_nonces"]), "revoked": set(v["revoked"])}
        ok, code = verify(v["receipt"], ctx)
        good = (ok, code) == (v["expect"]["ok"], v["expect"]["code"])
        fails += 0 if good else 1
        print("PASS" if good else "FAIL", v["name"], code)
    for a in d["attachment_vectors"]["accept"]:
        good = attachment_hash_of(a["attachment"]) == a["payload_hash"]
        fails += 0 if good else 1
        print("PASS" if good else "FAIL", "attachment:", a["name"])
    for a in d["attachment_vectors"]["reject"]:
        try:
            attachment_hash_of(a["attachment"]); good = False
        except ValueError:
            good = True
        fails += 0 if good else 1
        print("PASS" if good else "FAIL", "attachment refused:", a["name"])
    print("failures:", fails)
    return fails


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "gen":
        gen(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "check":
        sys.exit(1 if check(sys.argv[2]) else 0)
    else:
        print(__doc__)
        sys.exit(2)
