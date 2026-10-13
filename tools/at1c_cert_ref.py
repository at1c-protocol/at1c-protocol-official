"""AT1C agent-certificate reference verifier + vector generator (spec/agent-certificate.md, format 1)."""
import base64, copy, hashlib, json, re, sys
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import mldsa
from at1c_ref import jcs, b64u, unb64u, ts, ALG

HEX_ID = re.compile(r"^agent:[0-9a-f]{32}$")
B64U = re.compile(r"^[A-Za-z0-9_-]+$")
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
TIERS = {"free", "standard", "enterprise"}
MAX_DAYS = 366

def agent_id_for(pub_b64u):
    return "agent:" + hashlib.sha256(unb64u(pub_b64u)).hexdigest()[:32]

def signing_input(cert):
    c = copy.deepcopy(cert); c.pop("signature", None); return jcs(c)

def schema_ok(c):
    try:
        assert c["version"] == "1" and c["type"] == "agent_certificate"
        assert HEX_ID.match(c["agent_id"])
        assert isinstance(c["agent_alg"], str) and B64U.match(c["agent_public_key"])
        assert isinstance(c["name"], str) and isinstance(c["owner"], str) and c["owner"]
        p = c["permissions"]
        assert isinstance(p, list) and all(isinstance(x, str) and x for x in p)
        assert p == sorted(p) and len(set(p)) == len(p)
        assert c["tier"] in TIERS
        assert TS.match(c["issued_at"]) and TS.match(c["expires_at"])
        assert isinstance(c["issuer"], str) and c["issuer"] and isinstance(c["alg"], str)
        assert B64U.match(c["signature"])
        return True
    except (KeyError, AssertionError, TypeError, ValueError):
        return False

def verify(cert, ctx):
    if not schema_ok(cert): return False, "SCHEMA"
    if cert["alg"] not in ctx["allowed_algs"] or cert["agent_alg"] not in ctx["allowed_algs"]: return False, "ALG_NOT_ALLOWED"
    if cert["alg"] != ALG: return False, "ALG_NOT_ALLOWED"
    rec = ctx["pinned"].get(cert["issuer"])
    if rec is None: return False, "UNKNOWN_ISSUER"
    if rec["alg"] != cert["alg"] or rec.get("revoked") or not (ts(rec["valid_from"]) <= ctx["now"] < ts(rec["valid_until"])):
        return False, "KEY_NOT_VALID"
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(unb64u(rec["public_key"])).verify(unb64u(cert["signature"]), signing_input(cert))
    except Exception: return False, "BAD_SIGNATURE"
    iat, exp = ts(cert["issued_at"]), ts(cert["expires_at"])
    if exp <= iat or (exp - iat).total_seconds() > MAX_DAYS * 86400: return False, "BAD_VALIDITY"
    if ctx["now"] < iat: return False, "NOT_YET_VALID"
    if ctx["now"] >= exp: return False, "EXPIRED"
    if cert["agent_id"] != agent_id_for(cert["agent_public_key"]): return False, "AGENT_ID_MISMATCH"
    if cert["agent_id"] in ctx["revoked"]: return False, "REVOKED"
    return True, "OK"

def gen(out_path, receipt_vectors_path):
    def key(label):
        seed = hashlib.sha256(label).digest()
        return mldsa.MLDSA65PrivateKey.from_seed_bytes(seed)
    reg = key(b"at1c-test-registry-key-v1 THROWAWAY"); agent = key(b"at1c-test-agent-key-v1 THROWAWAY")
    reg_pub = b64u(reg.public_key().public_bytes_raw()); agent_pub = b64u(agent.public_key().public_bytes_raw())
    ISS = "did:web:test.at1c.example#registry-1"
    KEYREC = {"alg": ALG, "public_key": reg_pub, "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2028-01-01T00:00:00Z", "revoked": False}
    NOW = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)
    def base(**kw):
        c = {"version": "1", "type": "agent_certificate", "agent_id": agent_id_for(agent_pub), "agent_alg": ALG,
             "agent_public_key": agent_pub, "name": "Payments bot", "owner": "did:web:test.at1c.example#user-1",
             "permissions": ["read_balance", "send_payment"], "tier": "standard",
             "issued_at": "2026-10-13T09:00:00Z", "expires_at": "2027-10-13T09:00:00Z", "issuer": ISS, "alg": ALG}
        c.update(kw); return c
    def sign(c):
        c = copy.deepcopy(c); c.pop("signature", None)
        c["signature"] = b64u(reg.sign(signing_input(c))); return c
    vecs = []
    def add(name, c, ok, code, now=NOW, pinned=None, revoked=None, note=""):
        v = {"name": name, "note": note, "certificate": c, "now": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "revoked": revoked or [], "expect": {"ok": ok, "code": code}}
        if pinned: v["pinned"] = pinned
        vecs.append(v)
    good = sign(base()); add("valid", good, True, "OK")
    add("valid-with-unknown-extra-field", sign({**base(), "x_future": {"transfer_to": None}}), True, "OK", note="Signed unknown fields are ignored.")
    t = copy.deepcopy(good); t["permissions"] = ["read_balance", "send_payment", "wire_money"]; add("permissions-widened-after-signing", t, False, "BAD_SIGNATURE", note="The flaw in the old registry script: permissions were not covered.")
    t = copy.deepcopy(good); t["tier"] = "enterprise"; add("tier-changed-after-signing", t, False, "BAD_SIGNATURE")
    t = copy.deepcopy(good); t["expires_at"] = "2030-01-01T00:00:00Z"; add("expiry-extended-after-signing", t, False, "BAD_SIGNATURE")
    other = b64u(key(b"some-other-agent").public_key().public_bytes_raw())
    t = copy.deepcopy(good); t["agent_public_key"] = other; add("agent-key-swapped-after-signing", t, False, "BAD_SIGNATURE")
    add("agent-id-not-derived-from-key", sign(base(agent_id="agent:" + "0" * 32)), False, "AGENT_ID_MISMATCH")
    add("permissions-unsorted", sign(base(permissions=["send_payment", "read_balance"])), False, "SCHEMA")
    add("permissions-duplicate", sign(base(permissions=["read_balance", "read_balance"])), False, "SCHEMA")
    add("tier-not-allowed", sign(base(tier="platinum")), False, "SCHEMA")
    t = copy.deepcopy(good); del t["owner"]; add("missing-owner", t, False, "SCHEMA")
    rv = json.load(open(receipt_vectors_path))["vectors"][0]["receipt"]
    add("receipt-presented-as-certificate", rv, False, "SCHEMA", note="Domain separation: a receipt is never a certificate.")
    add("unknown-issuer", sign(base(issuer="did:web:attacker.example#registry-1")), False, "UNKNOWN_ISSUER")
    t = copy.deepcopy(good); t["alg"] = "Ed25519"; add("issuer-alg-downgrade", t, False, "ALG_NOT_ALLOWED")
    add("agent-alg-not-allowed", sign(base(agent_alg="Ed25519")), False, "ALG_NOT_ALLOWED")
    add("lifetime-too-long", sign(base(expires_at="2027-11-20T09:00:00Z")), False, "BAD_VALIDITY")
    add("expired", good, False, "EXPIRED", now=datetime(2027, 10, 13, 9, 0, 0, tzinfo=timezone.utc))
    add("not-yet-valid", good, False, "NOT_YET_VALID", now=datetime(2026, 10, 13, 8, 0, 0, tzinfo=timezone.utc))
    add("registry-key-expired", good, False, "KEY_NOT_VALID", pinned={ISS: {**KEYREC, "valid_until": "2026-10-13T11:00:00Z"}})
    add("registry-key-revoked", good, False, "KEY_NOT_VALID", pinned={ISS: {**KEYREC, "revoked": True}}, note="Compromised registry key: every certificate it signed is rejected.")
    add("agent-revoked", good, False, "REVOKED", revoked=[good["agent_id"]])
    json.dump({"format": "at1c-agent-certificate-test-vectors", "certificate_version": "1", "alg": ALG,
               "warning": "Throwaway test keys. Never use for anything real.",
               "pinned": {ISS: KEYREC}, "allowed_algs": [ALG], "vectors": vecs}, open(out_path, "w"), indent=2)
    print(len(vecs), "vectors")

if __name__ == "__main__":
    if sys.argv[1] == "gen":
        gen(sys.argv[2], sys.argv[3])
    else:
        d = json.load(open(sys.argv[2])); bad = 0
        for v in d["vectors"]:
            ctx = {"now": ts(v["now"]), "pinned": v.get("pinned", d["pinned"]), "allowed_algs": d["allowed_algs"], "revoked": set(v["revoked"])}
            ok, code = verify(v["certificate"], ctx)
            good = (ok, code) == (v["expect"]["ok"], v["expect"]["code"]); bad += not good
            print("PASS" if good else "FAIL", v["name"], code)
        print("failures:", bad); sys.exit(bad)
