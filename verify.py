#!/usr/bin/env python3
"""Verify ce-net capability chains and signed call receipts offline, with the standard library only.

  python3 verify.py ROOT_HEX TOKEN_HEX [NOW] [ISSUER_HEX:NONCE ...]   one capability chain
  python3 verify.py RECEIPTS.jsonl [--root HEX] [--nodes HEX,HEX...]   a file of signed call receipts
  python3 verify.py use VECTORS.json                                  v3 uses: chain, request, proofs, verdict"""
import hashlib, json, os, struct, sys, time

# Ed25519 (RFC 8032), pure Python. The `cryptography` package is used instead when it is installed.
_P, _L = 2**255 - 19, 2**252 + 27742317777372353535851937790883648493
_D, _I = -121665 * pow(121666, _P - 2, _P) % _P, pow(2, (_P - 1) // 4, _P)
def _add(a, b):
    A, B = (a[1] - a[0]) * (b[1] - b[0]) % _P, (a[1] + a[0]) * (b[1] + b[0]) % _P
    C, D = 2 * a[3] * b[3] * _D % _P, 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)
def _mul(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1: q = _add(q, p)
        p, s = _add(p, p), s >> 1
    return q
def _point(b):
    y = int.from_bytes(b, "little"); sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= _P: raise ValueError("bad point")
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P: x = x * _I % _P
    if (x * x - x2) % _P or (x == 0 and sign): raise ValueError("bad point")
    if x & 1 != sign: x = _P - x
    return (x, y, 1, x * y % _P)
def _enc(p):
    zi = pow(p[2], _P - 2, _P); x, y = p[0] * zi % _P, p[1] * zi % _P
    return (y | (x & 1) << 255).to_bytes(32, "little")
_B = _point((4 * pow(5, _P - 2, _P) % _P).to_bytes(32, "little"))
_h = lambda *m: int.from_bytes(hashlib.sha512(b"".join(m)).digest(), "little")
def _pure_verify(pub, sig, msg):
    s = int.from_bytes(sig[32:], "little")
    if len(sig) != 64 or s >= _L or _enc(_mul(s, _B)) != _enc(_add(_point(sig[:32]), _mul(_h(sig[:32], pub, msg) % _L, _point(pub)))):
        raise ValueError("invalid signature")
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    def ed25519_verify(pub, sig, msg): Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
except ImportError:
    ed25519_verify = _pure_verify
def ed25519_sign(seed, msg):
    """Sign with a 32-byte seed (pure Python, deterministic). Returns (public key, signature)."""
    d = hashlib.sha512(seed).digest(); a = int.from_bytes(d[:32], "little") & ((1 << 254) - 8) | 1 << 254
    pub = _enc(_mul(a, _B)); r = _h(d[32:], msg) % _L; R = _enc(_mul(r, _B))
    return pub, R + ((r + _h(R, pub, msg) % _L * a) % _L).to_bytes(32, "little")

def decode(token):  # bincode 1.x: little-endian, u64 lengths, option = 0/1 tag
    b, i = bytes.fromhex(token.strip()), [0]
    def take(n):
        if i[0] + n > len(b): raise ValueError("truncated token")
        i[0] += n; return b[i[0] - n:i[0]]
    num = lambda f: struct.unpack("<" + f, take(struct.calcsize(f)))[0]
    s = lambda: take(num("Q")).decode()
    seq = lambda f: [f() for _ in range(num("Q"))]
    def opt(f):
        t = take(1)[0]
        if t > 1: raise ValueError("bad option tag")
        return f() if t else None
    def res():
        v = num("I")
        if v > 3: raise ValueError("bad resource variant")
        return [lambda: ("Any",), lambda: ("Node", take(32)), lambda: ("Tag", s()), lambda: ("AllOf", seq(s))][v]()
    def link():
        st = i[0]
        c = dict(issuer=take(32), audience=take(32), abilities=seq(s), resource=res(), not_before=num("Q"), not_after=num("Q"),
                 max_cpu=opt(lambda: num("I")), max_mem_mb=opt(lambda: num("I")), max_credits=opt(lambda: num("Q")),
                 ports=opt(lambda: seq(lambda: num("H"))), path=opt(s), nonce=num("Q"), parent=opt(lambda: take(32)))
        c["signed"] = struct.pack("<Q", 9) + b"ce-cap-v1" + b[st:i[0]]  # cap_bytes = domain tag + Capability
        if num("Q") != 64: raise ValueError("bad signature length")
        c["sig"] = take(64); return c
    return seq(link)

cap_id = lambda c: hashlib.sha256(c["signed"]).digest()
covers = lambda g, n: g in (n, "*") or (g.endswith(":*") and n.startswith(g[:-1]) and len(n) > len(g) - 1)
def within(c, p):
    c, p = c.rstrip("/"), p.rstrip("/")
    return p == "" or c == p or c.startswith(p + "/")

def res_subset(c, p):
    if p[0] == "Any": return True
    if p[0] in ("Node", "Tag") and c == p: return True
    if p[0] == "Tag": return c[0] == "AllOf" and p[1] in c[1]
    if p[0] == "AllOf": return (c[0] == "AllOf" and all(x in c[1] for x in p[1])) or (c[0] == "Tag" and all(x == c[1] for x in p[1]))
    return False

def caveats_ok(c, p):
    if p["not_after"] and not (c["not_after"] and c["not_after"] <= p["not_after"]): return False
    if c["not_before"] < p["not_before"]: return False
    for k in ("max_cpu", "max_mem_mb", "max_credits"):
        if p[k] is not None and (c[k] is None or c[k] > p[k]): return False
    if p["ports"] is not None and (c["ports"] is None or any(x not in p["ports"] for x in c["ports"])): return False
    return p["path"] is None or (c["path"] is not None and within(c["path"], p["path"]))

def verify_chain(chain, root, now, revoked=()):
    """Returns the leaf capability; raises ValueError with the reference error text otherwise."""
    if not chain: raise ValueError("no capability presented")
    if chain[0]["issuer"] != root: raise ValueError("capability chain does not root at an accepted authority")
    for n, c in enumerate(chain):
        try: ed25519_verify(c["issuer"], c["sig"], c["signed"])
        except Exception: raise ValueError(f"link {n}: invalid signature")
        if c["not_before"] and now < c["not_before"]: raise ValueError(f"link {n}: capability not yet valid")
        if c["not_after"] and now > c["not_after"]: raise ValueError(f"link {n}: capability has expired")
        if (c["issuer"], c["nonce"]) in revoked: raise ValueError(f"link {n}: capability revoked")
        if n == 0:
            if c["parent"] is not None: raise ValueError("root capability must not name a parent")
            continue
        p = chain[n - 1]
        for bad, msg in [(c["issuer"] != p["audience"], "issuer is not the parent's audience"),
                         (c["parent"] != cap_id(p), "parent hash does not match the chain"),
                         (not all(any(covers(g, a) for g in p["abilities"]) for a in c["abilities"]), "abilities exceed the parent"),
                         (not res_subset(c["resource"], p["resource"]), "resource is broader than the parent"),
                         (not caveats_ok(c, p), "caveats are broader than the parent")]:
            if bad: raise ValueError(f"link {n}: {msg}")
    return chain[-1]


# Signed call receipts: one JSON object per line, each signed by the node that ran the call, hash-linked per node.
RECEIPT_FIELDS = ("node", "seq", "prev", "ts", "cell", "caller", "cap", "input", "output", "status")
ZERO = "0" * 64
def receipt_bytes(r):
    """What the node signs: a domain line, then one key=value line per field, in RECEIPT_FIELDS order."""
    return ("ce-receipt/1\n" + "".join(f"{k}={r[k]}\n" for k in RECEIPT_FIELDS)).encode()
receipt_hash = lambda r: hashlib.sha256(receipt_bytes(r)).hexdigest()
def _hex(v, n): return isinstance(v, str) and len(v) == n and all(ch in "0123456789abcdef" for ch in v)

def check_receipt(r, root=None, nodes=None, _chains={}):
    """Raises ValueError naming why one receipt is not valid on its own (format, signature, capability)."""
    for k in RECEIPT_FIELDS + ("chain", "sig"):
        if k not in r: raise ValueError(f"missing field {k}")
    for k in ("node", "prev", "caller", "cap", "input", "output"):
        if not _hex(r[k], 64): raise ValueError(f"{k} is not 32 bytes of lowercase hex")
    for k in ("seq", "ts"):
        if type(r[k]) is not int or r[k] < 0: raise ValueError(f"{k} is not a non-negative integer")
    for k in ("cell", "status"):
        if not isinstance(r[k], str) or "\n" in r[k] or not r[k]: raise ValueError(f"{k} is not a one-line string")
    if not _hex(r["sig"], 128): raise ValueError("sig is not 64 bytes of lowercase hex")
    if nodes is not None and r["node"] not in nodes: raise ValueError(f"signed by node {r['node'][:8]}, which is not a pinned node")
    try: ed25519_verify(bytes.fromhex(r["node"]), bytes.fromhex(r["sig"]), receipt_bytes(r))
    except Exception: raise ValueError(f"invalid signature: these fields are not what node {r['node'][:8]} signed")
    if r["status"] != "ok": return None  # a refused or failed call: the receipt records it, no capability to check
    if r["chain"] not in _chains:
        try: _chains[r["chain"]] = decode(r["chain"])
        except Exception as e: raise ValueError(f"capability chain does not decode ({e})")
    chain = _chains[r["chain"]]
    if not chain: raise ValueError("capability: no capability presented")
    if cap_id(chain[-1]).hex() != r["cap"]: raise ValueError("cap is not the id of the chain's leaf")
    try: leaf = verify_chain(chain, bytes.fromhex(root) if root else chain[0]["issuer"], r["ts"])
    except ValueError as e: raise ValueError(f"capability: {e}")
    if leaf["audience"].hex() != r["caller"]: raise ValueError("capability: the chain is not held by the caller")
    if not any(covers(g, "cell:" + r["cell"]) for g in leaf["abilities"]): raise ValueError(f"capability: does not grant cell:{r['cell']}")
    return chain[0]["issuer"].hex()

def verify_receipts(lines, root=None, nodes=None):
    """Returns (report lines, ok). Checks every receipt, then each node's hash-linked chain for gaps and edits."""
    out, bad, roots, per, last, breaks, total = [], {}, set(), {}, {}, [], 0
    for ln, text in enumerate(lines, 1):
        if not text.strip(): continue
        total += 1
        try:
            r = json.loads(text)
            if not isinstance(r, dict): raise ValueError("not a JSON object")
        except ValueError as e:
            bad[ln] = f"line {ln}: not a receipt ({e})"; continue
        label = f"line {ln} ({r.get('cell', '?')} seq {r.get('seq', '?')} on node {str(r.get('node', '?'))[:8]})"
        try: roots.add(check_receipt(r, root, nodes))
        except ValueError as e: bad[ln] = f"{label}: {e}"
        if not (_hex(r.get("node"), 64) and _hex(r.get("prev"), 64) and type(r.get("seq")) is int): continue
        n = r["node"]; s = per.setdefault(n, {"cells": set(), "receipts": 0, "valid": 0, "first": r["seq"], "last": r["seq"], "breaks": 0})
        s["cells"].add(str(r.get("cell"))); s["receipts"] += 1; s["valid"] += ln not in bad; s["last"] = r["seq"]
        try: h = receipt_hash(r)
        except Exception: h = None
        prev = last.get(n)
        if prev is None:
            if r["seq"] != 0 or r["prev"] != ZERO:
                breaks.append((n, f"chain {n[:8]}: starts at seq {r['seq']} (line {ln}), not seq 0: the first {r['seq']} receipt(s) are missing"))
        else:
            pln, pseq, ph = prev
            if r["seq"] <= pseq:
                breaks.append((n, f"chain {n[:8]}: line {ln} has seq {r['seq']} after seq {pseq} (line {pln}): reordered or duplicated"))
            elif r["seq"] > pseq + 1:
                k = r["seq"] - pseq - 1
                breaks.append((n, f"chain {n[:8]}: gap: {k} receipt(s) missing between seq {pseq} (line {pln}) and seq {r['seq']} (line {ln})" + ("" if r["prev"] != ph else ", yet the link matches")))
            elif r["prev"] != ph:
                why = "which was altered after it was signed" if pln in bad else "the chain was rewritten here"
                breaks.append((n, f"chain {n[:8]}: line {ln} (seq {r['seq']}) does not link to line {pln} (seq {pseq}), {why}"))
        last[n] = (ln, r["seq"], h)
    roots.discard(None)
    if root is None and len(roots) > 1: bad[0] = f"receipts use {len(roots)} different capability roots; pin one with --root"
    for n, _ in breaks: per[n]["breaks"] += 1
    valid = total - len([k for k in bad if k])
    out.append(f"{total} receipts from {len(per)} node(s), capability root {(root or (sorted(roots)[0] if roots else '?'))[:16]}" + ("" if root else " (pin it with --root)"))
    out.append(f"  {'node':9} {'receipts':>8} {'valid':>6}  {'chain':24} cells")
    for n in sorted(per):
        s = per[n]; chain = "intact" if not s["breaks"] else f"{s['breaks']} break(s)"
        out.append(f"  {n[:8]:9} {s['receipts']:>8} {s['valid']:>6}  {chain + ' seq %d..%d' % (s['first'], s['last']):24} {' '.join(sorted(s['cells']))}")
    out += [f"FAIL {m}" for _, m in sorted(bad.items())] + [f"FAIL {m}" for _, m in breaks]
    ok = not bad and not breaks
    out.append(f"{'VALID' if ok else 'INVALID'}: {valid} of {total} receipts valid" + (f", {len(breaks)} chain break(s)" if breaks else ""))
    return out, ok

# ---- token v3 (magic CEC3, ce-net-proto docs/CAPABILITY-PROGRAMS.md): one plain call at one node ----
# Covers Ed25519 and P-256 keys, delegation, Uses, and the conditions Requires / CoSign / Via with
# their proofs. Fails closed on what it does not implement: WebAuthn signatures, Limits, Egress,
# Programs, v1 links inside a v3 chain. Ed25519 needs nothing; P-256 needs the `cryptography` package.

P256_HALF_N = bytes.fromhex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")
USE_WINDOW_S = 300

class Unsupported(ValueError): pass

class _R:  # strict bincode reader: fixed-width little-endian, u64 lengths, 0/1 tags
    def __init__(s, b): s.b, s.i = b, 0
    def take(s, n):
        if s.i + n > len(s.b): raise ValueError("truncated")
        s.i += n; return s.b[s.i - n:s.i]
    def num(s, f): return struct.unpack("<" + f, s.take(struct.calcsize(f)))[0]
    def bytes_(s): return s.take(s.num("Q"))
    def str_(s): return s.bytes_().decode()
    def seq(s, f): return [f() for _ in range(s.num("Q"))]
    def tag(s):
        t = s.take(1)[0]
        if t > 1: raise ValueError("bad option or bool tag")
        return t
    def opt(s, f): return f() if s.tag() else None
    def var(s, n):
        v = s.num("I")
        if v >= n: raise ValueError("unknown variant")
        return v
    def raw(s, f):  # (value, its exact bytes)
        st = s.i; v = f(); return v, s.b[st:s.i]

def _key(r):
    return ("ed25519", r.take(32)) if r.var(2) == 0 else ("p256", r.take(33))

def _sig(r):
    v = r.var(3)
    if v == 2: return ("webauthn", r.bytes_(), r.bytes_(), r.bytes_())
    return ("ed25519" if v == 0 else "p256", r.take(64))

def _res3(r):
    v = r.var(5)
    return [lambda: ("Any",), lambda: ("Node", r.take(32)), lambda: ("Tag", r.str_()),
            lambda: ("AllOf", r.seq(r.str_)), lambda: ("Nodes", r.seq(lambda: r.take(32)))][v]()

def _party(r): return ("Key", _key(r)) if r.var(2) == 0 else ("Cell", r.str_())

def _claim(r):
    if r.var(2) == 0: return ("ReadThrough", r.str_(), r.str_(), r.opt(r.str_))
    return ("Fact", r.str_(), r.bytes_())

def _caveat(r):
    v = r.var(7)
    if v == 0: return ("Uses", r.num("I"), r.var(2))
    if v in (1, 2, 3): raise Unsupported(["Limits", "Egress", "Programs"][v - 1] + " caveats are not supported by this verifier")
    if v == 4: return ("Requires", r.seq(lambda: r.raw(lambda: (_party(r), _claim(r), r.opt(lambda: r.num("Q"))))))
    if v == 5: return ("CoSign", r.seq(lambda: r.raw(lambda: (_key(r), r.var(1)))))
    return ("Via", r.seq(lambda: r.raw(lambda: _party(r))))

def _cap3(r):
    c = dict(v=r.take(1)[0], issuer=_key(r), audience=_key(r), abilities=r.seq(r.str_), resource=_res3(r))
    c.update(not_before=r.num("Q"), not_after=r.num("Q"), max_cpu=r.opt(lambda: r.num("I")), max_mem_mb=r.opt(lambda: r.num("I")),
             max_credits=r.opt(lambda: r.num("Q")), ports=r.opt(lambda: r.seq(lambda: r.num("H"))), path=r.opt(r.str_))
    c["ext"] = r.seq(lambda: _caveat(r))
    c["delegate"] = r.opt(lambda: (r.seq(r.str_), ("Any",) if r.var(2) == 0 else ("Keys", r.seq(lambda: _key(r))), r.take(1)[0]))
    c["nonce"], c["parent"] = r.num("Q"), r.opt(lambda: r.take(32))
    return c

def _tagged(domain, raw): return struct.pack("<Q", len(domain)) + domain + raw

def decode_v3(token_hex):
    b = bytes.fromhex(token_hex.strip())
    if not b.startswith(b"CEC3"): raise ValueError("not a v3 capability token")
    r, links = _R(b[4:]), []
    for _ in range(r.num("Q")):
        if r.var(2) == 0: raise Unsupported("v1 links inside a v3 chain are not supported by this verifier")
        cap, raw = r.raw(lambda: _cap3(r))
        cap["signed"], cap["sig"] = _tagged(b"ce-cap-v3", raw), _sig(r)
        cap["id"] = hashlib.sha256(cap["signed"]).digest()
        links.append(cap)
    if r.num("Q"): raise Unsupported("program bodies are not supported by this verifier")
    if r.i != len(r.b): raise ValueError("trailing bytes")
    return links

def decode_request(req_hex):
    r = _R(bytes.fromhex(req_hex.strip()))
    u = dict(leaf=r.take(32), node=r.take(32), requester=_key(r), action=r.str_(), body=r.take(32), at=r.num("Q"), nonce=r.num("Q"))
    if r.i != len(r.b): raise ValueError("trailing bytes")
    u["raw"] = r.b; return u

def decode_proofs(proofs_hex):
    r = _R(bytes.fromhex(proofs_hex.strip())); out = []
    for _ in range(r.num("Q")):
        v = r.var(3)
        if v == 0:
            body, raw = r.raw(lambda: (_key(r), _key(r), _claim(r), r.num("Q")))
            out.append(("Attested", body, raw, _sig(r)))
        else: out.append(("CoSigned" if v == 1 else "Brokered", _key(r), _sig(r)))
    if r.i != len(r.b): raise ValueError("trailing bytes")
    return out

def _low_s(sig): return sig[0] != "p256" or sig[1][32:] <= P256_HALF_N
def _canon_key(k): return k[0] == "ed25519" or k[1][0] in (2, 3)

def check_sig(key, msg, sig):  # "" if valid, else the reference error text
    if (key[0], sig[0]) not in (("ed25519", "ed25519"), ("p256", "p256"), ("p256", "webauthn")):
        return "signature type does not match the issuer key"
    if sig[0] == "p256":
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        except ImportError: raise Unsupported("P-256 signatures need the cryptography package (pip install -r requirements.txt)")
    try:
        if sig[0] == "ed25519": ed25519_verify(key[1], sig[1], msg); return ""
        if sig[0] == "p256" and _low_s(sig):
            der = encode_dss_signature(int.from_bytes(sig[1][:32], "big"), int.from_bytes(sig[1][32:], "big"))
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key[1]).verify(der, msg, ec.ECDSA(hashes.SHA256())); return ""
    except Unsupported: raise
    except Exception: pass
    return "invalid signature"  # WebAuthn needs an owner root's rp_id, which this verifier has none of

def _strs_ok(*ss): return all(1 <= len(x.encode() if isinstance(x, str) else x) <= 256 for x in ss)

def _canon(c):  # CAPABILITY-PROGRAMS.md 3.4, for the caveats this verifier decodes
    if c["v"] != 3: return "v must be 3"
    if not (_canon_key(c["issuer"]) and _canon_key(c["audience"])): return "malformed key"
    if len(c["abilities"]) > 64: return "more than 64 abilities"
    r = c["resource"]
    if (r[0] == "Nodes" and (not r[1] or r[1] != sorted(set(r[1])))) or (r[0] == "AllOf" and not r[1]):
        return "resource lists must be sorted, unique, non-empty"
    d = c["delegate"]
    if d is not None:
        if d[2] < 1: return "delegate.depth must be >= 1"
        if not 1 <= len(d[0]) <= 64: return "delegate.abilities must hold 1..=64 entries"
    order = [("Uses", "Requires", "CoSign", "Via").index(e[0]) for e in c["ext"]]
    if order != sorted(set(order)): return "ext must hold at most one caveat per variant, ascending"
    for e in c["ext"]:
        if e[0] == "Uses" and e[1] < 1: return "Uses.max must be >= 1"
        if e[0] in ("Requires", "CoSign", "Via"):
            raws = [x[1] for x in e[1]]
            if not 1 <= len(raws) <= 16 or raws != sorted(set(raws)): return f"{e[0]} must hold 1..=16 entries, sorted by encoding, unique"
        if e[0] == "Requires":
            for (party, claim, fresh), _ in e[1]:
                if fresh == 0: return "Requires.fresh_within_s must be >= 1"
                if not _strs_ok(*[x for x in claim[1:] if x is not None]) or (party[0] == "Cell" and not _strs_ok(party[1])):
                    return "condition strings must hold 1..=256 bytes"
    if any(e[0] == "Uses" for e in c["ext"]):
        if c["not_after"] == 0: return "a counted link must set caveats.not_after"
        if r[0] not in ("Node", "Nodes"): return "a counted link must name a finite resource (Node or Nodes)"
    return ""

def _res3_subset(c, p):
    if p[0] == "Any": return True
    if (c[0], p[0]) == ("Nodes", "Node"): return len(c[1]) == 1 and c[1][0] == p[1]
    if (c[0], p[0]) == ("Node", "Nodes"): return c[1] in p[1]
    if (c[0], p[0]) == ("Nodes", "Nodes"): return all(n in p[1] for n in c[1])
    if c[0] in ("Node", "Tag", "AllOf") and p[0] in ("Node", "Tag", "AllOf"):
        return (c[0], p[0]) != ("Node", "Tag") and (c[0], p[0]) != ("Node", "AllOf") and res_subset(c, p)
    return False

def _res3_matches(r, node, tags):
    return {"Any": lambda: True, "Node": lambda: r[1] == node, "Tag": lambda: r[1] in tags,
            "AllOf": lambda: all(t in tags for t in r[1]), "Nodes": lambda: node in r[1]}[r[0]]()

def _abilities_in(child, granted): return all(any(covers(g, a) for g in granted) for a in child)

def _ext_narrower(child, parent):
    def kept(c, p):
        if c[0] != p[0]: return False
        if p[0] == "Uses": return c[1] <= p[1] and c[2] == p[2]
        if p[0] == "Requires":
            def fresh_ok(cf, pf): return pf is None or (cf is not None and cf <= pf)
            return all(any(cr[0] == pr[0] and cr[1] == pr[1] and fresh_ok(cr[2], pr[2]) for cr, _ in c[1]) for pr, _ in p[1])
        return all(x in [y[0] for y in c[1]] for x in [y[0] for y in p[1]])
    return all(any(kept(c, p) for c in child) for p in parent)

def _check_child(c, p):
    if c["issuer"] != p["audience"]: return "issuer is not the parent's audience"
    if c["parent"] != p["id"]: return "parent hash does not match the chain"
    d = p["delegate"]
    if d is None: return "the parent may not delegate"
    if d[1][0] == "Keys" and c["audience"] not in d[1][1]: return "audience is outside the parent's grant"
    if not _abilities_in(c["abilities"], d[0]): return "abilities exceed the parent's grant"
    e = c["delegate"]
    if e is not None:
        if d[2] < 2 or e[2] > d[2] - 1: return "delegation depth exceeds the parent"
        if not _abilities_in(e[0], d[0]): return "grantable abilities exceed the parent"
        if d[1][0] == "Keys" and (e[1][0] == "Any" or any(k not in d[1][1] for k in e[1][1])): return "grantable audience exceeds the parent"
    if not _res3_subset(c["resource"], p["resource"]): return "resource is broader than the parent"
    if not caveats_ok(c, p) or not _ext_narrower(c["ext"], p["ext"]): return "caveats are broader than the parent"
    return ""

def verify_use(token_hex, roots, node, requester, action, now, request_hex=None, proofs_hex="", body_sha256=None,
               tags=(), cell_keys=None, revoked=()):
    """authorize_use_v3 of a plain call (or authorize_v3 without a request). Returns the leaf link;
    raises ValueError with the reference error text if the use is refused."""
    cell_keys = cell_keys or {}
    chain = decode_v3(token_hex)
    if not chain: raise ValueError("no capability presented")
    for i, c in enumerate(chain):
        why = _canon(c)
        if why: raise ValueError(f"link {i}: not canonical ({why})")
        if not _low_s(c["sig"]): raise ValueError(f"link {i}: not canonical (P-256 signature is not low-S)")
    root = chain[0]["issuer"]
    if root not in roots and root != ("ed25519", node): raise ValueError("capability chain does not root at an accepted authority")
    if chain[0]["parent"] is not None: raise ValueError("root capability must not name a parent")
    conditions = []
    for i, c in enumerate(chain):
        why = check_sig(c["issuer"], c["signed"], c["sig"])
        if why: raise ValueError(f"link {i}: {why}")
        if c["not_before"] and now < c["not_before"]: raise ValueError(f"link {i}: capability not yet valid")
        if c["not_after"] and now > c["not_after"]: raise ValueError(f"link {i}: capability has expired")
        if (c["issuer"], c["nonce"]) in revoked: raise ValueError(f"link {i}: capability revoked")
        if not _res3_matches(c["resource"], node, tags): raise ValueError(f"link {i}: resource does not match this node")
        if i:
            why = _check_child(c, chain[i - 1])
            if why: raise ValueError(f"link {i}: {why}")
        conditions += [e for e in c["ext"] if e[0] in ("Requires", "CoSign", "Via")]
    leaf = chain[-1]
    if leaf["audience"] != requester: raise ValueError("leaf capability is not held by the request sender")
    if not any(covers(a, action) for a in leaf["abilities"]): raise ValueError(f"capability does not grant '{action}'")
    not_met = lambda e: ValueError("condition not met: " + {"Requires": "requires", "CoSign": "cosign"}.get(e[0], "via"))
    if request_hex is None:
        if conditions: raise not_met(conditions[0])
        return leaf
    proofs, u = decode_proofs(proofs_hex or "0000000000000000"), decode_request(request_hex)
    if len(proofs) > 64: raise ValueError("more than 64 proofs")
    for i, p in enumerate(proofs):
        keys, sig = ((p[1][0], p[1][1]), p[3]) if p[0] == "Attested" else ((p[1],), p[2])
        if p[0] == "Attested" and p[1][2][0] == "ReadThrough" and p[1][2][3] is None:
            raise ValueError(f"proof {i}: not canonical (an attestation must name the message read through)")
        if not all(_canon_key(k) for k in keys): raise ValueError(f"proof {i}: not canonical (malformed key)")
        if not _low_s(sig): raise ValueError(f"proof {i}: not canonical (P-256 signature is not low-S)")
    if not _canon_key(u["requester"]): raise ValueError("use request is malformed (malformed key)")
    if not u["action"]: raise ValueError("use request is malformed (use request names no action)")
    for field, ok in (("leaf", u["leaf"] == leaf["id"]), ("node", u["node"] == node), ("requester", u["requester"] == leaf["audience"]),
                      ("action", u["action"] == action), ("body", body_sha256 is None or u["body"] == body_sha256)):
        if not ok: raise ValueError(f"use request is not this use ({field})")
    if abs(now - u["at"]) > USE_WINDOW_S: raise ValueError(f"use request is outside the {USE_WINDOW_S} s window")
    attested, cosigned, brokered = [], [], []
    for p in proofs:
        if p[0] == "Attested":
            if not check_sig(p[1][0], _tagged(b"ce-cap-v3-attest", p[2]), p[3]): attested.append(p[1])
        elif p[0] == "CoSigned":
            if not check_sig(p[1], _tagged(b"ce-cap-v3-cosign", u["raw"]), p[2]): cosigned.append(p[1])
        elif not check_sig(p[1], _tagged(b"ce-cap-v3-via", u["raw"]), p[2]): brokered.append(p[1])
    keys_of = lambda party: [party[1]] if party[0] == "Key" else cell_keys.get(party[1], [])
    def proved(req, stated):
        if req[0] != stated[0]: return False
        if req[0] == "ReadThrough": return req[1:3] == stated[1:3] and stated[3] is not None and req[3] in (None, stated[3])
        return req[1:] == stated[1:]
    def met_req(party, claim, fresh):
        return any(w in keys_of(party) and s == leaf["audience"] and proved(claim, cl) and at <= now and (fresh is None or now - at <= fresh)
                   for w, s, cl, at in attested)
    for e in conditions:
        ok = {"Requires": lambda: all(met_req(*r) for r, _ in e[1]),
              "CoSign": lambda: all(k in cosigned for (k, _), _ in e[1]),
              "Via": lambda: all(any(b in keys_of(party) for b in brokered) for party, _ in e[1])}[e[0]]()
        if not ok: raise not_met(e)
    return leaf

def _key_text(t):
    kind, h = t.split(":", 1)
    return (kind, bytes.fromhex(h))

def run_use_vectors(path):
    """Check every case of a v3 use-vector file; returns the number of mismatches."""
    import json
    v, failed = json.load(open(path)), 0
    roots = [_key_text(k) for k in v["roots"]]
    cells = {api: [_key_text(k) for k in ks] for api, ks in v.get("cell_keys", {}).items()}
    for c in v["cases"]:
        try:
            verify_use(c["token"], roots, bytes.fromhex(v["node"]), _key_text(c["requester"]), c["action"], c["now"],
                       c.get("request"), c.get("proofs", ""), bytes.fromhex(c["body_sha256"]) if c.get("body_sha256") else None,
                       v.get("node_tags", []), cells)
            got = None
        except ValueError as e: got = str(e)
        want = c["expect"]["reason"] if not c["expect"]["allowed"] else None
        ok = got == want
        failed += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {c['name']:<34} {'allowed' if got is None else 'refused: ' + got}" + ("" if ok else f"   (expected {want or 'allowed'})"))
    print(f"{len(v['cases']) - failed}/{len(v['cases'])} use vectors pass")
    return failed


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "use": sys.exit(1 if run_use_vectors(sys.argv[2]) else 0)
    if len(sys.argv) >= 2 and os.path.isfile(sys.argv[1]):
        args, root, nodes = sys.argv[2:], None, None
        while args:
            flag = args.pop(0)
            if flag == "--root" and args: root = args.pop(0).lower()
            elif flag == "--nodes" and args: nodes = set(args.pop(0).lower().split(","))
            else: sys.exit(__doc__)
        with open(sys.argv[1], encoding="utf-8") as f: report, ok = verify_receipts(f.read().splitlines(), root, nodes)
        print("\n".join(report)); sys.exit(0 if ok else 1)
    if len(sys.argv) < 3: sys.exit(__doc__)
    now = int(sys.argv[3]) if len(sys.argv) > 3 else int(time.time())
    revoked = {(bytes.fromhex(r.split(":")[0]), int(r.split(":")[1])) for r in sys.argv[4:]}
    try: leaf = verify_chain(decode(sys.argv[2]), bytes.fromhex(sys.argv[1]), now, revoked)
    except ValueError as e: sys.exit(f"INVALID: {e}")
    r = leaf["resource"]
    print(f"VALID: holder {leaf['audience'].hex()}\n  abilities {leaf['abilities']}\n  resource  {r[0]} {r[1].hex() if r[0] == 'Node' else r[1] if len(r) > 1 else ''}")
