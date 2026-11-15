#!/usr/bin/env python3
"""Verify ce-net capability chains and signed call receipts offline, with the standard library only.

  python3 verify.py ROOT_HEX TOKEN_HEX [NOW] [ISSUER_HEX:NONCE ...]   one capability chain
  python3 verify.py RECEIPTS.jsonl [--root HEX] [--nodes HEX,HEX...]   a file of signed call receipts"""
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

if __name__ == "__main__":
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
