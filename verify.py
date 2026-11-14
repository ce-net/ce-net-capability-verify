#!/usr/bin/env python3
"""Verify a ce-net capability chain offline. Usage: python3 verify.py ROOT_HEX TOKEN_HEX [NOW] [ISSUER_HEX:NONCE ...]"""
import hashlib, struct, sys, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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
        try: Ed25519PublicKey.from_public_bytes(c["issuer"]).verify(c["sig"], c["signed"])
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

if __name__ == "__main__":
    if len(sys.argv) < 3: sys.exit(__doc__)
    now = int(sys.argv[3]) if len(sys.argv) > 3 else int(time.time())
    revoked = {(bytes.fromhex(r.split(":")[0]), int(r.split(":")[1])) for r in sys.argv[4:]}
    try: leaf = verify_chain(decode(sys.argv[2]), bytes.fromhex(sys.argv[1]), now, revoked)
    except ValueError as e: sys.exit(f"INVALID: {e}")
    r = leaf["resource"]
    print(f"VALID: holder {leaf['audience'].hex()}\n  abilities {leaf['abilities']}\n  resource  {r[0]} {r[1].hex() if r[0] == 'Node' else r[1] if len(r) > 1 else ''}")
