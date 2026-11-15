#!/usr/bin/env python3
"""Check verify.py against every golden vector in vectors.json, then the receipt verifier on receipts.jsonl
(20 receipts signed on the ce-net local sim): honest, one output hash edited, one dropped, one replayed;
then v3 uses (verify_use) against vectors_v3.json and vectors_v3_read_receipt.json. Exit code 0 = all pass."""
import json, sys
import verify
from verify import decode, cap_id

vectors = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "vectors.json"))
failed = 0
def run_vector(v):
    chain = decode(v["chain_hex"])
    for c, link in zip(chain, v["links"]):  # byte-exact: what was signed, its id, its signature
        assert c["signed"].hex() == link["cap_bytes"] and cap_id(c).hex() == link["cap_id"] and c["sig"].hex() == link["sig"], v["name"]
    revoked = {(bytes.fromhex(r["issuer"]), r["nonce"]) for r in v["revoked"]}
    try: verify.verify_chain(chain, bytes.fromhex(v["root"]), v["now"], revoked); got = {"ok": True}
    except ValueError as e: got = {"ok": False, "error": str(e)}
    return got == v["verify_chain"], got

for v in vectors["chains"]:
    ok, got = run_vector(v)
    failed += not ok
    print(f"{'ok  ' if ok else 'FAIL'} {v['name']:34} {got.get('error', 'valid')}")
print(f"{len(vectors['chains']) - failed}/{len(vectors['chains'])} vectors pass")

ROOT = "86f9f18295a18b9d604ef9a56a9047a0cc2e69f200e5f84d9b1f3cd267c6e40f"
lines = open("receipts.jsonl").read().splitlines()
checks = []
def check(name, cond): checks.append(cond); print(f"{'ok  ' if cond else 'FAIL'} {name}")

report, ok = verify.verify_receipts(lines, ROOT)
check("20 honest receipts verify", ok and report[-1] == "VALID: 20 of 20 receipts valid")
check("a wrong pinned root is refused", not verify.verify_receipts(lines, "00" * 32)[1])
check("a pinned node set excludes others", not verify.verify_receipts(lines, ROOT, {"11" * 32})[1])

edited = list(lines); r = json.loads(edited[6]); r["output"] = "ab" * 32; edited[6] = json.dumps(r)
report, ok = verify.verify_receipts(edited, ROOT)
check("an edited output hash names line 7", not ok and any(l.startswith("FAIL line 7 (mcp.echo seq 6") and "invalid signature" in l for l in report))
check("and the next receipt no longer links to it", any("line 8 (seq 7) does not link to line 7 (seq 6), which was altered" in l for l in report))

report, ok = verify.verify_receipts(lines[:10] + lines[11:], ROOT)
check("a dropped receipt shows as a gap", not ok and any("gap: 1 receipt(s) missing between seq 9 (line 10) and seq 11 (line 11)" in l for l in report))

report, ok = verify.verify_receipts(lines[:5] + [lines[3]] + lines[5:], ROOT)
check("a replayed receipt is caught", not ok and any("reordered or duplicated" in l for l in report))

_ed25519_default = verify.ed25519_verify
verify.ed25519_verify = verify._pure_verify
check("pure-Python Ed25519 verifies the same file", verify.verify_receipts(lines, ROOT)[1])
check("pure-Python Ed25519 passes the capability vectors", all(
    run_vector(v)[0] for v in vectors["chains"]))
print(f"{sum(checks)}/{len(checks)} receipt checks pass")

# v3 uses (verify.verify_use): ce-net-proto's conformance vectors (vectors_v3.json, Apache-2.0, every
# plain-call use; program steps are skipped) and demo-read-before-act's read-receipt vectors.
verify.ed25519_verify = _ed25519_default
import hashlib, struct
from verify import verify_use, run_use_vectors, decode_request, Unsupported
print()
K = lambda k: ("ed25519" if k["type"] == "Ed25519" else "p256", bytes.fromhex(k["public"]))
v = json.load(open("vectors_v3.json"))
n = bad = skip = 0
for x in v["vectors"]:
    roots = [K(k) for k in x["roots"]["keys"]] + [K(o["key"]) for o in x["roots"]["owners"]]
    cells = {c["api"]: [K(k) for k in c["keys"]] for c in x["cell_keys"]}
    seen = set()  # a node's request-id log: verify_use itself is stateless
    for u, e in zip(x["uses"], x["expect"]["uses"]):
        if "call" not in u["request"]:
            skip += 1; continue
        p = u["presented"]
        try:
            verify_use(u["token_hex"] or x["token_hex"], roots, bytes.fromhex(u["node"]["id"]), K(u["requester"]), u["request"]["call"],
                       int(x["now"]), p and p["use_request_hex"], p and p["proofs_hex"],
                       p and hashlib.sha256(bytes.fromhex(p["body_hex"])).digest(), (), cells)
            got = None
            if p:
                rid = hashlib.sha256(struct.pack("<Q", 17) + b"ce-cap-v3-request" + decode_request(p["use_request_hex"])["raw"]).digest()
                if rid in seen: got = "request replayed"
                seen.add(rid)
        except Unsupported:
            skip += 1; continue
        except ValueError as ex:
            got = str(ex)
        want = None if e.get("ok") else e.get("error")
        n += 1
        ok = got == want
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {x['name']:<34} {'allowed' if got is None else 'refused: ' + got}" + ("" if ok else f"   (expected {want or 'allowed'})"))
print(f"{n - bad}/{n} ce-net-proto v3 plain-call uses agree ({skip} skipped: program steps, or P-256 without the cryptography package)\n")
bad += run_use_vectors("vectors_v3_read_receipt.json")
sys.exit(1 if failed or bad or not all(checks) else 0)
