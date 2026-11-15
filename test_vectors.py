#!/usr/bin/env python3
"""Check verify.py against every golden vector in vectors.json, then the receipt verifier on receipts.jsonl
(20 receipts signed on the ce-net local sim): honest, one output hash edited, one dropped, one replayed.
Exit code 0 = all pass."""
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

verify.ed25519_verify = verify._pure_verify
check("pure-Python Ed25519 verifies the same file", verify.verify_receipts(lines, ROOT)[1])
check("pure-Python Ed25519 passes the capability vectors", all(
    run_vector(v)[0] for v in vectors["chains"]))
print(f"{sum(checks)}/{len(checks)} receipt checks pass")
sys.exit(1 if failed or not all(checks) else 0)
