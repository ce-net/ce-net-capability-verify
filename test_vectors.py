#!/usr/bin/env python3
"""Check verify.py against every golden vector in vectors.json. Exit code 0 = all pass."""
import json, sys
from verify import decode, verify_chain, cap_id

vectors = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "vectors.json"))
failed = 0
for v in vectors["chains"]:
    chain = decode(v["chain_hex"])
    for c, link in zip(chain, v["links"]):  # byte-exact: what was signed, its id, its signature
        assert c["signed"].hex() == link["cap_bytes"] and cap_id(c).hex() == link["cap_id"] and c["sig"].hex() == link["sig"], v["name"]
    revoked = {(bytes.fromhex(r["issuer"]), r["nonce"]) for r in v["revoked"]}
    try: verify_chain(chain, bytes.fromhex(v["root"]), v["now"], revoked); got = {"ok": True}
    except ValueError as e: got = {"ok": False, "error": str(e)}
    ok = got == v["verify_chain"]
    failed += not ok
    print(f"{'ok  ' if ok else 'FAIL'} {v['name']:34} {got.get('error', 'valid')}")
print(f"{len(vectors['chains']) - failed}/{len(vectors['chains'])} vectors pass")
sys.exit(1 if failed else 0)
