# capability-verify

Verify a ce-net capability chain, or a file of signed call receipts, **offline**, in one small Python file,
with no ce-net code, no network and no packages (Python standard library only).

A ce-net capability is a chain of signed links: a root key grants abilities to a holder, who may
delegate a narrower subset onward. `verify.py` decodes the token, checks every Ed25519 signature,
the hash links between links, expiry, revocation, and that each delegation only narrows
(abilities, resource, caveats). It reproduces all 12 golden vectors in `vectors.json` byte for byte.

## Quick start (under 5 minutes)

Needs Python 3.9+ and git. Installing `cryptography` (`pip install -r requirements.txt`) is optional and only makes signature checks faster.

```sh
git clone https://github.com/ce-net/ce-net-capability-verify && cd ce-net-capability-verify
python3 test_vectors.py
```

Expected output:

```
ok   issued                             valid
ok   delegated                          valid
ok   delegated-ability-not-granted      valid
ok   delegated-expired                  link 1: capability has expired
ok   expired                            link 0: capability has expired
ok   not-yet-expired                    valid
ok   revoked-leaf                       link 1: capability revoked
ok   revoked-root                       link 0: capability revoked
ok   revoked-other-issuer-same-nonce    valid
ok   tampered                           link 1: invalid signature
ok   amplified                          link 1: abilities exceed the parent
ok   wrong-root                         capability chain does not root at an accepted authority
12/12 vectors pass
ok   20 honest receipts verify
...
9/9 receipt checks pass
```

## Verify a token yourself

```
python3 verify.py ROOT_HEX TOKEN_HEX [NOW_UNIX_SECONDS] [REVOKED_ISSUER_HEX:NONCE ...]
```

Take the two-link `delegated` chain (root -> a -> b) from the vectors:

```sh
ROOT=8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
TOKEN=$(python3 -c "import json; print(json.load(open('vectors.json'))['chains'][1]['chain_hex'])")
python3 verify.py $ROOT $TOKEN 1700000100
```

```
VALID: holder ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1
  abilities ['sync', 'app:spawn:wasm']
  resource  AllOf ['gpu', 'linux']
```

The same token an hour later, after the middle holder revokes its link, and with one byte flipped:

```sh
python3 verify.py $ROOT $TOKEN 1700003601
python3 verify.py $ROOT $TOKEN 1700000100 8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394:11
python3 verify.py $ROOT ${TOKEN%?}0 1700000100
```

```
INVALID: link 1: capability has expired
INVALID: link 1: capability revoked
INVALID: link 1: invalid signature
```

Exit code is 0 for valid, 1 for invalid. Without `NOW` the current time is used.

## Verify call receipts

A receipt is one JSON line per call, signed by the node that ran it and hash-linked to that node's
previous receipt. Each names the call's cell, caller, input and output hashes, and the capability chain
the caller presented. `verify.py` checks every signature, every capability chain (valid at the call's
time, held by the caller, granting `cell:<name>`), and each node's chain for gaps, edits and replays:

```sh
python3 verify.py receipts.jsonl --root 86f9f18295a18b9d604ef9a56a9047a0cc2e69f200e5f84d9b1f3cd267c6e40f
```

```
20 receipts from 1 node(s), capability root 86f9f18295a18b9d
  node      receipts  valid  chain                    cells
  b7e26cb9        20     20  intact seq 0..19         mcp.echo
VALID: 20 of 20 receipts valid
```

`--nodes HEX,HEX` also pins which node keys may sign. The format and the middleware that writes
receipts are in [demo-signed-receipts](https://github.com/ce-net/demo-demo-signed-receipts).

## Use it as a library

```python
from verify import decode, verify_chain
leaf = verify_chain(decode(token_hex), bytes.fromhex(root_hex), now=1700000100, revoked={(issuer_bytes, nonce)})
print(leaf["audience"].hex(), leaf["abilities"])   # raises ValueError with the reason if invalid
```

## The format in one screen

Encoding is bincode 1.x: little-endian fixed-width integers, `u64` length prefixes, options as a
`00`/`01` tag byte, enums as a `u32` variant index.

```
token     = hex( seq<SignedCapability> )               root link first, holder's link last
Signed    = Capability || u64(64) || ed25519 sig (64 bytes)
Capability= issuer[32] audience[32] seq<string> abilities  Resource  Caveats  u64 nonce  option<[32]> parent
Resource  = 0 Any | 1 Node([32]) | 2 Tag(string) | 3 AllOf(seq<string>)
Caveats   = u64 not_before, u64 not_after, option<u32> max_cpu, option<u32> max_mem_mb,
            option<u64> max_credits, option<seq<u16>> allowed_ports, option<string> path_prefix
signed    = u64(9) || "ce-cap-v1" || Capability         what the issuer signs (pure Ed25519)
cap_id    = sha256(signed)                              each child's `parent` is its parent's cap_id
```

Abilities match exactly, by `*`, or by a `prefix:*` wildcard (`app:spawn:*` covers `app:spawn:wasm`).

## Token v3: verify one use, conditions included

ce-net-proto's v3 tokens (magic `CEC3`, [CAPABILITY-PROGRAMS.md](https://github.com/ce-net/ce-net-proto/blob/main/docs/CAPABILITY-PROGRAMS.md))
carry delegation rights and conditions: `Requires` (a witness attests something was done first, such as a read
receipt), `CoSign` (a key signs the exact request) and `Via` (a broker approves it). `verify_use` in the same
`verify.py` runs the node-side check of one plain call: the chain, the use request and its proofs.

```sh
python3 test_vectors.py
```

```
ok   wechat-read-then-write             allowed
ok   wechat-write-unread                refused: condition not met: requires
...
28/28 ce-net-proto v3 plain-call uses agree (24 skipped: program steps, or P-256 without the cryptography package)

ok   refused-without-receipt            refused: condition not met: requires
ok   accepted-with-receipt              allowed
...
13/13 use vectors pass
```

`vectors_v3.json` is ce-net-proto's conformance set (Apache-2.0, copied from `tests/v3_vectors.json`).
`vectors_v3_read_receipt.json` is from [demo-read-before-act](https://github.com/ce-net/demo-demo-read-before-act): an
approve key that works only after the reader's phone signs a read receipt. Check any file in that format with:

```sh
python3 verify.py use vectors_v3_read_receipt.json
```

As a library:

```python
from verify import verify_use
leaf = verify_use(token_hex, roots=[("ed25519", root_bytes)], node=node_id_bytes, requester=("ed25519", holder_bytes),
                  action="change.approve:approve", now=1800000070, request_hex=req_hex, proofs_hex=proofs_hex,
                  body_sha256=sha256_of_body, cell_keys={"wechat.read": [("ed25519", key_bytes)]})
```

Ed25519 needs only the standard library; P-256 links (a passkey device key) need `cryptography`, and without it
those uses are skipped, never passed. It fails closed on what it does not implement: WebAuthn signatures, `Limits`, `Egress` and `Programs` caveats,
program bodies, v1 links inside a v3 chain. It is stateless: use counters and the replay log (`request replayed`)
are the executing node's.

## Limits

- This checks a chain against a root you trust. It does not check that the resource names *your*
  node or that the holder is the one sending a request; add those two comparisons on the leaf if you
  run a service.
- Revocations are passed in as `(issuer, nonce)` pairs; fetching them is up to you.
- Resource ceilings (`max_cpu`, `max_mem_mb`, `max_credits`, `allowed_ports`, `path_prefix`) are
  checked for narrowing across the chain but enforced by whatever consumes the capability.
- Signature checks are RFC 8032 Ed25519: the `cryptography` package when installed, otherwise a short
  pure-Python implementation in the same file (slower, about 15 ms per signature). Honest signatures
  verify identically everywhere; adversarial edge cases (small-order keys) may differ between libraries.

## License

MIT
