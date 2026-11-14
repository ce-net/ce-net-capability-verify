# capability-verify

Verify a ce-net capability chain **offline**, in one small Python file, with no ce-net code and no network.

A ce-net capability is a chain of signed links: a root key grants abilities to a holder, who may
delegate a narrower subset onward. `verify.py` decodes the token, checks every Ed25519 signature,
the hash links between links, expiry, revocation, and that each delegation only narrows
(abilities, resource, caveats). It reproduces all 12 golden vectors in `vectors.json` byte for byte.

## Quick start (under 5 minutes)

Needs Python 3.9+ and git.

```sh
git clone https://github.com/ce-net/capability-verify && cd capability-verify
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
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

## Limits

- This checks a chain against a root you trust. It does not check that the resource names *your*
  node or that the holder is the one sending a request; add those two comparisons on the leaf if you
  run a service.
- Revocations are passed in as `(issuer, nonce)` pairs; fetching them is up to you.
- Resource ceilings (`max_cpu`, `max_mem_mb`, `max_credits`, `allowed_ports`, `path_prefix`) are
  checked for narrowing across the chain but enforced by whatever consumes the capability.
- Signature checks use the `cryptography` package (RFC 8032 Ed25519). Honest signatures verify
  identically everywhere; adversarial edge cases (small-order keys) may differ between libraries.

## License

MIT
