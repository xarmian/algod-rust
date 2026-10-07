# algo-ledger fixtures

## mainnet_53000003_txn3_itx.hex

Byte-exact go-algorand output used as an oracle by
`eval_delta::tests::mainnet_itx_round_trips_byte_exact_through_canonical_encoder`
(issue #1739): the `itx` value (`[]SignedTxnWithAD`, 987 bytes, hex-encoded on
one line) of the `dt` of transaction index 3 in **mainnet round 53000003**
(an app call with two inner entries, one of them an app call whose own `dt`
carries a nested `itx` and an `lg`). Public chain data, sliced verbatim from the
block msgpack with no trimming or re-encoding.

Source: `https://mainnet-api.algonode.cloud/v2/blocks/53000003?format=msgpack`

Regenerate (python `msgpack` >= 1.0; slices the raw bytes by stream offsets, so
nothing is re-packed):

```python
import msgpack, urllib.request, sys
r, idx = 53000003, 3
body = urllib.request.urlopen(
    f"https://mainnet-api.algonode.cloud/v2/blocks/{r}?format=msgpack").read()
u = msgpack.Unpacker(raw=True, strict_map_key=False); u.feed(body)
for _ in range(u.read_map_header()):                 # top-level
    if u.unpack() != b'block': u.skip(); continue
    for _ in range(u.read_map_header()):             # block
        if u.unpack() != b'txns': u.skip(); continue
        for i in range(u.read_array_header()):       # txns
            if i != idx: u.skip(); continue
            for _ in range(u.read_map_header()):     # the stib
                if u.unpack() != b'dt': u.skip(); continue
                s = u.tell(); u.skip(); dt = body[s:u.tell()]
                u2 = msgpack.Unpacker(raw=True, strict_map_key=False); u2.feed(dt)
                for _ in range(u2.read_map_header()):  # the dt
                    if u2.unpack() != b'itx': u2.skip(); continue
                    a = u2.tell(); u2.skip()
                    open("mainnet_53000003_txn3_itx.hex", "w").write(dt[a:u2.tell()].hex() + "\n")
                    sys.exit(0)
```

The file is LF-pinned by the `crates/**/fixtures/**` rule in `.gitattributes`.
