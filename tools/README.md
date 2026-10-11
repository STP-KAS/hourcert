> **Experimental. Testnet-10 only.**

# hourcert tools

- `hourcert.rs`: a Rust binary that builds every hourcert spend path (and the oneword bond on the meter key), signs locally and writes one JSON file per transaction (Borsh hex included). It never prints a key. It also builds the deliberately invalid variants used in the test run, two controls for the mutation method, off-chain meter readings (`meter-sign`), and runs an offline `selftest`.
- `submit1.mjs`: sends one of those files to a synced testnet-10 node (`node submit1.mjs <row.json> <log.jsonl>`). It refuses a node that is not testnet-10 or not synced.
- `waitage.mjs`: waits until a transaction has left the mempool, then until the DAA score has moved on by `window` plus a margin (`node waitage.mjs <txid> <window> [margin]`).

## Build

1. Check out argent-lang/kcc20-reference at `c8a087117735a1f87c5c6d115fcddeaf2562c784` (it pins Argent `9a9f4b10`, Silverscript v1.0.0 and Rust 1.94.1).
2. Copy `../contracts/hourcert.ag` and `../contracts/oneword.ag` to `contracts/`, and `hourcert.rs` to `src/bin/hourcert/main.rs`.
3. In `Cargo.toml` add a binary and three dependencies:

```toml
[[bin]]
name = "hourcert"
path = "src/bin/hourcert/main.rs"

[dependencies]
kaspa-addresses = { git = "https://github.com/kaspanet/rusty-kaspa", rev = "a41a333b08848f41bf737b72592e463a6011b8ac" }
serde_json = "1"
blake2b_simd = "1.0.5"
```

4. `cargo build --bin hourcert`, then `hourcert selftest` (no node or key needed). It should report 29 passed and 0 failed.
5. `hourcert info` prints the artifact ids. HourCert should be `44df7267f19824257c2254259bf3c087297083e07e79001dfd6cd3b03c4d8f30`; OneWord `06be3b66f92da3f331d09d23e40f07b5ab7c7e4990a72a2e9f6bfe109114d9ee`, the same as [STP-KAS/oneword](https://github.com/STP-KAS/oneword).

`../generated/*.sil` is the Silverscript that Argent generated from the contract, kept here for review.

## Environment

| Variable | Meaning |
| --- | --- |
| `HC_PAYER_KEY`, `HC_PAYER_ADDRESS` | file with one 64-hex secret and its `kaspatest:` P2PK address: pays fees and deposits, is the "producer" holder and the bond beneficiary; the tool refuses a mismatch or a mainnet address |
| `HC_ISSUER_KEY` | issuing body: co-signs every issuance, closes the device |
| `HC_METER_KEY` | meter attester: signs readings; also the oneword bond's attester |
| `HC_AUDITOR_KEY` | auditor: invalidates, archives voided certificates |
| `HC_BUYER_KEY` | the second holder |
| `HC_FORGER_KEY` | an unrelated key, used only by the invalid variants |
| `HC_STATE`, `HC_OUT`, `HC_LABEL` | state file, output folder, file label; each command writes `<label>.json` with the transaction and the `next` state to adopt if it lands |
| `HC_RATE` | sompi per gram (default 100) |
| `HC_DEVICE_VALUE`, `HC_CERT_VALUE`, `HC_BOND_VALUE` | deposits (defaults 1, 0.8 and 1.5 tKAS; covenant outputs count double for KIP-9 storage mass, so smaller deposits push issuance over the standard mass limit) |
| `HC_MAX_WH`, `HC_ARCHIVE_AFTER`, `HC_START_HOUR` | genesis parameters (defaults 1,000,000 Wh per hour, 300 DAA, 0) |
| `HC_REGISTRY_SEED`, `HC_DEVICE_SEED`, `HC_METER_DOMAIN_SEED` | the 32-byte ids are `blake2b(seed)` (defaults `hourcert/v1/registry/R1`, `hourcert/v1/device/FAC-TN10-0001`, `hourcert/v1/meter/M1`) |
| `HC_BOUNTY`, `HC_UNBOND`, `HC_MIN_TOPUP` | oneword bond parameters (defaults 20 %, 300 DAA, 0.2 tKAS) |
| `HC_EXPECT` | override the expected verdict of a valid build (for example `reject` for an archive sent before the window) |
| `KASPA_WASM`, `HC_URL` | for the `.mjs` scripts: path to the kaspa-wasm32-sdk `kaspa.js`, and the wRPC Borsh URL of your node |

## Commands

`genesis <funding-file>...`, `issue <cert> <hour> <wh>`, `transfer <cert>`, `split <cert> <take> <new-cert>`, `retire <cert> <claim-text>`, `invalidate <cert> <reason-text>`, `archive <cert>`, `close`, `bond-genesis`, `meter-sign <hour> <wh> <registry-seed>`, `slash-meter <hour> <wh> <other-registry-seed>`; invalid variants `bad-replay`, `bad-meter`, `bad-issuer`, `bad-cap`, `bad-amount`, `bad-transfer <cert>`, `bad-split <cert> <take>`, `bad-skim <cert>`, `bad-reuse <retired-cert>`, `bad-void <cert>`, `bad-archive <cert>`, `bad-close`; controls `ctl-hour`, `ctl-amount`.

`hour` is hours since the Unix epoch (2026-10-11 09:00 UTC is 497697). `wh` is watt-hours.

Each invalid variant is a valid transaction with exactly one thing changed (a signature, an argument and the matching output script, or a value), re-signed where the change touches what a signature covers. The two controls make the same kind of edit to a legal value and must pass, which shows the edit itself does not break a transaction.

Meter readings are signed without auxiliary randomness so a drill can rebuild the same signature byte for byte. A real meter may sign either way; the covenant only checks the signature.

`slash-meter` signs both readings with the meter key, which is what a drill needs. A real slasher does not have that key: it collects the on-chain reading (it is in the issuance transaction) and the second reading someone else published.

Use the `next` state only after the node has accepted the transaction and it has really landed. A Kaspa transaction id does not cover signature scripts, so an invalid variant that only changes a signature has the same id as its valid twin.
