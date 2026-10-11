> **Experimental. Not advice. Testnet-10 only.** tKAS has no value. No certificate made here counts for anything. [DISCLAIMER.md](DISCLAIMER.md)

# hourcert

Hourly energy-attribute certificates on Kaspa Testnet-10, with the lifecycle rules a registry needs enforced by covenants: **one certificate per meter-hour, one holder at a time, one retirement against one claim, and invalidation that leaves the record visible.** The meter signs its readings in the [oneword](https://github.com/STP-KAS/oneword) format, so a meter that sells the same hour into a second registry can lose a bond, without the two registries ever talking to each other.

A certificate here is evidence about a clean megawatt-hour or tonne of hydrogen, not the energy itself and not a contract. Everything physical (did the plant really run, is the meter honest) sits with the meter key, the issuing body and the auditor. The covenant only makes sure that what they sign is used once.

## Why: the industry problem

Clean-energy markets trade the *proof* that a unit was made cleanly separately from the unit itself. That proof is only worth something if it is counted once.

- **Double counting is the failure every scheme is built around.** US tracking systems require a generator to register in only one system and report all of its output there, precisely so that the same MWh is not issued twice ([US EPA, Status and Trends Report on U.S. Energy Attribute Tracking Systems, Jan 2025](https://www.epa.gov/system/files/documents/2025-01/status_and_trends_report_us_energy_attribute_tracking_systems.pdf)). Cross-registry transfers still rest on bilateral agreements and manual reconciliation.
- **The hour is becoming the unit of proof.** EU rules for renewable hydrogen (RFNBOs) move from monthly to hourly matching of clean power from 1 January 2030 ([Commission Delegated Regulation (EU) 2023/1184](https://eur-lex.europa.eu/eli/reg_del/2023/1184/oj)). Registries in the US, Taiwan and under I-REC already issue hourly or sub-hourly certificates, and EnergyTag sets the granular-certificate standard ([EnergyTag FAQ](https://energytag.org/faq/)). Hourly means 8,760 certificates per meter per year instead of 12, and 8,760 chances per meter to count an hour twice.
- **Evidence can fail after the claim.** ZETA, the Zero Emissions Traders Alliance (an affiliate of Dii Desert Energy), puts it on its home page: a certificate must be "issued once, owned by one party at a time, retired against one claim", and when evidence fails later the unit is "void on the record, with the reason attached. Nothing is quietly deleted" ([zeta-global.org](https://zeta-global.org), read 11 Oct 2026). ZETA also writes that "only a registry can guarantee that one unit is claimed once, because only a registry can see every unit at once". hourcert is a test of how far a public covenant gets toward that without a single operator.
- **Deadlines are in law for trade, too.** CBAM charges importers for embedded emissions and applies default values when the real figure cannot be evidenced (ZETA, same page). Steel, aluminium, cement and fertiliser claims all end up resting on clean power or clean hydrogen upstream.

### Sources: KII and ZETA

stp asked for something aimed at industry, in the spirit of KII and ZETA. Both were used only as sources; hourcert is our own design and is not affiliated with either.

- **KII, the Kaspa Industrial Initiative** ([kaspa-kii.org](https://kaspa-kii.org), [@KaspaKii](https://x.com/KaspaKii)): a Dutch foundation (Stichting Kii Foundation, chaired by Paul van Son, President of Dii Desert Energy) that presents Kaspa to energy, finance and trade. Its site lists three products built and run by "KiiLabs": WarpCore (ISO 20022 payment evidence), Meridian (institutional assets) and KiiWORKS (trade documents, credentials and digital product passports anchored to Kaspa). Its public open-source work is the [Portrait](https://github.com/KaspaKii/Portrait) covenant pattern library (testnet-only, unaudited). Two STP-KAS reviews of KII's public record were the main source here:
  - [STP-KAS/kii-communication-review](https://github.com/STP-KAS/kii-communication-review) (public, 5 Oct 2026): the delivery and communication record. Real: a mainnet covenant on Toccata day, Portrait, two research repos. Not publicly verifiable: the commercial products, named pilots and partners.
  - [STP-KAS/kaspa-kii-analysis](https://github.com/STP-KAS/kaspa-kii-analysis) (private archive since 5 Oct 2026; the public review replaces it): the full claims ledger, the Dii and ZETA links and the timeline against Kaspa's protocol milestones.
- **ZETA** ([zeta-global.org](https://zeta-global.org)): a Dutch foundation launched by Dii in 2023 that drafts standards for zero-emission attribute certificates for hydrogen, ammonia, methanol, e-fuels and power, and plans a registry and an exchange. Its site states that nothing is released for reliance, no certificate has been issued and no registry holds ZETA recognition. Per Dii's September 2026 white paper (summarised in the KII analysis), ZETA began research in June 2026 into a certificate registry pilot with KII; its draft standards keep the core ledger-neutral and use Kaspa as the worked reference profile. The reviews note that ZETA and KII share people. This repository copies none of ZETA's draft documents.

What both point at, and what hourcert takes from them: **the industrial problem is not moving data, it is making a unit of evidence single-use.** Anchoring a hash proves a record existed; it does not stop the same hour being certified twice or claimed twice. That needs state and rules, which is what covenants add.

## Roles and spend paths

Four actors share one covenant id (KIP-20), so every certificate of a registry carries the registry's id and a copy made outside it cannot pass as one.

| Actor | Entry | Who | Rule enforced by the covenant |
| --- | --- | --- | --- |
| `Device` | `issue(hour, wh, meter_sig, issuer_sig, holder)` | meter **and** issuing body | `hour > last_hour`; `0 < wh <= max_wh`; `meter_sig` is the meter's BIP-340 signature over the oneword statement `blake2b(meter_domain ‖ hour ‖ blake2b(registry ‖ device ‖ wh))`; the issuer signs the transaction; successor 0 is the same `Device` with `last_hour = hour` and the same value; successor 1 is a `Cert` for exactly that hour, amount and holder |
| `Device` | `close(sig)` | issuing body | ends the lineage |
| `Cert` | `transfer(sig, new_holder)` | holder | successor is the same `Cert` with the new holder and the same value |
| `Cert` | `split(sig, take, new_holder)` | holder | `0 < take < wh`; successors are `wh - take` for the holder (same value) and `take` for `new_holder`; no Wh created |
| `Cert` | `retire(sig, claim)` | holder | successor is a `Retired` with the same fields plus the 32-byte claim hash (who, what consumption, which reporting period) and the same value |
| `Cert`, `Retired` | `invalidate(sig, reason)` | auditor | successor is a `Void` with the same fields, the claim (if any) and the 32-byte reason hash, same value |
| `Retired` | `archive(sig)` | holder | only after `archive_after` DAA (relative lock); releases the deposit |
| `Void` | `archive(sig)` | auditor | only after `archive_after` DAA; releases the deposit |

There is no keyless path. `Retired` has no `transfer`, `split` or `retire`: once claimed, a certificate can only be voided or archived. `Void` can only be archived.

```
Device --issue--> Device + Cert
Cert --transfer--> Cert --split--> Cert + Cert --retire--> Retired --invalidate--> Void
Cert --invalidate--> Void                         Retired --archive (after window)--> closed
Void --archive (after window)--> closed           Device --close--> closed
```

### Composition with oneword

The meter's reading signature *is* a oneword statement: domain = `meter_domain`, epoch = the hour, body = `blake2b(registry ‖ device ‖ wh)`. If the meter key also backs a [oneword](https://github.com/STP-KAS/oneword) bond with that domain, its promise becomes "one reading per hour, across every registry". Two readings for the same hour, whether with different amounts or the same amount for two registries, are two different bodies for one epoch, and anyone holding both can slash the bond. The reading used for an issuance is public, because it is in the issuance transaction. So double issuance across registries gets a price without a shared database, as long as each registry requires readings in this format under the meter's published domain.

The hourcert covenant does not check that a bond exists or how big it is; it cannot see other outputs. Integrators must check that the meter's bond is live, is a `Bond` and not `Unbonding`, and is large enough (see the oneword README).

### Composition with feetank (not tested)

A [feetank](https://github.com/STP-KAS/feetank) whose `sponsor_cov` is a registry's covenant id could pay the fees of end consumers who retire certificates, without the registry running a signing server. This run did not test it.

## What is enforced and what is not

Enforced on L1 (each rule was tested on chain, see below):

- one certificate per meter-hour within a device lineage: hours only move forward, so a signed reading cannot be used twice;
- issuance needs two parties: a valid reading by the meter key for exactly that hour and amount, plus the issuing body;
- no hour can claim more than the facility's nameplate `max_wh`;
- exactly one holder at a time; only the holder moves, splits or retires; splits conserve Wh;
- retirement is terminal for trading: a retired certificate cannot be moved, split or retired again;
- only the auditor can void, from live or retired, and the voided record keeps hour, amount, holder, claim and reason;
- deposits cannot be skimmed on any path, and archiving waits for the window.

Not enforced, or only convention:

- **The physical world.** The covenant never sees a meter, a plant or a molecule. A tampered meter that signs one consistent false reading per hour is never caught by hourcert or oneword. That is the job of metering standards, calibration and audits, and it is the main trust in the system.
- **Who the keys belong to.** `issuer`, `meter`, `auditor` and holders are public keys. Accreditation of the issuing body, device registration and know-your-customer checks happen off chain.
- **Uniqueness across lineages.** Nothing stops the issuer from creating a second `Device` for the same facility and issuing the same hours again. The oneword bond makes that costly for the meter key (the readings would conflict), but only if the second lineage uses the same meter key and someone publishes the conflicting reading. A registry should publish its device list, and readers should check it.
- **Order of readings.** Hours must go up. A late reading for an earlier hour cannot be issued in the same lineage. Real metering backfills; an integrator would issue in batches after data closes, or open a per-period lineage.
- **What a claim or a reason means.** Both are 32-byte hashes. The text behind them (company, consumption site, reporting year, standard) is a convention, as in oneword.
- **Hourly matching itself.** hourcert records the production hour. Matching it to consumption, deliverability zones, additionality and recognition under RED III, the GHG Protocol or CBAM are rules on top that the covenant does not check.
- **Expiry.** EnergyTag schemes let unclaimed certificates expire (for example after 12 months). hourcert has no expiry; it could be added as an auditor or issuer path after an age.
- **Privacy.** Hour, amount, device id and holder keys are public. Project Origin uses Pedersen commitments to hide volumes ([LF Energy, Project Origin](https://lfenergy.org/project-origin-granular-certificates-from-theory-to-practice/)); hourcert does not.
- **Auditor power.** The auditor can void any live or retired certificate until it is archived. That matches ZETA's model (a failed claim stays visible) and differs from Energy Web Origin, where a claimed certificate can no longer be revoked ([EW-Origin docs](https://energy-web-foundation-origin.readthedocs-hosted.com/en/latest/traceability/)). After `archive_after`, the holder can take the deposit back and the auditor loses that power on chain. The window has to fit the audit cycle (months, not the 30 seconds used here). The history stays in the chain either way.
- **Cost at scale.** Each live certificate is a covenant output holding a deposit (0.8 tKAS in the test, because covenant outputs count double for KIP-9 storage mass). At one certificate per MWh-hour that is a lot of locked value and a lot of UTXOs. Realistic use would certify per day or per batch, with hourly detail inside the record.

## Attack and grief vectors

- **Same hour, two registries.** The core double-issuance case. Covered only through the oneword bond and only if both readings become public; tested on chain (bond slashed with the on-chain reading of 09:00 UTC for registry R1 and a second reading of the same hour for registry R2).
- **Replay of a signed reading** in the same lineage: rejected (tested).
- **Inflating a reading** after the meter signed it: rejected (tested); inflating at the meter: allowed up to `max_wh` and not detectable on chain.
- **Issuer issuing alone, or meter issuing alone:** rejected (tested both ways: forged meter signature, forged issuer signature).
- **Double claim:** a retired certificate cannot be spent through the live certificate's paths (tested).
- **Rogue auditor:** can void honest certificates. It cannot steal them or their deposits; the holder can see the void and the reason on chain. Choose auditors with a bond of their own, or require two auditor keys (not built).
- **Stolen holder key:** the thief can move or retire the certificate. Same as any wallet.
- **Stolen meter key:** the thief can sign readings but cannot issue without the issuer. It can equivocate on purpose and slash the bond, taking the bounty; the beneficiary keeps its share (see oneword).
- **Early archive** to escape a pending invalidation: blocked by the relative lock until `archive_after` (tested).

## Is a covenant the right tool?

For the lifecycle, yes. Anchoring a record's hash (the KiiWORKS and ZETA anchoring approach) proves the record existed at a time; it does not stop the same hour from being certified twice or a certificate from being claimed twice. Smart-contract registries do this on account-based chains: Energy Web Origin mints certificates as ERC-1888 tokens with issue, split, transfer, claim and issuer revocation before claim. Project Origin (Energinet, LF Energy) runs a stateful certificate model with Merkle proofs and was piloted in Denmark with about 600 commercial actors ([LF Energy](https://lfenergy.org/project-origin-granular-certificates-from-theory-to-practice/)). Energinet's granular-certificate protocol prevents double issuance between hourly certificates and monthly Guarantees of Origin by marking metering data in the national DataHub ([Energinet GC scheme protocol](https://energytag.org/wp-content/uploads/2025/09/Energinet_GC-Scheme_protocol.pdf)).

What hourcert adds, as far as we found (web search, 11 Oct 2026):

1. the same lifecycle as UTXO covenants on a proof-of-work chain, with the registry identity carried by the covenant id;
2. **two-party issuance where the meter's signature doubles as a slashable oneword statement**, so cross-registry double issuance is punished without a shared database or a referee. We found no published design that does this on Kaspa or elsewhere;
3. invalidation after retirement that keeps the claim and the reason on the record, as ZETA asks for.

On Kaspa, KII's Portrait library has an `EvidenceLineage` pattern (a monotonic attestation chain), which is close to the `Device` lineage. We found no published energy-certificate covenant on Kaspa (searched the web and the TN10 covenant explorer at [tn10-covenants.kaspa.com](https://tn10-covenants.kaspa.com/), 11 Oct 2026).

No for some uses. If a single trusted registry operator exists and participants are happy with it, a database with an audit log is cheaper. hourcert is for the case ZETA describes: several registries and jurisdictions that do not fully trust each other, and buyers who want to check rather than trust.

## Design choices and rejected alternatives

Before building, six industry ideas were scored from 1 (bad) to 5 (good). For "enforceable" a 5 means the covenant can enforce what the idea needs; for "build risk" a 5 means low risk.

| Idea | Industry | New | Useful | Enforceable on TN10 | Build risk | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| **hourcert** (hourly attribute certificates: two-party issuance per meter-hour, transfer, split, retire, void with reason, oneword-bonded meter) | energy, hydrogen, CBAM | 4 | 5 | 4 | 3 | **built** |
| Custody hand-off chain (each carrier signs receipt, title moves with the cargo, eBL style) | shipping, trade finance | 2 | 4 | 2 | 4 | Electronic bills of lading under MLETR already have platforms, and KII's own "Trusted Trade" demo works this corridor. The covenant cannot see the cargo, so every hand-off is just a signature chain. |
| Cold-chain SLA escrow (carrier is paid unless a bonded sensor attests a breach before a deadline) | logistics, pharma | 3 | 3 | 2 | 3 | The sensor oracle carries all of the trust, and disputes over one reading are not something a covenant settles. The bonded-sensor part is already oneword. |
| Machine-to-machine metering channel (an EV charger draws from a prepaid covenant per signed kWh tick, refund after a timeout) | e-mobility, metering | 2 | 4 | 4 | 3 | A payment channel; ApiPaymentChannel-type covenants are already live on TN10 per the covenant explorer. Close to feetank in shape. |
| Battery passport and warranty claims (state per serial number: made, installed, second life, recycled) | batteries (EU Battery Regulation) | 2 | 4 | 2 | 3 | Mostly data anchoring; KiiWORKS, the Global Battery Alliance and others work on passports. A covenant adds little beyond a hash unless claims move money, and warranty payouts need an assessor anyway. |
| Maintenance milestone escrow (operator pays a contractor in tranches when an inspector signs) | construction, O&M | 1 | 3 | 2 | 4 | Escrow with arbiter exists on TN10, and Portrait lists a FIDIC construction lineage. The inspector is a trusted party; the covenant only routes money. |

hourcert won because its core problem (count a unit once) is a pure state-and-rules problem that a covenant can enforce, it maps to deadlines already in law, and it composes with oneword in a way that is new. It lost a point on build risk because it is the largest contract so far (four actors, multi-output issuance and split).

Inside hourcert:

- **Two signatures to issue.** The meter attests the physics, the issuing body attests the registration. Either alone is refused.
- **Monotonic hours** instead of a set of used hours: a covenant cannot store a growing set, and a strictly increasing cursor makes replays impossible within the lineage at the cost of no backfill.
- **Nameplate cap** at genesis, so a compromised pair of keys cannot mint an unlimited hour.
- **Reading in oneword format,** with registry and device inside the body, so one meter key can serve several registries and still be slashable for selling one hour twice.
- **Separate `Retired` and `Void` actors** instead of flags, so the forbidden paths simply do not exist on those actors.
- **Deposits per certificate,** because a covenant output must hold value. Archiving returns them; the history stays.
- **No parameter changes.** A device whose meter, issuer or cap could change would let issued hours be re-issued. Close it and open a new one instead.

## Throughput and mass

- Scripts: `Device` 937 bytes, `Cert` 1,347, `Retired` 506, `Void` 281.
- Covenant outputs count double in KIP-9 storage mass (plurality 2), so a covenant output needs about four times the value of a plain output for the same storage mass. With 0.8 tKAS certificates and a 1 tKAS device, issuance stays under the 100,000 standard limit; at 0.5 tKAS it does not.
- Measured on TN10 at 100 sompi/gram:

| Path | Compute mass | Storage mass | Fee |
| --- | --- | --- | --- |
| genesis (1 tKAS device, four funding inputs) | 5,443 | 3,080 | 0.0055 tKAS |
| issue (new 0.8 tKAS certificate) | 7,047 | 68,741 to 72,082 | 0.069 to 0.072 tKAS |
| transfer | 4,691 | 23,725 | 0.024 tKAS |
| split (new 0.8 tKAS part) | 5,152 | 77,022 | 0.077 tKAS |
| retire | 4,876 | 13,100 to 13,307 | 0.013 tKAS |
| invalidate (from Cert or Retired) | 3,808 to 4,649 | 11,504 to 12,893 | 0.012 to 0.013 tKAS |
| archive (deposit merged into the fee coin) | 3,035 to 3,260 | 0 | 0.003 tKAS |
| close | 3,691 | 0 | 0.004 tKAS |
| oneword bond genesis (1.5 tKAS) | 2,083 | 53,247 | 0.053 tKAS |
| oneword slash of the meter bond | 3,847 | 17,004 | 0.017 tKAS, paid from the bounty |

Creating a covenant output is the expensive step. Moving or ending one is cheap.

## Developer and integrator guide

**Issuing body (registry operator):**

1. Register the facility off chain (owner, location, technology, nameplate capacity, metering point). Pick `registry` (one id for your registry), `device` (one per metering point), `max_wh` (nameplate × 1 hour) and an `auditor`.
2. Ask the facility's meter operator for its meter public key and its oneword `meter_domain`, and check its bond.
3. Create the `Device` with `genesis`. Publish the covenant id, the device list, the meaning of `claim` and `reason` hashes, and `archive_after` (match your audit and dispute cycle).
4. For each closed hour: receive the meter's signed reading, check it against settlement data, co-sign `issue` to the producer's key.

**Meter operator:**

1. Keep the meter key in the meter or its gateway (HSM). Create a oneword bond with `attester` = meter key and `domain` = `meter_domain`; size it to what one double-sold hour would earn.
2. Sign exactly one reading per hour: `body = blake2b(registry ‖ device ‖ wh as 8-byte little endian)`, `statement = blake2b(meter_domain ‖ hour as 8-byte LE ‖ body)`. `hourcert meter-sign` shows the bytes.
3. Never sign the same hour for a second registry. That is the slashable act.

**Holder (producer, trader, buyer):** keep the certificate key like a wallet key. `transfer` or `split` to sell, `retire` with `claim = blake2b(<your claim text>)` when you report. Publish the claim text next to the txid.

**Verifier (auditor of a claim, buyer, regulator):**

1. Check the certificate output carries the registry's published covenant id and is a `Retired` (for a claim) or `Cert` (for a sale), not `Void`. Covenant-id lookup over RPC is not available yet; use an indexer or follow the lineage from the genesis transaction.
2. Recompute the claim hash from the published text.
3. Read the issuance transaction: it holds the meter's reading signature. Check it against the meter key and keep it. If you ever see another reading by that meter for the same hour, slash its bond.
4. Check the meter's oneword bond is live and big enough.

**Auditor:** `invalidate` with `reason = blake2b(<reason text>)`, publish the text, issue a replacement if your rules call for it. `archive` voided certificates after the window to release deposits.

## Test run on TN10 (11 Oct 2026, 19:32:01 to 19:34:36 CEST)

Deployed by Grok Bot from its own TN10 wallet through a synced local TN10 node. Parameters: registry `hourcert/v1/registry/R1`, device `hourcert/v1/device/FAC-TN10-0001` (a made-up 1 MW facility, `max_wh` 1,000,000), meter domain `hourcert/v1/meter/M1`, `archive_after` 300 DAA (about 30 seconds; a real window needs months), device deposit 1 tKAS, certificate deposits 0.8 tKAS, meter bond 1.5 tKAS with 20 % bounty and a 300 DAA unbonding delay. Issuer, meter, auditor, buyer and forger were throwaway keys made for this run. The Grok Bot TN10 key paid the fees, was the "producer" holder and was the bond beneficiary and slasher, so every tKAS came back except fees. All keys were destroyed after the run. The facility, readings, claims and reasons are made up for the drill; they are not real claims.

| Field | Value |
| --- | --- |
| App | `HourCert`, artifact `44df7267f19824257c2254259bf3c087297083e07e79001dfd6cd3b03c4d8f30` |
| Launch path | `launch::hourcert-v1` |
| Registry covenant | `3163d8e46f112bc6dffb21291a7054bcabf5cb96918d0751f1a9ce12bc1c44a3`, genesis `9eb0028f5b9aba4e9b6651b5e0e41543cc0676babbc0628734323c6cf68f02ee`, closed in `891f0775e8e1e5d7726a078f87700350811dc785905b71b067c070355fc312d4` |
| Meter bond (oneword) | covenant `60689d40483bc61b9b7c53f320f0d78eab88ff2d0d90828adc838827bb0f1977`, genesis `b25675aff2e1518985c9a137adbcb227c58948b14a3d137a670d32306abe109c`, slashed in `510e5aa8c767a4011da1f89a1264ab86ca17dea938025d58d09eff81bb7f06a4` |
| Status | all closed. Deploy your own. |

Every path ran on chain. Each reject case is a valid transaction with exactly one thing changed, and the unchanged version passes. The full log is [results/landed.jsonl](results/landed.jsonl).

**Landed (15):**

1. genesis of the device;
2. issue c1: hour 497697 (11 Oct 2026, 09:00–10:00 UTC), 1,000,000 Wh, to the producer;
3. transfer c1 to the buyer;
4. split c1: 400,000 Wh back to the producer as c3, 600,000 Wh stay with the buyer;
5. retire c1 (buyer) against "buyer B: Scope 2 market-based claim, reporting year 2026, site A";
6. retire c3 (producer) against "producer P: own consumption claim, reporting year 2026";
7. invalidate c1 after retirement ("auditor: meter evidence for this hour failed after retirement; replacement to follow"); the claim stays in the `Void` record;
8. archive c3 after the window;
9. issue c2: hour 497698, 600,000 Wh;
10. invalidate c2 while live ("auditor: meter calibration certificate expired for this hour");
11. archive c1 (voided) after the window;
12. genesis of the meter's oneword bond;
13. slash of the meter bond with the on-chain reading of hour 497697 for registry R1 and a second reading of the same hour and amount for registry `hourcert/v1/registry/R2`: 1.2 tKAS to the beneficiary, 0.283 tKAS to the slasher after the fee;
14. archive c2 after the window;
15. close of the device.

**Rejected by the covenant script on the node, as designed (12):**

- a second certificate for hour 497697 re-using its own signed reading, with valid meter and issuer signatures;
- issue with the reading signed by a key that is not the meter;
- issue co-signed by a key that is not the issuing body;
- issue of 1,000,001 Wh, 1 Wh above the nameplate cap, signed by meter and issuer;
- certificate claiming 500,001 Wh when the meter signed 500,000;
- transfer signed by someone who is not the holder;
- split whose new part carries 1 Wh more than was taken;
- retirement that moves 0.01 tKAS of the deposit to the holder;
- a retired certificate presented as live and transferred (a second claim on the same Wh);
- invalidate signed by someone who is not the auditor;
- archive after the window signed by someone who is not the holder;
- close signed by someone who is not the issuer.

**Rejected by the relative lock, as designed (1):** archive of c3 sent right after its retirement landed ("one of the transaction sequence locks conditions was not met"). Archive merges the deposit into the fee coin, and that coin had moved on by the time the window passed, so the archive that landed was rebuilt rather than re-sent byte for byte.

Rejected transactions that differ from a valid one only in a signature have the same transaction id as the valid one, because Kaspa transaction ids do not cover signature scripts (for example the forged-holder transfer and the real transfer).

**Offline selftest:** `hourcert selftest` runs 29 cases (15 valid, 12 invalid, 2 controls) with public demo keys and made-up coins: 29 passed, 0 failed. The two controls apply the same edits as the replay and amount cases but to legal values, and pass, so the rejections come from the covenant rules and not from the editing.

**Cost:** 0.3813 tKAS in fees for the 15 landed transactions. Nothing stays locked. At most 3.3 tKAS was locked at once (the device, the voided c2 and the meter bond), and all of it came back. The rejected transactions cost nothing.

**Mistakes in the run, owned:** none on chain. Before the run, the selftest used a wrong hour index for 09:00 UTC (493929 instead of 497697); the live run used the right values, and the selftest was corrected afterwards.

Intentions are good; thought process is questionable. STP remains delusional. Si vis pacem, para bellum.
