//! hourcert tool: builds every hourcert spend path for testnet-10 drills.
//!
//! hourcert models hourly energy-attribute certificates: a Device lineage
//! issues one certificate per meter-hour (meter reading + issuer co-signature),
//! certificates are transferred, split, retired against one claim, voided by an
//! auditor, and archived after a challenge window. The meter signs readings in
//! the oneword statement format, so a meter that signs two readings for one
//! hour can be slashed through a oneword bond (also built here).
//!
//! Each command builds ONE transaction (or one deliberately invalid one) and
//! writes `$HC_OUT/<label>.json` with the state to adopt if the node accepts
//! it. Keys are read from mode-600 files named in env vars, never printed.
//!
//! Commands:
//!   genesis <funding-file>...        create the Device (registry R, device D)
//!   bond-genesis                     oneword bond for the meter key, domain = meter_domain
//!   issue <cert> <hour> <wh>         meter + issuer: new certificate to the producer
//!   transfer <cert>                  holder -> the other holder (producer <-> buyer)
//!   split <cert> <take> <new-cert>   holder gives `take` Wh to the other holder
//!   retire <cert> <claim-text>       holder retires against blake2b(claim-text)
//!   invalidate <cert> <reason-text>  auditor voids a Cert or Retired
//!   archive <cert>                   after archive_after DAA: Retired (holder) or Void (auditor)
//!   close                            issuer closes the Device
//!   meter-sign <hour> <wh> <registry-seed>   off-chain reading (prints JSON)
//!   slash-meter <hour> <wh> <other-registry-seed>  slash the meter bond with the
//!                                    on-chain reading of <hour> and a second reading
//!                                    of the same hour for another registry
//!   bad-*                            invalid variants (see `bad`)
//!   selftest                         offline run of all paths with demo keys

use std::fs;
use std::str::FromStr;

use argent::artifact::Artifact;
use argent::build_file;
use argent_runtime::{
    ArtifactValue, CovenantOutput, EntryCall, InputSigScript, TxBuilder, TxContext, args, execute_input_with_covenants, state,
};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::MassCalculator;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionOutpoint, UtxoEntry,
};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde_json::{Value, json};

type R<T> = Result<T, Box<dyn std::error::Error>>;
type St = std::collections::BTreeMap<String, ArtifactValue>;

const LAUNCH_PATH: &str = "launch::hourcert-v1";
const BOND_LAUNCH_PATH: &str = "launch::oneword-v1";
const STORAGE_LIMIT: u64 = 100_000;

struct Coin {
    outpoint: TransactionOutpoint,
    entry: UtxoEntry,
}

struct Ready {
    tx: Transaction,
    entries: Vec<UtxoEntry>,
    storage: u64,
    compute: u64,
    transient: u64,
    fee: u64,
}

// ---------- parameters and states ----------

#[derive(Clone)]
struct DevP {
    issuer: [u8; 32],
    meter: [u8; 32],
    auditor: [u8; 32],
    meter_domain: [u8; 32],
    registry: [u8; 32],
    device: [u8; 32],
    last_hour: i64,
    max_wh: i64,
    archive_after: i64,
}

impl DevP {
    fn state(&self) -> St {
        state! {
            issuer: self.issuer.to_vec(), meter: self.meter.to_vec(), auditor: self.auditor.to_vec(),
            meter_domain: self.meter_domain.to_vec(), registry: self.registry.to_vec(), device: self.device.to_vec(),
            last_hour: self.last_hour, max_wh: self.max_wh, archive_after: self.archive_after
        }
    }
    fn json(&self) -> Value {
        json!({"issuer": hex(&self.issuer), "meter": hex(&self.meter), "auditor": hex(&self.auditor),
            "meterDomain": hex(&self.meter_domain), "registry": hex(&self.registry), "device": hex(&self.device),
            "lastHour": self.last_hour, "maxWh": self.max_wh, "archiveAfter": self.archive_after})
    }
    fn from_json(v: &Value) -> R<Self> {
        Ok(Self {
            issuer: arr32(s(v, "issuer")?)?, meter: arr32(s(v, "meter")?)?, auditor: arr32(s(v, "auditor")?)?,
            meter_domain: arr32(s(v, "meterDomain")?)?, registry: arr32(s(v, "registry")?)?, device: arr32(s(v, "device")?)?,
            last_hour: i(v, "lastHour")?, max_wh: i(v, "maxWh")?, archive_after: i(v, "archiveAfter")?,
        })
    }
}

#[derive(Clone)]
struct CertP {
    auditor: [u8; 32],
    registry: [u8; 32],
    device: [u8; 32],
    hour: i64,
    wh: i64,
    holder: [u8; 32],
    archive_after: i64,
    claim: [u8; 32],
    reason: [u8; 32],
}

impl CertP {
    fn state(&self, actor: &str) -> St {
        let mut st = state! {
            auditor: self.auditor.to_vec(), registry: self.registry.to_vec(), device: self.device.to_vec(),
            hour: self.hour, wh: self.wh, holder: self.holder.to_vec(), archive_after: self.archive_after
        };
        if actor == "Retired" || actor == "Void" {
            st.extend(state! { claim: self.claim.to_vec() });
        }
        if actor == "Void" {
            st.extend(state! { reason: self.reason.to_vec() });
        }
        st
    }
    fn json(&self) -> Value {
        json!({"auditor": hex(&self.auditor), "registry": hex(&self.registry), "device": hex(&self.device),
            "hour": self.hour, "wh": self.wh, "holder": hex(&self.holder), "archiveAfter": self.archive_after,
            "claim": hex(&self.claim), "reason": hex(&self.reason)})
    }
    fn from_json(v: &Value) -> R<Self> {
        Ok(Self {
            auditor: arr32(s(v, "auditor")?)?, registry: arr32(s(v, "registry")?)?, device: arr32(s(v, "device")?)?,
            hour: i(v, "hour")?, wh: i(v, "wh")?, holder: arr32(s(v, "holder")?)?, archive_after: i(v, "archiveAfter")?,
            claim: arr32(s(v, "claim")?)?, reason: arr32(s(v, "reason")?)?,
        })
    }
}

#[derive(Clone)]
struct BondP {
    attester: [u8; 32],
    domain: [u8; 32],
    beneficiary: [u8; 32],
    bounty_pct: i64,
    unbond_delay: i64,
    min_topup: i64,
}

impl BondP {
    fn state(&self) -> St {
        state! {
            attester: self.attester.to_vec(), domain: self.domain.to_vec(), beneficiary: self.beneficiary.to_vec(),
            bounty_pct: self.bounty_pct, unbond_delay: self.unbond_delay, min_topup: self.min_topup
        }
    }
    fn json(&self) -> Value {
        json!({"attester": hex(&self.attester), "domain": hex(&self.domain), "beneficiary": hex(&self.beneficiary),
               "bountyPct": self.bounty_pct, "unbondDelay": self.unbond_delay, "minTopup": self.min_topup})
    }
    fn from_json(v: &Value) -> R<Self> {
        Ok(Self {
            attester: arr32(s(v, "attester")?)?, domain: arr32(s(v, "domain")?)?, beneficiary: arr32(s(v, "beneficiary")?)?,
            bounty_pct: i(v, "bountyPct")?, unbond_delay: i(v, "unbondDelay")?, min_topup: i(v, "minTopup")?,
        })
    }
}

struct Keys {
    payer: Keypair,
    issuer: Keypair,
    meter: Keypair,
    auditor: Keypair,
    buyer: Keypair,
    forger: Keypair,
}

struct Ctx {
    k: Keys,
    payer_pub: [u8; 32],
    out: String,
    rate: u64,
    state: Value,
}

fn pubk(k: &Keypair) -> [u8; 32] {
    k.x_only_public_key().0.serialize()
}

fn main() -> R<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cmd = argv.first().cloned().ok_or("usage: hourcert <cmd> [args]")?;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let art = build_file(root.join("contracts/hourcert.ag"), root.join("build/hourcert"))?;
    let bond_art = build_file(root.join("contracts/oneword.ag"), root.join("build/oneword"))?;
    if cmd == "info" {
        for a in [&art, &bond_art] {
            println!("app {} artifact {}", a.app, a.id);
            for (name, contract) in &a.sil_abi.contracts {
                println!("  {name}: {} bytes", contract.compiled.bytecode.len());
            }
        }
        return Ok(());
    }
    if cmd == "selftest" {
        return selftest(&art, &bond_art);
    }
    let keys = Keys {
        payer: load_key("HC_PAYER_KEY", Some("HC_PAYER_ADDRESS"))?.0,
        issuer: load_key("HC_ISSUER_KEY", None)?.0,
        meter: load_key("HC_METER_KEY", None)?.0,
        auditor: load_key("HC_AUDITOR_KEY", None)?.0,
        buyer: load_key("HC_BUYER_KEY", None)?.0,
        forger: load_key("HC_FORGER_KEY", None)?.0,
    };
    if cmd == "meter-sign" {
        let hour: u64 = argv.get(1).ok_or("hour")?.parse()?;
        let wh: u64 = argv.get(2).ok_or("wh")?.parse()?;
        let reg = blake2b32(argv.get(3).ok_or("registry seed")?.as_bytes());
        let st: Value = serde_json::from_str(&fs::read_to_string(std::env::var("HC_STATE")?)?)?;
        let d = DevP::from_json(&st["device"]["params"])?;
        let (body, digest, sig) = meter_reading(&keys.meter, &d.meter_domain, hour, &reg, &d.device, wh);
        println!("{}", json!({"hour": hour, "wh": wh, "registry": hex(&reg), "device": hex(&d.device), "body": hex(&body),
            "statement": hex(&digest), "sig": hex(&sig), "meter": hex(&pubk(&keys.meter))}));
        return Ok(());
    }
    let payer_pub = pubk(&keys.payer);
    let out = std::env::var("HC_OUT").map_err(|_| "HC_OUT")?;
    fs::create_dir_all(&out)?;
    let rate = std::env::var("HC_RATE").ok().map(|v| v.parse()).transpose()?.unwrap_or(100u64);
    let state_path = std::env::var("HC_STATE").map_err(|_| "HC_STATE")?;
    let state: Value = serde_json::from_str(&fs::read_to_string(&state_path)?)?;
    let ctx = Ctx { k: keys, payer_pub, out, rate, state };
    let b = TxBuilder::new(&art)?;
    let bb = TxBuilder::new(&bond_art)?;
    let label = std::env::var("HC_LABEL").unwrap_or_else(|_| cmd.clone());
    run_cmd(&ctx, &b, &bb, &label, &cmd, &argv)
}

fn run_cmd(ctx: &Ctx, b: &TxBuilder<'_>, bb: &TxBuilder<'_>, label: &str, cmd: &str, argv: &[String]) -> R<()> {
    let arg = |k: usize| argv.get(k).cloned().ok_or_else(|| format!("{cmd}: missing argument {k}"));
    match cmd {
        "genesis" => genesis(ctx, b, label, &argv[1..]),
        "bond-genesis" => bond_genesis(ctx, bb, label),
        "issue" => {
            let (name, hour, wh): (String, i64, i64) = (arg(1)?, arg(2)?.parse()?, arg(3)?.parse()?);
            let ready = issue(ctx, b, hour, wh, &Issue::default())?;
            let mut next = ctx.state.clone();
            let mut d = DevP::from_json(&next["device"]["params"])?;
            d.last_hour = hour;
            next["device"]["params"] = d.json();
            next["device"]["utxo"] = utxo_json(&ready.tx, 0);
            let c = CertP { auditor: d.auditor, registry: d.registry, device: d.device, hour, wh, holder: ctx.payer_pub,
                archive_after: d.archive_after, claim: [0; 32], reason: [0; 32] };
            next["certs"][&name] = json!({"actor": "Cert", "state": c.json(), "holderRole": "producer", "utxo": utxo_json(&ready.tx, 1)});
            next["payer"] = coin_json(&ready.tx, 2);
            emit(ctx, label, &format!("issue {name}: hour {hour}, {wh} Wh"), &ready, next)
        }
        "transfer" => {
            let name = arg(1)?;
            let ready = transfer(ctx, b, &name, None)?;
            let (_, mut c, _, role) = cert_coin(ctx, &name)?;
            let new_role = other_role(&role);
            c.holder = pubk(role_key(ctx, new_role));
            let mut next = ctx.state.clone();
            next["certs"][&name]["state"] = c.json();
            next["certs"][&name]["holderRole"] = json!(new_role);
            next["certs"][&name]["utxo"] = utxo_json(&ready.tx, 0);
            next["payer"] = coin_json(&ready.tx, 1);
            emit(ctx, label, &format!("transfer {name}: {role} -> {new_role}"), &ready, next)
        }
        "split" => {
            let (name, take, new_name): (String, i64, String) = (arg(1)?, arg(2)?.parse()?, arg(3)?);
            let ready = split(ctx, b, &name, take, 0)?;
            let (_, c, _, role) = cert_coin(ctx, &name)?;
            let new_role = other_role(&role);
            let mut kept = c.clone();
            kept.wh -= take;
            let mut given = c.clone();
            given.wh = take;
            given.holder = pubk(role_key(ctx, new_role));
            let mut next = ctx.state.clone();
            next["certs"][&name]["state"] = kept.json();
            next["certs"][&name]["utxo"] = utxo_json(&ready.tx, 0);
            next["certs"][&new_name] = json!({"actor": "Cert", "state": given.json(), "holderRole": new_role, "utxo": utxo_json(&ready.tx, 1)});
            next["payer"] = coin_json(&ready.tx, 2);
            emit(ctx, label, &format!("split {name}: {take} Wh to {new_role} as {new_name}"), &ready, next)
        }
        "retire" => {
            let (name, claim) = (arg(1)?, arg(2)?);
            let ready = retire(ctx, b, &name, &blake2b32(claim.as_bytes()), None, 0)?;
            let (_, mut c, _, _) = cert_coin(ctx, &name)?;
            c.claim = blake2b32(claim.as_bytes());
            let mut next = ctx.state.clone();
            next["certs"][&name]["state"] = c.json();
            next["certs"][&name]["actor"] = json!("Retired");
            next["certs"][&name]["claimText"] = json!(claim);
            next["certs"][&name]["utxo"] = utxo_json(&ready.tx, 0);
            next["payer"] = coin_json(&ready.tx, 1);
            emit(ctx, label, &format!("retire {name} against claim \"{claim}\""), &ready, next)
        }
        "invalidate" => {
            let (name, reason) = (arg(1)?, arg(2)?);
            let ready = invalidate(ctx, b, &name, &blake2b32(reason.as_bytes()), None)?;
            let (_, mut c, actor, _) = cert_coin(ctx, &name)?;
            c.reason = blake2b32(reason.as_bytes());
            let mut next = ctx.state.clone();
            next["certs"][&name]["state"] = c.json();
            next["certs"][&name]["actor"] = json!("Void");
            next["certs"][&name]["reasonText"] = json!(reason);
            next["certs"][&name]["utxo"] = utxo_json(&ready.tx, 0);
            next["payer"] = coin_json(&ready.tx, 1);
            emit(ctx, label, &format!("invalidate {name} ({actor} -> Void): \"{reason}\""), &ready, next)
        }
        "archive" => {
            let name = arg(1)?;
            let ready = archive(ctx, b, &name, None)?;
            let (_, _, actor, _) = cert_coin(ctx, &name)?;
            let mut next = ctx.state.clone();
            next["certs"][&name]["actor"] = json!(format!("archived-{}", actor.to_lowercase()));
            next["certs"][&name]["archivedIn"] = json!(ready.tx.id().to_string());
            next["payer"] = coin_json(&ready.tx, 0);
            emit(ctx, label, &format!("archive {name} ({actor}) after the window"), &ready, next)
        }
        "close" => {
            let ready = close(ctx, b, None)?;
            let mut next = ctx.state.clone();
            next["device"]["actor"] = json!("closed");
            next["device"]["closedIn"] = json!(ready.tx.id().to_string());
            next["payer"] = coin_json(&ready.tx, 0);
            emit(ctx, label, "issuer closes the device lineage", &ready, next)
        }
        "slash-meter" => {
            let (hour, wh, other): (u64, u64, String) = (arg(1)?.parse()?, arg(2)?.parse()?, arg(3)?);
            let d = DevP::from_json(&ctx.state["device"]["params"])?;
            let (ba, _, sa) = meter_reading(&ctx.k.meter, &d.meter_domain, hour, &d.registry, &d.device, wh);
            let (bo, _, so) = meter_reading(&ctx.k.meter, &d.meter_domain, hour, &blake2b32(other.as_bytes()), &d.device, wh);
            let ready = slash(ctx, bb, hour, &ba, &sa, &bo, &so)?;
            let mut next = ctx.state.clone();
            next["bond"]["actor"] = json!("slashed");
            next["bond"]["slash"] = json!({"hour": hour, "wh": wh, "registryA": hex(&d.registry), "registryB": hex(&blake2b32(other.as_bytes())), "otherSeed": other});
            push_payout(&mut next, &ready.tx, 0)?;
            push_payout(&mut next, &ready.tx, 1)?;
            emit(ctx, label, &format!("slash the meter's oneword bond: hour {hour} signed for two registries"), &ready, next)
        }
        c if c.starts_with("bad-") || c.starts_with("ctl-") => bad(ctx, b, label, c, argv),
        _ => Err(format!("unknown command {cmd}").into()),
    }
}

// ---------- statements ----------

fn blake2b32(data: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new().hash_length(32).to_state().update(data).finalize();
    h.as_bytes().try_into().expect("32")
}

/// body = blake2b(registry || device || wh LE8); statement = blake2b(domain || hour LE8 || body) (oneword format).
fn meter_reading(key: &Keypair, domain: &[u8; 32], hour: u64, registry: &[u8; 32], device: &[u8; 32], wh: u64) -> ([u8; 32], [u8; 32], Vec<u8>) {
    let mut b = Vec::with_capacity(72);
    b.extend_from_slice(registry);
    b.extend_from_slice(device);
    b.extend_from_slice(&wh.to_le_bytes());
    let body = blake2b32(&b);
    let mut m = Vec::with_capacity(72);
    m.extend_from_slice(domain);
    m.extend_from_slice(&hour.to_le_bytes());
    m.extend_from_slice(&body);
    let digest = blake2b32(&m);
    // Deterministic (no aux randomness) so a drill can rebuild the same reading byte for byte.
    let sig = secp256k1::SECP256K1.sign_schnorr_no_aux_rand(&Message::from_digest(digest), key).as_ref().to_vec();
    (body, digest, sig)
}

// ---------- coins from state ----------

fn payer_coin(ctx: &Ctx) -> R<Coin> {
    let p = &ctx.state["payer"];
    Ok(Coin {
        outpoint: TransactionOutpoint::new(TransactionId::from_str(s(p, "txid")?)?, u(p, "index")? as u32),
        entry: UtxoEntry::new(u(p, "value")?, p2pk(&ctx.payer_pub), 0, false, None),
    })
}

fn cov_out(cov: &str, t: &Value) -> R<CovenantOutput> {
    let cov = Hash::from_str(cov)?;
    let spk = ScriptPublicKey::from_vec(0, hex_decode(s(t, "script")?)?);
    let value = u(t, "value")?;
    Ok(CovenantOutput {
        index: u(t, "index")? as u32,
        covenant_id: cov,
        outpoint: TransactionOutpoint::new(TransactionId::from_str(s(t, "txid")?)?, u(t, "index")? as u32),
        utxo: UtxoEntry::new(value, spk, 0, false, Some(cov)),
    })
}

fn device_coin(ctx: &Ctx) -> R<(CovenantOutput, DevP)> {
    let d = &ctx.state["device"];
    if s(d, "actor")? != "Device" {
        return Err("device is not live".into());
    }
    Ok((cov_out(s(&ctx.state, "cov")?, &d["utxo"])?, DevP::from_json(&d["params"])?))
}

fn cert_coin(ctx: &Ctx, name: &str) -> R<(CovenantOutput, CertP, String, String)> {
    let c = ctx.state.get("certs").and_then(|v| v.get(name)).ok_or_else(|| format!("no cert {name}"))?;
    Ok((cov_out(s(&ctx.state, "cov")?, &c["utxo"])?, CertP::from_json(&c["state"])?, s(c, "actor")?.to_string(), s(c, "holderRole")?.to_string()))
}

fn other_role(role: &str) -> &'static str {
    if role == "producer" { "buyer" } else { "producer" }
}

fn role_key<'a>(ctx: &'a Ctx, role: &str) -> &'a Keypair {
    if role == "producer" { &ctx.k.payer } else { &ctx.k.buyer }
}

fn payer_input(ctx: &Ctx, coin: &Coin) -> (TransactionOutpoint, UtxoEntry, InputSigScript<'static>) {
    let payer = ctx.k.payer;
    (coin.outpoint, coin.entry.clone(), InputSigScript::with_transaction(move |tx, index| p2pk_signature(&sign(tx, index, &payer))))
}

fn cert_value() -> R<u64> {
    Ok(env_i("HC_CERT_VALUE", 80_000_000)? as u64)
}

// ---------- valid paths ----------

fn genesis(ctx: &Ctx, b: &TxBuilder<'_>, label: &str, funding: &[String]) -> R<()> {
    if funding.is_empty() {
        return Err("genesis needs funding files".into());
    }
    let coins: Vec<Coin> = funding.iter().map(|f| load_funding(f, &ctx.payer_pub)).collect::<R<_>>()?;
    let seed = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let d = DevP {
        issuer: pubk(&ctx.k.issuer),
        meter: pubk(&ctx.k.meter),
        auditor: pubk(&ctx.k.auditor),
        meter_domain: blake2b32(seed("HC_METER_DOMAIN_SEED", "hourcert/v1/meter/M1").as_bytes()),
        registry: blake2b32(seed("HC_REGISTRY_SEED", "hourcert/v1/registry/R1").as_bytes()),
        device: blake2b32(seed("HC_DEVICE_SEED", "hourcert/v1/device/FAC-TN10-0001").as_bytes()),
        last_hour: env_i("HC_START_HOUR", 0)?,
        max_wh: env_i("HC_MAX_WH", 1_000_000)?,
        archive_after: env_i("HC_ARCHIVE_AFTER", 300)?,
    };
    let value = env_i("HC_DEVICE_VALUE", 100_000_000)? as u64;
    let total: u64 = coins.iter().map(|c| c.entry.amount).sum();
    let ready = fit_fee(ctx.rate, |fee| {
        let change = total.checked_sub(value).and_then(|v| v.checked_sub(fee)).ok_or("change")?;
        let mut t = TxContext::new();
        for c in &coins {
            let (o, e, sig) = payer_input(ctx, c);
            t = t.input(o, e, sig, 0);
        }
        let tx = b.build(&t.actor_genesis_output(0, LAUNCH_PATH, "Device", d.state(), value).output(p2pk(&ctx.payer_pub), None, change))?;
        commit(tx, coins.iter().map(|c| c.entry.clone()).collect())
    })?;
    let cov = CovenantOutput::from_tx(&ready.tx, 0)?;
    let mut next = ctx.state.clone();
    next["payer"] = coin_json(&ready.tx, 1);
    next["cov"] = json!(cov.covenant_id.to_string());
    next["genesis"] = json!(ready.tx.id().to_string());
    next["device"] = json!({"actor": "Device", "params": d.json(), "utxo": utxo_json(&ready.tx, 0),
        "seeds": {"meterDomain": seed("HC_METER_DOMAIN_SEED", "hourcert/v1/meter/M1"), "registry": seed("HC_REGISTRY_SEED", "hourcert/v1/registry/R1"),
                  "device": seed("HC_DEVICE_SEED", "hourcert/v1/device/FAC-TN10-0001")}});
    next["certs"] = json!({});
    emit(ctx, label, "genesis: Device lineage", &ready, next)
}

fn bond_genesis(ctx: &Ctx, bb: &TxBuilder<'_>, label: &str) -> R<()> {
    let d = DevP::from_json(&ctx.state["device"]["params"])?;
    let p = BondP {
        attester: d.meter,
        domain: d.meter_domain,
        beneficiary: ctx.payer_pub,
        bounty_pct: env_i("HC_BOUNTY", 20)?,
        unbond_delay: env_i("HC_UNBOND", 300)?,
        min_topup: env_i("HC_MIN_TOPUP", 20_000_000)?,
    };
    let value = env_i("HC_BOND_VALUE", 150_000_000)? as u64;
    let coin = payer_coin(ctx)?;
    let ready = fit_fee(ctx.rate, |fee| {
        let change = coin.entry.amount.checked_sub(value).and_then(|v| v.checked_sub(fee)).ok_or("change")?;
        let (o, e, sig) = payer_input(ctx, &coin);
        let tx = bb.build(&TxContext::new().input(o, e, sig, 0)
            .actor_genesis_output(0, BOND_LAUNCH_PATH, "Bond", p.state(), value)
            .output(p2pk(&ctx.payer_pub), None, change))?;
        commit(tx, vec![coin.entry.clone()])
    })?;
    let cov = CovenantOutput::from_tx(&ready.tx, 0)?;
    let mut next = ctx.state.clone();
    next["payer"] = coin_json(&ready.tx, 1);
    next["bond"] = json!({"cov": cov.covenant_id.to_string(), "actor": "Bond", "params": p.json(), "utxo": utxo_json(&ready.tx, 0), "genesis": ready.tx.id().to_string()});
    emit(ctx, label, "genesis: oneword bond on the meter key (domain = meter_domain)", &ready, next)
}

#[derive(Default)]
struct Issue {
    meter: Option<Keypair>,
    issuer: Option<Keypair>,
    signed_wh: Option<i64>,
}

fn issue(ctx: &Ctx, b: &TxBuilder<'_>, hour: i64, wh: i64, o: &Issue) -> R<Ready> {
    let (dev, d) = device_coin(ctx)?;
    let coin = payer_coin(ctx)?;
    let meter = o.meter.unwrap_or(ctx.k.meter);
    let issuer = o.issuer.unwrap_or(ctx.k.issuer);
    let signed = o.signed_wh.unwrap_or(wh);
    let (_, _, msig) = meter_reading(&meter, &d.meter_domain, hour as u64, &d.registry, &d.device, signed as u64);
    let mut nd = d.clone();
    nd.last_hour = hour;
    let c = CertP { auditor: d.auditor, registry: d.registry, device: d.device, hour, wh, holder: ctx.payer_pub,
        archive_after: d.archive_after, claim: [0; 32], reason: [0; 32] };
    let cv = cert_value()?;
    let holder = ctx.payer_pub.to_vec();
    fit_fee(ctx.rate, |fee| {
        let change = coin.entry.amount.checked_sub(cv).and_then(|v| v.checked_sub(fee)).ok_or("change")?;
        let (hl, wl, ms, hd) = ((hour as u64).to_le_bytes().to_vec(), (wh as u64).to_le_bytes().to_vec(), msig.clone(), holder.clone());
        let call = EntryCall::new("issue").args_with(move |tx, index| args!(hl.clone(), wl.clone(), ms.clone(), sign(tx, index, &issuer), hd.clone()));
        let (po, pe, ps) = payer_input(ctx, &coin);
        let tx = b.build(&TxContext::new()
            .actor_input("Device", d.state(), call, dev.outpoint, dev.utxo.clone(), 0)
            .input(po, pe, ps, 0)
            .actor_output("Device", nd.state(), CovenantBinding::new(0, dev.covenant_id), dev.utxo.amount)
            .actor_output("Cert", c.state("Cert"), CovenantBinding::new(0, dev.covenant_id), cv)
            .output(p2pk(&ctx.payer_pub), None, change))?;
        commit(tx, vec![dev.utxo.clone(), coin.entry.clone()])
    })
}

fn transfer(ctx: &Ctx, b: &TxBuilder<'_>, name: &str, signer: Option<Keypair>) -> R<Ready> {
    let (cert, c, actor, role) = cert_coin(ctx, name)?;
    if actor != "Cert" {
        return Err(format!("transfer needs a live Cert, {name} is {actor}").into());
    }
    let key = signer.unwrap_or(*role_key(ctx, &role));
    let new_holder = pubk(role_key(ctx, other_role(&role)));
    let mut moved = c.clone();
    moved.holder = new_holder;
    let coin = payer_coin(ctx)?;
    fit_fee(ctx.rate, |fee| {
        let change = coin.entry.amount.checked_sub(fee).ok_or("change")?;
        let nh = new_holder.to_vec();
        let call = EntryCall::new("transfer").args_with(move |tx, index| args!(sign(tx, index, &key), nh.clone()));
        let (po, pe, ps) = payer_input(ctx, &coin);
        let tx = b.build(&TxContext::new()
            .actor_input("Cert", c.state("Cert"), call, cert.outpoint, cert.utxo.clone(), 0)
            .input(po, pe, ps, 0)
            .actor_output("Cert", moved.state("Cert"), CovenantBinding::new(0, cert.covenant_id), cert.utxo.amount)
            .output(p2pk(&ctx.payer_pub), None, change))?;
        commit(tx, vec![cert.utxo.clone(), coin.entry.clone()])
    })
}

/// `inflate` adds Wh to the given part's output state (0 for the valid path).
fn split(ctx: &Ctx, b: &TxBuilder<'_>, name: &str, take: i64, inflate: i64) -> R<Ready> {
    let (cert, c, actor, role) = cert_coin(ctx, name)?;
    if actor != "Cert" {
        return Err(format!("split needs a live Cert, {name} is {actor}").into());
    }
    let key = *role_key(ctx, &role);
    let new_holder = pubk(role_key(ctx, other_role(&role)));
    let mut kept = c.clone();
    kept.wh -= take;
    let mut given = c.clone();
    given.wh = take + inflate;
    given.holder = new_holder;
    let coin = payer_coin(ctx)?;
    let cv = cert_value()?;
    fit_fee(ctx.rate, |fee| {
        let change = coin.entry.amount.checked_sub(cv).and_then(|v| v.checked_sub(fee)).ok_or("change")?;
        let nh = new_holder.to_vec();
        let call = EntryCall::new("split").args_with(move |tx, index| args!(sign(tx, index, &key), take, nh.clone()));
        let (po, pe, ps) = payer_input(ctx, &coin);
        let tx = b.build(&TxContext::new()
            .actor_input("Cert", c.state("Cert"), call, cert.outpoint, cert.utxo.clone(), 0)
            .input(po, pe, ps, 0)
            .actor_output("Cert", kept.state("Cert"), CovenantBinding::new(0, cert.covenant_id), cert.utxo.amount)
            .actor_output("Cert", given.state("Cert"), CovenantBinding::new(0, cert.covenant_id), cv)
            .output(p2pk(&ctx.payer_pub), None, change))?;
        commit(tx, vec![cert.utxo.clone(), coin.entry.clone()])
    })
}

/// `skim` sompi are moved from the certificate output to the payer's change (0 for the valid path).
fn retire(ctx: &Ctx, b: &TxBuilder<'_>, name: &str, claim: &[u8; 32], signer: Option<Keypair>, skim: u64) -> R<Ready> {
    let (cert, c, actor, role) = cert_coin(ctx, name)?;
    if actor != "Cert" {
        return Err(format!("retire needs a live Cert, {name} is {actor}").into());
    }
    let key = signer.unwrap_or(*role_key(ctx, &role));
    let mut done = c.clone();
    done.claim = *claim;
    let coin = payer_coin(ctx)?;
    let cl = claim.to_vec();
    fit_fee(ctx.rate, |fee| {
        let change = (coin.entry.amount + skim).checked_sub(fee).ok_or("change")?;
        let cl = cl.clone();
        let call = EntryCall::new("retire").args_with(move |tx, index| args!(sign(tx, index, &key), cl.clone()));
        let (po, pe, ps) = payer_input(ctx, &coin);
        let tx = b.build(&TxContext::new()
            .actor_input("Cert", c.state("Cert"), call, cert.outpoint, cert.utxo.clone(), 0)
            .input(po, pe, ps, 0)
            .actor_output("Retired", done.state("Retired"), CovenantBinding::new(0, cert.covenant_id), cert.utxo.amount - skim)
            .output(p2pk(&ctx.payer_pub), None, change))?;
        commit(tx, vec![cert.utxo.clone(), coin.entry.clone()])
    })
}

fn invalidate(ctx: &Ctx, b: &TxBuilder<'_>, name: &str, reason: &[u8; 32], signer: Option<Keypair>) -> R<Ready> {
    let (cert, c, actor, _) = cert_coin(ctx, name)?;
    if actor != "Cert" && actor != "Retired" {
        return Err(format!("invalidate needs a Cert or Retired, {name} is {actor}").into());
    }
    let key = signer.unwrap_or(ctx.k.auditor);
    let mut voided = c.clone();
    voided.reason = *reason;
    let coin = payer_coin(ctx)?;
    let rs = reason.to_vec();
    fit_fee(ctx.rate, |fee| {
        let change = coin.entry.amount.checked_sub(fee).ok_or("change")?;
        let rs = rs.clone();
        let call = EntryCall::new("invalidate").args_with(move |tx, index| args!(sign(tx, index, &key), rs.clone()));
        let (po, pe, ps) = payer_input(ctx, &coin);
        let tx = b.build(&TxContext::new()
            .actor_input(actor.as_str(), c.state(&actor), call, cert.outpoint, cert.utxo.clone(), 0)
            .input(po, pe, ps, 0)
            .actor_output("Void", voided.state("Void"), CovenantBinding::new(0, cert.covenant_id), cert.utxo.amount)
            .output(p2pk(&ctx.payer_pub), None, change))?;
        commit(tx, vec![cert.utxo.clone(), coin.entry.clone()])
    })
}

fn archive(ctx: &Ctx, b: &TxBuilder<'_>, name: &str, signer: Option<Keypair>) -> R<Ready> {
    let (cert, c, actor, role) = cert_coin(ctx, name)?;
    let default = match actor.as_str() {
        "Retired" => *role_key(ctx, &role),
        "Void" => ctx.k.auditor,
        _ => return Err(format!("archive needs a Retired or Void, {name} is {actor}").into()),
    };
    let key = signer.unwrap_or(default);
    let coin = payer_coin(ctx)?;
    // The deposit is merged into the payer coin (one output, so storage mass stays near zero).
    fit_fee(ctx.rate, |fee| {
        let call = EntryCall::new("archive").args_with(move |tx, index| args!(sign(tx, index, &key)));
        let (po, pe, ps) = payer_input(ctx, &coin);
        let tx = b.build(&TxContext::new()
            .actor_input(actor.as_str(), c.state(&actor), call, cert.outpoint, cert.utxo.clone(), c.archive_after as u64)
            .input(po, pe, ps, 0)
            .output(p2pk(&ctx.payer_pub), None, (cert.utxo.amount + coin.entry.amount).checked_sub(fee).ok_or("fee")?))?;
        commit(tx, vec![cert.utxo.clone(), coin.entry.clone()])
    })
}

fn close(ctx: &Ctx, b: &TxBuilder<'_>, signer: Option<Keypair>) -> R<Ready> {
    let (dev, d) = device_coin(ctx)?;
    let key = signer.unwrap_or(ctx.k.issuer);
    let coin = payer_coin(ctx)?;
    fit_fee(ctx.rate, |fee| {
        let call = EntryCall::new("close").args_with(move |tx, index| args!(sign(tx, index, &key)));
        let (po, pe, ps) = payer_input(ctx, &coin);
        let tx = b.build(&TxContext::new()
            .actor_input("Device", d.state(), call, dev.outpoint, dev.utxo.clone(), 0)
            .input(po, pe, ps, 0)
            .output(p2pk(&ctx.payer_pub), None, (dev.utxo.amount + coin.entry.amount).checked_sub(fee).ok_or("fee")?))?;
        commit(tx, vec![dev.utxo.clone(), coin.entry.clone()])
    })
}

/// oneword slash of the meter bond: output 0 pays the beneficiary bond - bounty, output 1 the slasher.
fn slash(ctx: &Ctx, bb: &TxBuilder<'_>, epoch: u64, body_a: &[u8; 32], sig_a: &[u8], body_b: &[u8; 32], sig_b: &[u8]) -> R<Ready> {
    let e = &ctx.state["bond"];
    if s(e, "actor")? != "Bond" {
        return Err("meter bond is not live".into());
    }
    let bond = cov_out(s(e, "cov")?, &e["utxo"])?;
    let p = BondP::from_json(&e["params"])?;
    let bounty = bond.utxo.amount * p.bounty_pct as u64 / 100;
    let (ba, sa, bb2, sb) = (body_a.to_vec(), sig_a.to_vec(), body_b.to_vec(), sig_b.to_vec());
    fit_fee(ctx.rate, |fee| {
        let call = EntryCall::new("slash").args(args!(epoch.to_le_bytes().to_vec(), ba.clone(), sa.clone(), bb2.clone(), sb.clone()));
        let tx = bb.build(&TxContext::new()
            .actor_input("Bond", p.state(), call, bond.outpoint, bond.utxo.clone(), 0)
            .output(p2pk(&p.beneficiary), None, bond.utxo.amount - bounty)
            .output(p2pk(&ctx.payer_pub), None, bounty.checked_sub(fee).ok_or("bounty below fee")?))?;
        commit(tx, vec![bond.utxo.clone()])
    })
}

// ---------- invalid variants (built valid, then exactly one thing changed) ----------

/// The scriptPubKey an actor output with this state would have (via a throwaway genesis build).
fn script_for(ctx: &Ctx, b: &TxBuilder<'_>, actor: &str, st: St) -> R<ScriptPublicKey> {
    let coin = payer_coin(ctx)?;
    let (po, pe, ps) = payer_input(ctx, &coin);
    let tx = b.build(&TxContext::new().input(po, pe, ps, 0)
        .actor_genesis_output(0, LAUNCH_PATH, actor, st, 1_000)
        .output(p2pk(&ctx.payer_pub), None, coin.entry.amount - 1_000))?;
    Ok(tx.outputs[0].script_public_key.clone())
}

fn bad(ctx: &Ctx, b: &TxBuilder<'_>, label: &str, cmd: &str, argv: &[String]) -> R<()> {
    let forger = ctx.k.forger;
    let arg = |k: usize| argv.get(k).cloned().ok_or_else(|| format!("{cmd}: missing argument {k}"));
    let d = DevP::from_json(&ctx.state["device"]["params"])?;
    let next_hour = d.last_hour + 1;
    let cert_state = |hour: i64, wh: i64| CertP { auditor: d.auditor, registry: d.registry, device: d.device, hour, wh,
        holder: ctx.payer_pub, archive_after: d.archive_after, claim: [0; 32], reason: [0; 32] };
    let msig = |hour: i64, wh: i64| meter_reading(&ctx.k.meter, &d.meter_domain, hour as u64, &d.registry, &d.device, wh as u64).2;
    match cmd {
        // Re-use the exact reading of the last issued hour (meter and issuer both sign) to issue it again.
        "bad-replay" => {
            let wh = env_i("HC_WH", 1_000_000)?;
            let r = issue(ctx, b, next_hour, wh, &Issue::default())?;
            let mut tx = r.tx.clone();
            let script = &mut tx.inputs[0].signature_script;
            replace_once(script, &(next_hour as u64).to_le_bytes(), &(d.last_hour as u64).to_le_bytes())?;
            replace_once(script, &msig(next_hour, wh), &msig(d.last_hour, wh))?;
            let mut same = d.clone();
            same.last_hour = d.last_hour;
            tx.outputs[0].script_public_key = script_for(ctx, b, "Device", same.state())?;
            tx.outputs[1].script_public_key = script_for(ctx, b, "Cert", cert_state(d.last_hour, wh).state("Cert"))?;
            resign_actor(&mut tx, &r.entries, 0, &ctx.k.issuer)?;
            resign_p2pk(&mut tx, &r.entries, 1, &ctx.k.payer)?;
            finish_bad(ctx, label, "second certificate for the hour already issued, re-using its signed reading (meter and issuer signatures valid)", tx, r.entries)
        }
        // Controls for the mutation method: the same edits as bad-replay / bad-amount, but to a legal value.
        // Each must PASS locally, which shows the edit itself does not break a transaction.
        "ctl-hour" | "ctl-amount" => {
            let r = issue(ctx, b, next_hour, 500_000, &Issue::default())?;
            let mut tx = r.tx.clone();
            let (hour, wh) = if cmd == "ctl-hour" { (next_hour + 1, 500_000) } else { (next_hour, 500_001) };
            let script = &mut tx.inputs[0].signature_script;
            if cmd == "ctl-hour" {
                replace_once(script, &(next_hour as u64).to_le_bytes(), &(hour as u64).to_le_bytes())?;
            } else {
                replace_once(script, &500_000u64.to_le_bytes(), &(wh as u64).to_le_bytes())?;
            }
            replace_once(script, &msig(next_hour, 500_000), &msig(hour, wh))?;
            let mut nd = d.clone();
            nd.last_hour = hour;
            tx.outputs[0].script_public_key = script_for(ctx, b, "Device", nd.state())?;
            tx.outputs[1].script_public_key = script_for(ctx, b, "Cert", cert_state(hour, wh).state("Cert"))?;
            resign_actor(&mut tx, &r.entries, 0, &ctx.k.issuer)?;
            resign_p2pk(&mut tx, &r.entries, 1, &ctx.k.payer)?;
            let ready = commit(tx, r.entries.clone())?;
            let local = match execute_input_with_covenants(&ready.tx, r.entries.clone(), 0) { Ok(()) => "ok".to_string(), Err(e) => format!("LOCAL-FAIL {e}") };
            write_row(ctx, label, "control: same mutation to a legal value (never sent)", "accept", &ready, &local, ctx.state.clone())
        }
        "bad-meter" => {
            let r = issue(ctx, b, next_hour, 500_000, &Issue::default())?;
            let mut tx = r.tx.clone();
            let forged = meter_reading(&forger, &d.meter_domain, next_hour as u64, &d.registry, &d.device, 500_000).2;
            replace_once(&mut tx.inputs[0].signature_script, &msig(next_hour, 500_000), &forged)?;
            finish_bad(ctx, label, "issue with the reading signed by a key that is not the meter", tx, r.entries)
        }
        "bad-issuer" => {
            let r = issue(ctx, b, next_hour, 500_000, &Issue::default())?;
            let mut tx = r.tx.clone();
            resign_actor(&mut tx, &r.entries, 0, &forger)?;
            finish_bad(ctx, label, "issue co-signed by a key that is not the issuing body", tx, r.entries)
        }
        "bad-cap" => {
            let (ok_wh, over) = (d.max_wh - 1, d.max_wh + 1);
            let r = issue(ctx, b, next_hour, ok_wh, &Issue::default())?;
            let mut tx = r.tx.clone();
            let script = &mut tx.inputs[0].signature_script;
            replace_once(script, &(ok_wh as u64).to_le_bytes(), &(over as u64).to_le_bytes())?;
            replace_once(script, &msig(next_hour, ok_wh), &msig(next_hour, over))?;
            tx.outputs[1].script_public_key = script_for(ctx, b, "Cert", cert_state(next_hour, over).state("Cert"))?;
            resign_actor(&mut tx, &r.entries, 0, &ctx.k.issuer)?;
            resign_p2pk(&mut tx, &r.entries, 1, &ctx.k.payer)?;
            finish_bad(ctx, label, "issue 1 Wh above the facility's hourly nameplate cap (meter and issuer signed it)", tx, r.entries)
        }
        "bad-amount" => {
            let r = issue(ctx, b, next_hour, 500_000, &Issue::default())?;
            let mut tx = r.tx.clone();
            replace_once(&mut tx.inputs[0].signature_script, &500_000u64.to_le_bytes(), &500_001u64.to_le_bytes())?;
            tx.outputs[1].script_public_key = script_for(ctx, b, "Cert", cert_state(next_hour, 500_001).state("Cert"))?;
            resign_actor(&mut tx, &r.entries, 0, &ctx.k.issuer)?;
            resign_p2pk(&mut tx, &r.entries, 1, &ctx.k.payer)?;
            finish_bad(ctx, label, "certificate claims 1 Wh more than the meter signed (issuer signed it)", tx, r.entries)
        }
        "bad-transfer" => {
            let r = transfer(ctx, b, &arg(1)?, None)?;
            let mut tx = r.tx.clone();
            resign_actor(&mut tx, &r.entries, 0, &forger)?;
            finish_bad(ctx, label, "transfer signed by someone who is not the holder", tx, r.entries)
        }
        "bad-split" => {
            let (name, take): (String, i64) = (arg(1)?, arg(2)?.parse()?);
            let r = split(ctx, b, &name, take, 0)?;
            let (_, c, _, role) = cert_coin(ctx, &name)?;
            let mut given = c.clone();
            given.wh = take + 1;
            given.holder = pubk(role_key(ctx, other_role(&role)));
            let mut tx = r.tx.clone();
            tx.outputs[1].script_public_key = script_for(ctx, b, "Cert", given.state("Cert"))?;
            resign_actor(&mut tx, &r.entries, 0, role_key(ctx, &role))?;
            resign_p2pk(&mut tx, &r.entries, 1, &ctx.k.payer)?;
            finish_bad(ctx, label, "split whose new part carries 1 Wh more than was taken (holder signed it)", tx, r.entries)
        }
        "bad-skim" => {
            let name = arg(1)?;
            let r = retire(ctx, b, &name, &blake2b32(b"skim"), None, 0)?;
            let (_, _, _, role) = cert_coin(ctx, &name)?;
            let mut tx = r.tx.clone();
            tx.outputs[0].value -= 1_000_000;
            tx.outputs[1].value += 1_000_000;
            resign_actor(&mut tx, &r.entries, 0, role_key(ctx, &role))?;
            resign_p2pk(&mut tx, &r.entries, 1, &ctx.k.payer)?;
            finish_bad(ctx, label, "retirement that moves 0.01 tKAS of the certificate deposit to the holder", tx, r.entries)
        }
        "bad-void" => {
            let r = invalidate(ctx, b, &arg(1)?, &blake2b32(b"not an auditor"), None)?;
            let mut tx = r.tx.clone();
            resign_actor(&mut tx, &r.entries, 0, &forger)?;
            finish_bad(ctx, label, "invalidate signed by someone who is not the auditor", tx, r.entries)
        }
        // bad-reuse <retired-cert>: spend a Retired certificate through Cert's transfer (a second life after the claim).
        "bad-reuse" => {
            let name = arg(1)?;
            let (cert, c, actor, role) = cert_coin(ctx, &name)?;
            if actor != "Retired" {
                return Err("bad-reuse needs a Retired cert".into());
            }
            let key = *role_key(ctx, &role);
            let mut moved = c.clone();
            moved.holder = pubk(role_key(ctx, other_role(&role)));
            let live_script = script_for(ctx, b, "Cert", c.state("Cert"))?;
            let fake = UtxoEntry::new(cert.utxo.amount, live_script, 0, false, Some(cert.covenant_id));
            let coin = payer_coin(ctx)?;
            let r = fit_fee(ctx.rate, |fee| {
                let change = coin.entry.amount.checked_sub(fee).ok_or("change")?;
                let nh = moved.holder.to_vec();
                let call = EntryCall::new("transfer").args_with(move |tx, index| args!(sign(tx, index, &key), nh.clone()));
                let (po, pe, ps) = payer_input(ctx, &coin);
                let tx = b.build(&TxContext::new()
                    .actor_input("Cert", c.state("Cert"), call, cert.outpoint, fake.clone(), 0)
                    .input(po, pe, ps, 0)
                    .actor_output("Cert", moved.state("Cert"), CovenantBinding::new(0, cert.covenant_id), cert.utxo.amount)
                    .output(p2pk(&ctx.payer_pub), None, change))?;
                commit(tx, vec![fake.clone(), coin.entry.clone()])
            })?;
            let entries = vec![cert.utxo.clone(), coin.entry.clone()];
            let mut tx = r.tx.clone();
            resign_actor(&mut tx, &entries, 0, &key)?;
            resign_p2pk(&mut tx, &entries, 1, &ctx.k.payer)?;
            finish_bad(ctx, label, "transfer a retired certificate as if it were live (a second claim on the same Wh)", tx, entries)
        }
        "bad-archive" => {
            let r = archive(ctx, b, &arg(1)?, None)?;
            let mut tx = r.tx.clone();
            resign_actor(&mut tx, &r.entries, 0, &forger)?;
            finish_bad(ctx, label, "archive after the window signed by someone who is not the holder", tx, r.entries)
        }
        "bad-close" => {
            let r = close(ctx, b, None)?;
            let mut tx = r.tx.clone();
            resign_actor(&mut tx, &r.entries, 0, &forger)?;
            finish_bad(ctx, label, "close the device signed by someone who is not the issuer", tx, r.entries)
        }
        _ => Err(format!("unknown command {cmd}").into()),
    }
}

fn resign_actor(tx: &mut Transaction, entries: &[UtxoEntry], index: usize, key: &Keypair) -> R<()> {
    let script = tx.inputs[index].signature_script.clone();
    let mut at = None;
    for k in 0..script.len().saturating_sub(66) {
        if script[k] == 65 && script[k + 65] == SIG_HASH_ALL.to_u8() {
            if at.is_some() {
                return Err("ambiguous signature push".into());
            }
            at = Some(k + 1);
        }
    }
    let at = at.ok_or("signature push not found")?;
    let mtx = MutableTransaction::with_entries(tx.clone(), entries.to_vec());
    let sig = sign(&mtx, index, key);
    tx.inputs[index].signature_script[at..at + 65].copy_from_slice(&sig);
    Ok(())
}

fn resign_p2pk(tx: &mut Transaction, entries: &[UtxoEntry], index: usize, key: &Keypair) -> R<()> {
    let mtx = MutableTransaction::with_entries(tx.clone(), entries.to_vec());
    tx.inputs[index].signature_script = p2pk_signature(&sign(&mtx, index, key));
    Ok(())
}

fn replace_once(hay: &mut [u8], from: &[u8], to: &[u8]) -> R<()> {
    if from.len() != to.len() {
        return Err("widths differ".into());
    }
    let hits: Vec<usize> = (0..=hay.len() - from.len()).filter(|&k| &hay[k..k + from.len()] == from).collect();
    if hits.len() != 1 {
        return Err(format!("pattern found {} times", hits.len()).into());
    }
    hay[hits[0]..hits[0] + to.len()].copy_from_slice(to);
    Ok(())
}

fn finish_bad(ctx: &Ctx, label: &str, what: &str, tx: Transaction, entries: Vec<UtxoEntry>) -> R<()> {
    let ready = commit(tx, entries.clone())?;
    let local = match execute_input_with_covenants(&ready.tx, entries, 0) {
        Ok(()) => "UNEXPECTED-ACCEPT".to_string(),
        Err(e) => format!("reject: {e}"),
    };
    write_row(ctx, label, what, "reject", &ready, &local, ctx.state.clone())
}

// ---------- selftest ----------

fn selftest(art: &Artifact, bond_art: &Artifact) -> R<()> {
    let dir = std::env::temp_dir().join(format!("hourcert-selftest-{}", std::process::id()));
    fs::create_dir_all(&dir)?;
    let demo = |seed: u8| -> R<Keypair> { Ok(Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[seed; 32])?)) };
    let keys = Keys { payer: demo(0xc0)?, issuer: demo(0x15)?, meter: demo(0x3e)?, auditor: demo(0xad)?, buyer: demo(0xb0)?, forger: demo(0xf1)? };
    let payer_pub = pubk(&keys.payer);
    let b = TxBuilder::new(art)?;
    let bb = TxBuilder::new(bond_art)?;
    let mut fund = Vec::new();
    for (n, byte, amount) in [(0u8, 0xf0u8, 119_769_700u64), (1, 0xf2, 98_653_100), (2, 0xf4, 98_639_800), (3, 0xf6, 80_000_000)] {
        let f = dir.join(format!("funding{n}.txt"));
        fs::write(&f, format!("txid={}\nindex=0\namount={}\ncoinbase=0\nblockDaa=0\nscript={}\n",
            TransactionId::from_bytes([byte; 32]), amount, hex(p2pk(&payer_pub).script())))?;
        fund.push(f.to_string_lossy().into_owned());
    }
    let h1 = "497697"; // 2026-10-11 09:00 UTC in hours since the Unix epoch
    let h2 = "497698";
    let steps: Vec<(&str, Vec<String>)> = vec![
        ("genesis", fund.clone()),
        ("issue", vec!["c1".into(), h1.into(), "1000000".into()]),
        ("bad-replay", vec![]),
        ("ctl-hour", vec![]),
        ("ctl-amount", vec![]),
        ("bad-meter", vec![]),
        ("bad-issuer", vec![]),
        ("bad-cap", vec![]),
        ("bad-amount", vec![]),
        ("bad-transfer", vec!["c1".into()]),
        ("transfer", vec!["c1".into()]),
        ("bad-split", vec!["c1".into(), "400000".into()]),
        ("split", vec!["c1".into(), "400000".into(), "c3".into()]),
        ("bad-skim", vec!["c1".into()]),
        ("retire", vec!["c1".into(), "buyer: Scope 2, 2026, site A".into()]),
        ("bad-reuse", vec!["c1".into()]),
        ("retire", vec!["c3".into(), "producer: own use, 2026".into()]),
        ("invalidate", vec!["c1".into(), "evidence failed after retirement".into()]),
        ("bad-archive", vec!["c3".into()]),
        ("archive", vec!["c3".into()]),
        ("issue", vec!["c2".into(), h2.into(), "600000".into()]),
        ("bad-void", vec!["c2".into()]),
        ("invalidate", vec!["c2".into(), "meter calibration failed audit".into()]),
        ("archive", vec!["c1".into()]),
        ("archive", vec!["c2".into()]),
        ("bond-genesis", vec![]),
        ("slash-meter", vec![h1.into(), "1000000".into(), "hourcert/v1/registry/R2".into()]),
        ("bad-close", vec![]),
        ("close", vec![]),
    ];
    let (mut pass, mut fail) = (0, 0);
    let mut state = json!({});
    for (n, (cmd, extra)) in steps.into_iter().enumerate() {
        let label = format!("{n:02}-{cmd}");
        let mut argv = vec![cmd.to_string()];
        argv.extend(extra);
        let ctx = Ctx { k: Keys { ..keys_clone(&keys) }, payer_pub, out: dir.to_string_lossy().into_owned(), rate: 100, state: state.clone() };
        let row: Value = match run_cmd(&ctx, &b, &bb, &label, cmd, &argv) {
            Ok(()) => serde_json::from_str(&fs::read_to_string(dir.join(format!("{label}.json")))?)?,
            Err(e) => { println!("FAIL {label}: build error {e}"); fail += 1; continue; }
        };
        let ok = match row["expect"].as_str() {
            Some("accept") => row["local"] == "ok",
            _ => row["local"].as_str().is_some_and(|l| l.starts_with("reject")),
        };
        if ok { pass += 1 } else { fail += 1 }
        println!("{} {label} {}", if ok { "PASS" } else { "FAIL" }, row["local"].as_str().unwrap_or("").chars().take(110).collect::<String>());
        if row["expect"] == "accept" && !cmd.starts_with("ctl-") {
            state = row["next"].clone();
        }
    }
    fs::remove_dir_all(&dir)?;
    println!("selftest: {pass} passed, {fail} failed");
    if fail > 0 { Err("selftest failed".into()) } else { Ok(()) }
}

fn keys_clone(k: &Keys) -> Keys {
    Keys { payer: k.payer, issuer: k.issuer, meter: k.meter, auditor: k.auditor, buyer: k.buyer, forger: k.forger }
}

// ---------- state and output ----------

fn push_payout(next: &mut Value, tx: &Transaction, index: u32) -> R<()> {
    let mut paid = next.get("payouts").cloned().unwrap_or_else(|| json!([]));
    paid.as_array_mut().ok_or("payouts")?.push(coin_json(tx, index));
    next["payouts"] = paid;
    Ok(())
}

fn utxo_json(tx: &Transaction, index: u32) -> Value {
    let o = &tx.outputs[index as usize];
    json!({"txid": tx.id().to_string(), "index": index, "value": o.value, "script": hex(o.script_public_key.script())})
}

fn coin_json(tx: &Transaction, index: u32) -> Value {
    json!({"txid": tx.id().to_string(), "index": index, "value": tx.outputs[index as usize].value})
}

fn emit(ctx: &Ctx, label: &str, what: &str, r: &Ready, next: Value) -> R<()> {
    let mut local = "ok".to_string();
    for (k, e) in r.entries.iter().enumerate() {
        if e.covenant_id.is_some() {
            if let Err(err) = execute_input_with_covenants(&r.tx, r.entries.clone(), k) {
                local = format!("LOCAL-FAIL input {k}: {err}");
            }
        }
    }
    let expect = std::env::var("HC_EXPECT").unwrap_or_else(|_| "accept".into());
    write_row(ctx, label, what, &expect, r, &local, next)
}

fn write_row(ctx: &Ctx, label: &str, what: &str, expect: &str, r: &Ready, local: &str, next: Value) -> R<()> {
    let row = json!({"label": label, "what": what, "expect": expect, "local": local, "fee": r.fee.to_string(),
        "storage": r.storage, "compute": r.compute, "transient": r.transient, "feeRate": ctx.rate,
        "tx": serde_json::from_str::<Value>(&tx_json(&r.tx))?, "next": next});
    fs::write(format!("{}/{label}.json", ctx.out), serde_json::to_string(&row)?)?;
    println!("{label}: {what} expect={expect} local={} fee={} storage={} compute={}",
        local.chars().take(160).collect::<String>(), r.fee, r.storage, r.compute);
    Ok(())
}

// ---------- helpers (same as oneword's tool) ----------

fn sign(tx: &MutableTransaction<Transaction>, index: usize, key: &Keypair) -> Vec<u8> {
    let digest = calc_schnorr_signature_hash(&tx.as_verifiable(), index, SIG_HASH_ALL, &SigHashReusedValuesUnsync::new());
    let mut w = key.sign_schnorr(Message::from_digest(digest.as_bytes())).as_ref().to_vec();
    w.push(SIG_HASH_ALL.to_u8());
    w
}

fn load_key(var: &str, address_var: Option<&str>) -> R<(Keypair, [u8; 32])> {
    let path = std::env::var(var).map_err(|_| var.to_string())?;
    let secret = hex_decode(fs::read_to_string(&path)?.trim())?;
    let key = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&secret)?);
    let public = key.x_only_public_key().0.serialize();
    if let Some(av) = address_var {
        let expect = std::env::var(av).map_err(|_| av.to_string())?;
        let address = Address::try_from(expect.trim())?;
        if address.prefix != Prefix::Testnet || address.version != Version::PubKey || address.payload.as_slice() != public {
            return Err("payer key does not match its testnet address".into());
        }
    }
    Ok((key, public))
}

fn load_funding(path: &str, payer_public: &[u8; 32]) -> R<Coin> {
    let text = fs::read_to_string(path)?;
    let get = |k: &str| -> R<String> {
        text.lines().find_map(|l| l.strip_prefix(&format!("{k}=")).map(|v| v.trim().to_string())).ok_or_else(|| format!("funding {k}").into())
    };
    let script = hex_decode(&get("script")?)?;
    if script.as_slice() != p2pk(payer_public).script() {
        return Err("funding script".into());
    }
    Ok(Coin {
        outpoint: TransactionOutpoint::new(TransactionId::from_str(&get("txid")?)?, get("index")?.parse()?),
        entry: UtxoEntry::new(get("amount")?.parse()?, ScriptPublicKey::from_vec(0, script), get("blockDaa")?.parse()?, get("coinbase")? == "1", None),
    })
}

fn env_i(k: &str, d: i64) -> R<i64> {
    Ok(std::env::var(k).ok().map(|v| v.parse()).transpose()?.unwrap_or(d))
}
fn s<'a>(v: &'a Value, k: &str) -> R<&'a str> {
    v.get(k).and_then(|x| x.as_str()).ok_or_else(|| format!("missing {k}").into())
}
fn u(v: &Value, k: &str) -> R<u64> {
    v.get(k).and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|s| s.parse().ok()))).ok_or_else(|| format!("missing {k}").into())
}
fn i(v: &Value, k: &str) -> R<i64> {
    v.get(k).and_then(|x| x.as_i64().or_else(|| x.as_str().and_then(|s| s.parse().ok()))).ok_or_else(|| format!("missing {k}").into())
}
fn arr32(h: &str) -> R<[u8; 32]> {
    let v = hex_decode(h)?;
    v.as_slice().try_into().map_err(|_| "need 32 bytes".into())
}

fn p2pk(public_key: &[u8; 32]) -> ScriptPublicKey {
    let mut script = Vec::with_capacity(34);
    script.push(32);
    script.extend_from_slice(public_key);
    script.push(0xac);
    ScriptPublicKey::from_vec(0, script)
}

fn p2pk_signature(raw: &[u8]) -> Vec<u8> {
    let mut script = vec![raw.len() as u8];
    script.extend_from_slice(raw);
    script
}

fn commit(mut tx: Transaction, entries: Vec<UtxoEntry>) -> R<Ready> {
    let calculator = MassCalculator::new(1, 10, 1_000_000_000_000);
    let populated = MutableTransaction::with_entries(tx.clone(), entries.clone());
    let storage = calculator.calc_contextual_masses(&populated.as_verifiable()).ok_or("storage mass")?.storage_mass;
    if storage > STORAGE_LIMIT {
        let outs: Vec<u64> = tx.outputs.iter().map(|o| o.value).collect();
        let ins: Vec<u64> = entries.iter().map(|e| e.amount).collect();
        return Err(format!("storage mass {storage} over the standard limit (in {ins:?} out {outs:?})").into());
    }
    tx.set_storage_mass(storage);
    tx.finalize();
    let masses = calculator.calc_non_contextual_masses(&tx);
    let input_value: u64 = entries.iter().map(|e| e.amount).sum();
    let output_value: u64 = tx.outputs.iter().map(|o| o.value).sum();
    if input_value < output_value {
        return Err("values".into());
    }
    Ok(Ready { tx, entries, storage, compute: masses.compute_mass, transient: masses.transient_mass, fee: input_value - output_value })
}

fn required_fee(item: &Ready, rate: u64) -> u64 {
    let relay = item.compute.max(item.transient.div_ceil(2));
    item.storage.max(relay).saturating_mul(rate).max(1)
}

fn fit_fee(rate: u64, build: impl Fn(u64) -> R<Ready>) -> R<Ready> {
    let mut fee = rate.saturating_mul(2_000).max(1);
    let mut last = String::from("no fee");
    for _ in 0..10 {
        let ready = build(fee)?;
        let need = required_fee(&ready, rate);
        if ready.fee >= need {
            return Ok(ready);
        }
        last = format!("need {need} had {}", ready.fee);
        fee = need + rate * 16;
    }
    Err(last.into())
}

fn tx_json(tx: &Transaction) -> String {
    let raw = borsh::to_vec(tx).expect("borsh");
    format!("{{\"id\":\"{}\",\"borsh\":\"{}\"}}", tx.id(), hex(&raw))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(text: &str) -> R<Vec<u8>> {
    if text.len() % 2 != 0 {
        return Err("hex".into());
    }
    (0..text.len()).step_by(2).map(|k| u8::from_str_radix(&text[k..k + 2], 16).map_err(|e| e.into())).collect()
}
