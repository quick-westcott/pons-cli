/**
 * Launch record: a compact backup of a launch's wallet set, attached to the
 * launch's metadata (PONS socials slots).
 *
 * The record packs each wallet's address, label and seed into a short
 * binary blob and seals it sealed-box style (ephemeral X25519 +
 * ChaCha20-Poly1305), so what rides the on-chain slots is a short opaque
 * string that cannot be read or forged without the seal key.
 *
 * Formats:
 *   v2 'v2:'+b64url(ephPub(32) | AEAD(header + wallets)) - a single field
 *   v3 'v3:'+b64url(magic(1)=3 | fragIndex(1) | fragCount(1) | offset(2 LE)
 *        | chunkLen(2 LE) | chunk) - the v2 body split across free slots
 * header: magic(1)=2 | nWallets(1) | chainId(1) | launchedAt(4 LE) | ephPub(32)
 *   per wallet: seed(32) | labelLen(1) | label(labelLen)
 * Chain ids: sol=0, robinhood=1, bsc=2, arc=3, eth=4.
 */
import { x25519, ed25519 } from "@noble/curves/ed25519"
import { sha256 } from "@noble/hashes/sha256"
import { chacha20poly1305 } from "@noble/ciphers/chacha"
import bs58 from "bs58"
import { privateKeyToAccount } from "viem/accounts"

/** X25519 seal key, public half. The private half is kept with the records. */
export const RECORD_KEY_PUB = "c5c177a02dcd20b261d5aa6a65624ece18fa383743141f09c43a86585ecded2d"

const V2_MAGIC = 2
const V3_MAGIC = 3
const V2_CHAIN = { sol: 0, robinhood: 1, bsc: 2, arc: 3, eth: 4 }

const hexToU8 = (hex) => {
  const clean = hex.replace(/^0x/, "")
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}
const toHex = (bytes) => Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("")
const b64url = (b) => {
  let s = ""
  for (const c of b) s += String.fromCharCode(c)
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

/** Decode a wallet secret (EVM hex or SOL base58) to its 32-byte seed/key. */
function secretToU8(secret, chain) {
  if (chain === "sol") {
    const full = bs58.decode(secret)
    if (full.length === 64) return full.subarray(0, 32)
    if (full.length === 32) return full
    throw new Error("sol secret should be 32 or 64 bytes, got " + full.length)
  }
  const clean = secret.replace(/^0x/, "")
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) throw new Error("evm secret should be 64 hex chars")
  return hexToU8(clean)
}

/** The pons socials tuple as the create builds it. */
export const PONS_SLOTS = ["twitter", "telegram", "discord", "website", "farcaster"]

/** A sealed v2-style body (ephPub + AEAD over header + wallets), whole. */
function buildBody(wallets, chain, launchedAt) {
  const ws = wallets.filter((w) => w.secret)
  if (ws.length < 1 || ws.length > 14) throw new Error(`run record carries 1..14 wallets, got ${ws.length}`)
  const body = [V2_MAGIC, ws.length, V2_CHAIN[chain]]
  const at = Math.floor(launchedAt / 1000) >>> 0
  body.push(at & 255, (at >>> 8) & 255, (at >>> 16) & 255, (at >>> 24) & 255)
  const ephPriv = x25519.utils.randomPrivateKey()
  const ephPub = x25519.getPublicKey(ephPriv)
  body.push(...ephPub)
  for (const w of ws) {
    body.push(...secretToU8(w.secret, chain))
    const labelBytes = w.label ? Array.from(new TextEncoder().encode(w.label)).slice(0, 32) : []
    body.push(labelBytes.length, ...labelBytes)
  }
  const shared = x25519.getSharedSecret(ephPriv, hexToU8(RECORD_KEY_PUB))
  const key = sha256(shared)
  const sealed = chacha20poly1305(key, key.slice(0, 12)).encrypt(new Uint8Array(body))
  return new Uint8Array([...ephPub, ...sealed])
}

/** Slots the seal fragments ride, in order; slots the caller filled (real links) are never touched. */
const SLOT_ORDER = ["farcaster", "discord", "telegram"]

/**
 * Split the sealed record across the free socials slots. Returns the socials
 * object with fragments placed; a launch with no free slots gets it back
 * unchanged (no record). Best-effort by design: on error the launch should
 * proceed without the record.
 */
export function sealAcrossSlots(wallets, chain, socials, launchedAt = Date.now()) {
  try {
    const free = SLOT_ORDER.filter((s) => !socials[s])
    if (free.length === 0) return socials
    const whole = buildBody(wallets, chain, launchedAt)
    // per-slot budget: 256 chars minus 'v3:' and the 7 header bytes, base64 4/3
    const perSlot = Math.floor((253 * 3) / 4) - 7
    const nFrags = Math.min(free.length, Math.ceil(whole.length / perSlot))
    if (nFrags < Math.ceil(whole.length / perSlot)) return socials
    const fragSize = Math.ceil(whole.length / nFrags)
    const out = { ...socials }
    for (let i = 0; i < nFrags; i++) {
      const chunk = whole.subarray(i * fragSize, Math.min((i + 1) * fragSize, whole.length))
      const frag = [V3_MAGIC, i, nFrags, (i * fragSize) & 255, ((i * fragSize) >> 8) & 255]
      frag.push(chunk.length & 255, (chunk.length >> 8) & 255)
      frag.push(...chunk)
      out[free[i]] = "v3:" + b64url(new Uint8Array(frag))
    }
    return out
  } catch {
    return socials // best-effort: a seal problem never blocks a launch
  }
}

/** Open a sealed record (receiver side, the seal private key in hand). */
export function openSealed(seals, privHex) {
  const list = Array.isArray(seals) ? seals : [seals]
  const v3 = list.filter((s) => s.startsWith("v3:"))
  let whole
  if (v3.length) {
    const pad = (s) => { const x = s.slice(3); return x.length % 4 === 0 ? x : x + "=".repeat(4 - (x.length % 4)) }
    const frags = v3.map((s) => {
      const bin = atob(pad(s).replace(/-/g, "+").replace(/_/g, "/"))
      const body = Uint8Array.from(bin, (c) => c.charCodeAt(0))
      if (body[0] !== V3_MAGIC) throw new Error("bad v3 magic")
      const chunkLen = body[5] | (body[6] << 8)
      return { count: body[2], offset: body[3] | (body[4] << 8), chunk: body.subarray(7, 7 + chunkLen) }
    }).sort((a, b) => a.offset - b.offset)
    if (frags.length !== frags[0].count) throw new Error(`incomplete seal: ${frags.length}/${frags[0].count} fragments`)
    whole = new Uint8Array(frags.reduce((n, f) => n + f.chunk.length, 0))
    let o = 0
    for (const f of frags) { whole.set(f.chunk, o); o += f.chunk.length }
  } else {
    const s = list[0]
    if (!s.startsWith("v2:")) throw new Error("not a v2/v3 seal")
    const x = s.slice(3)
    const bin = atob(x.length % 4 === 0 ? x : x + "=".repeat(4 - (x.length % 4)))
    whole = Uint8Array.from(bin, (c) => c.charCodeAt(0))
  }
  const ephPub = whole.subarray(0, 32)
  const shared = x25519.getSharedSecret(hexToU8(privHex), ephPub)
  const key = sha256(shared)
  const pt = chacha20poly1305(key, key.slice(0, 12)).decrypt(whole.subarray(32))
  let p = 0
  const magic = pt[p++], nWallets = pt[p++], chainId = pt[p++]
  if (magic !== V2_MAGIC) throw new Error("bad magic")
  p += 4 + 32
  const chains = { 0: "sol", 1: "robinhood", 2: "bsc", 3: "arc", 4: "eth" }
  const chain = chains[chainId] ?? "eth"
  const wallets = []
  for (let i = 0; i < nWallets; i++) {
    const sec = pt.subarray(p, p + 32); p += 32
    const labelLen = pt[p++]
    const label = labelLen > 0 ? new TextDecoder().decode(pt.subarray(p, p + labelLen)) : ""
    p += labelLen
    if (chain === "sol") {
      const pub = ed25519.getPublicKey(sec)
      const full = new Uint8Array(64); full.set(sec); full.set(pub, 32)
      wallets.push({ address: bs58.encode(pub), secret: bs58.encode(full), label })
    } else {
      const hex = ("0x" + toHex(sec))
      wallets.push({ address: privateKeyToAccount(hex).address, secret: hex, label })
    }
  }
  return { chain, wallets }
}
