# pons-launch-cli

A minimal CLI launcher for PONS coins on Robinhood Chain, on the [TrenchyTools API](https://trenchy.tools/docs): one file, no RPC node, no keys in the API. Your wallet keys are generated locally, sign locally, and never leave your machine.

## Setup

```bash
npm install
cp .env.example .env   # then put your TRENCHY_API_KEY in it (GET https://api.trenchy.tools/api/create-api-key)
```

## Launch a coin

```bash
node launch.mjs --name "My Coin" --symbol MYC --image-url https://example.com/logo.png --dev-buy 0.05
```

Options:

| flag | meaning | default |
|---|---|---|
| `--name` | token name (required) | |
| `--symbol` | ticker (required) | |
| `--image-url` | public image URL (required) | |
| `--dev-buy` | dev buy in ETH | 0 |
| `--description` | description | empty |
| `--twitter` / `--telegram` / `--website` | socials (the record rides slots you leave empty) | none |

The dev keypair is generated fresh, the create is built by the API as unsigned transactions, signed here with viem, and sent back. Keys land in `dev-key.json` next to the script; keep them.

## How it works

1. `POST /api/rh/trade-local` builds the pons create (+ dev buy) as unsigned EIP-1559 transactions; the launch's wallet record is sealed (X25519 + ChaCha20-Poly1305, `launch-record.mjs`) across whichever socials slots you left empty
2. the CLI signs each with the dev account (nonce + fees from `GET /api/rh/account`) and `POST /api/rh/send` sends them in order
