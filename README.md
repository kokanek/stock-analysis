# stock-analysis

A repo for stock market analysis and TradingView Pine Script strategies.

## What's here

Three Pine Script v6 swing/momentum strategies, each matched to the behavioral
"bucket" of the stocks it trades, plus a multi-page site explaining the market
rationale behind every rule and default (context as of July 2026).

| Bucket | Tickers | Strategy | Script |
|---|---|---|---|
| Mega-cap compounders | MSFT, AAPL | Quality Trend Pullback — buy orderly dips in a confirmed uptrend, exit on trend break | [`pine-scripts/01_quality_trend_pullback_megacap.pine`](pine-scripts/01_quality_trend_pullback_megacap.pine) |
| AI semiconductors | NVDA, AMD, MU | High-Beta Momentum Breakout — Donchian breakout + volume, risk-based sizing, scale-out, chandelier trail | [`pine-scripts/02_momentum_breakout_semis.pine`](pine-scripts/02_momentum_breakout_semis.pine) |
| Platform giants | AMZN, GOOGL | Range Reversion — fade lower-band washouts above the 200-day, sell the mean, time stop | [`pine-scripts/03_range_reversion_platforms.pine`](pine-scripts/03_range_reversion_platforms.pine) |

## Design notes

- **Daily timeframe, long-only.** Every entry passes a trend/regime gate first.
- **Backtest window manually limited to the last 365 days** (toggleable input in
  every script) so results reflect the current regime — hawkish Fed, geopolitical
  oil premium, AI-capex anxiety — rather than the 2023–2025 melt-up.
- **All parameters are tweakable inputs** with tooltips, grouped by purpose, and
  tethered to defaults argued for on the docs site.
- Conservative fill assumptions: 0.03% commission, slippage, close-of-bar orders.

## Docs site (password-gated)

The site explains the market rationale behind every rule and default: home, a
July-2026 market overview, and one deep-dive page per strategy (rules, parameter
reference, tuning guidance, failure modes).

It is published **encrypted**, so it can sit on GitHub Pages or Netlify without
being publicly readable:

| Directory | Contents | In git? |
|---|---|---|
| `site-src/` | plaintext HTML + CSS — the editable source | **no** (gitignored) |
| `docs/` | encrypted lock pages — the published build | yes |

### Building

```bash
node scripts/encrypt-site.js            # prompts for the passphrase
node scripts/encrypt-site.js --title 'Pine Strategy Lab' --hint 'Ask KK.'
```

Reads `site-src/`, writes password-gated pages to `docs/`. Then commit `docs/`
and point GitHub Pages (or Netlify's publish directory) at it.

Each page is encrypted with **AES-256-GCM** under a key derived from your
passphrase by **PBKDF2-SHA256, 600k iterations**. The browser asks for the
passphrase, derives the key with WebCrypto, decrypts locally, and writes the
real document — no server involved. Local `<link rel="stylesheet">` files are
inlined before encryption, so no plaintext CSS ships next to the locked pages.
Unlocking once per tab covers the whole site (the passphrase is cached in
`sessionStorage`), and every file is round-trip decrypted during the build, so a
page that cannot be recovered is never written.

Useful flags: `--in` / `--out`, `--key` (also read from `$SITE_KEY`), `--title`,
`--hint`, `--iterations`, `--delete-originals`. Run with `--help` for details.

### Editing the site

Edit `site-src/`, re-run the script, commit the regenerated `docs/`. Because
`site-src/` is gitignored, **keep a backup** — without it you can view the site
but never change it.

### What this protects against

Casual readers, scrapers, and search indexing. It is *not* protection against a
determined attacker: the ciphertext is public, so a weak passphrase can be
brute-forced offline regardless of iteration count. Use a long random passphrase,
share it out of band, and don't put genuine secrets in the site. Testing locally
requires a real HTTP origin (`http://localhost`) — browsers block WebCrypto on
`file://`.

## Disclaimer

Educational tooling, not financial advice. Backtest and forward-test before
risking capital.
