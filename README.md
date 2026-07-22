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

## Docs site

Open [`docs/index.html`](docs/index.html) locally, or enable GitHub Pages on the
`docs/` folder. Pages: home, July-2026 market overview, and one deep-dive page
per strategy (rationale, rules, parameter reference, tuning guidance, failure modes).

## Disclaimer

Educational tooling, not financial advice. Backtest and forward-test before
risking capital.
