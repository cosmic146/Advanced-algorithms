# Code Cracker (Unified Multi-Cipher)

## Project Description

Advanced Algorithms is a dual-tool Python project that combines:

- A multi-cipher code cracking engine
- A multi-source stock and asset prediction engine

It is designed for educational use and experimentation with algorithmic
analysis, ranking, fallback systems, and interactive CLI workflows.

### Key Features

- Multi-cipher cracking (Caesar, Atbash, Affine, Vigenere)
- Auto-detection for encoded ciphertext variants (raw, hex, base64)
- Multi-source market data fetch with fallback and caching
- 5-day forecast path with 3-pass cross-check selection
- TradingView-style technical analysis integration (`tradingview-ta`)
- Name-to-symbol resolver with typo fixes and numeric market code support
- Commodity and crypto aliases (gold, silver, bitcoin)
- Offline CSV mode for rate-limited or unavailable live providers

### Built-in Company/Asset Mappings (Core Offline List)

- NVIDIA -> NVDA
- APPLE -> AAPL
- MICROSOFT -> MSFT
- TESLA -> TSLA
- ROBLOX -> RBLX
- TENCENT -> 0700.HK
- AMAZON -> AMZN
- ALPHABET -> GOOGL
- GOOGLE -> GOOGL
- META -> META
- NETFLIX -> NFLX
- BERKSHIRE HATHAWAY -> BRK-B
- JPMORGAN CHASE -> JPM
- VISA -> V
- MASTERCARD -> MA
- WALMART -> WMT
- COSTCO -> COST
- HOME DEPOT -> HD
- LOWES -> LOW
- MCDONALDS -> MCD
- STARBUCKS -> SBUX
- NIKE -> NKE
- DISNEY -> DIS
- BOEING -> BA
- UNITEDHEALTH GROUP -> UNH
- AMERICAN EXPRESS -> AXP
- GOLDMAN SACHS -> GS
- MORGAN STANLEY -> MS
- BANK OF AMERICA -> BAC
- CITIGROUP -> C
- WELLS FARGO -> WFC
- JOHNSON AND JOHNSON -> JNJ
- PFIZER -> PFE
- MERCK -> MRK
- ELI LILLY -> LLY
- ABBVIE -> ABBV
- PROCTER AND GAMBLE -> PG
- COCA COLA -> KO
- PEPSICO -> PEP
- EXXON MOBIL -> XOM
- CHEVRON -> CVX
- ORACLE -> ORCL
- CISCO -> CSCO
- INTEL -> INTC
- ADVANCED MICRO DEVICES -> AMD
- BROADCOM -> AVGO
- QUALCOMM -> QCOM
- TEXAS INSTRUMENTS -> TXN
- ADOBE -> ADBE
- SALESFORCE -> CRM
- PALANTIR -> PLTR
- UBER -> UBER
- AIRBNB -> ABNB
- PAYPAL -> PYPL
- SHOPIFY -> SHOP
- SPACEX -> ARKX (proxy)
- SPACE X -> ARKX (proxy)
- GOLD -> GC=F
- SILVER -> SI=F
- BITCOIN -> BTC-USD

This Python program tests multiple cracking versions in one run, scores all
candidates, and returns the best-fitting plaintext.

Supported cracking versions:

- Caesar cipher
- Atbash cipher
- Affine cipher
- Vigenere cipher (automatic key-length testing)

Supported input variants (auto-detected):

- Raw text
- Hex-encoded text
- Base64-encoded text

## Run

```bash
python3 code_cracker.py
```

Then paste or type your encrypted text when prompted.

Show more candidate results:

```bash
python3 code_cracker.py --top 10
```

Increase Vigenere key search depth:

```bash
python3 code_cracker.py --max-key-len 14
```

## How it chooses the best version

- Tries every supported algorithm across every detected input variant
- Scores output using letter frequency, readability, and word-hit signals
- Deduplicates equivalent plaintexts
- Ranks and prints the best candidates

## Example

Encrypted:

```text
Uifsf jt b tfdsfu dpef
```

Likely top output includes:

```text
There is a secret code
```

Hex input example:

```bash
python3 code_cracker.py
```

At the prompt, enter:

```text
546865726520697320612073656372657420636f6465
```

## Stock Predictor (New Program)

There is now a second program in this project:

- stock_predictor.py

It asks for a company ticker, gets market data, predicts the next 5 trading
days, and prints an educational buy/sell/hold summary using a weighted
ensemble of:

- Linear trend model
- Exponential smoothing
- AR(1) return model
- Moving-average crossover signal

It also cross-checks with TradingView-style technical analysis via the
`tradingview-ta` Python library (when available).

Run it:

```bash
python3 stock_predictor.py
```

It will prompt:

```text
Enter company ticker symbol (e.g., AAPL):
```

Input resolver now supports:

- Common company names/typos (example: NVDIA -> NVDA, roblox -> RBLX)
- Numeric HK code input (example: 700 -> 0700.HK)
- Gold (gold -> GC=F)
- Silver (silver -> SI=F)
- Bitcoin (bitcoin -> BTC-USD)

Large company library:

- The app now imports a large company-name library (NASDAQ listings + S&P 500)
- Company names are normalized and mapped to ticker symbols automatically
- Library data is cached locally for faster repeated lookups
- Includes a built-in offline fallback list of 50+ major companies
- SpaceX input is supported via proxy mapping (spacex -> ARKX)

Advanced options:

```bash
python3 stock_predictor.py --lookback 300 --alpha 0.3 --short-window 12 --long-window 48
```

Disable TradingView cross-check:

```bash
python3 stock_predictor.py --no-tradingview
```

Offline mode (if live APIs are rate-limited):

```bash
python3 stock_predictor.py --csv data/aapl_history.csv
```

CSV format requirements:

- Must include Date column (YYYY-MM-DD)
- Must include Close column (or Adj Close)
- Needs at least 20 rows

Important:

- It is educational and experimental.
- It is not financial advice.
