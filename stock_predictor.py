#!/usr/bin/env python3
"""
Stock Predictor (educational)

This tool asks for a company ticker, pulls market data, estimates the next
week (5 trading days), and prints an educational buy/sell/hold signal.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import date, datetime, timedelta
import json
import math
from pathlib import Path
from statistics import fmean
import time
import warnings
from typing import Iterable
from urllib.request import Request
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
from typing import Callable

# Suppress noisy LibreSSL warning emitted by urllib3 on macOS system Python.
warnings.filterwarnings(
    "ignore",
    message="urllib3 v2 only supports OpenSSL 1.1.1+",
)

try:
    from tradingview_ta import Interval, TA_Handler
except ImportError:
    TA_Handler = None
    Interval = None

try:
    import yfinance as yf
except ImportError:
    yf = None


# ── Model defaults (auto-tuned by portfolio_tracker.py after prediction reviews) ──
MODEL_DEFAULT_ALPHA: float = 0.25
MODEL_DEFAULT_SHORT_WINDOW: int = 10
MODEL_DEFAULT_LONG_WINDOW: int = 40

CACHE_DIR = Path(__file__).resolve().parent / ".cache" / "market_data"
COMPANY_LIBRARY_CACHE = CACHE_DIR / "company_library.json"

_COMPANY_LIBRARY: dict[str, str] | None = None


@dataclass(frozen=True)
class PricePoint:
    day: date
    close: float


@dataclass(frozen=True)
class ModelPrediction:
    name: str
    predicted_close: float
    predicted_return: float


@dataclass(frozen=True)
class LiveQuote:
    price: float
    quote_time: str
    source: str


@dataclass(frozen=True)
class DayForecast:
    day_index: int
    predicted_close: float
    predicted_return: float


@dataclass(frozen=True)
class CrossCheckPass:
    name: str
    week_forecasts: list[DayForecast]
    models: list[ModelPrediction]
    confidence: float
    week_return: float


@dataclass(frozen=True)
class ResolvedSymbol:
    display_symbol: str
    data_symbol: str
    asset_type: str
    tradingview_symbol: str | None
    tradingview_exchange: str | None
    tradingview_screener: str | None


@dataclass(frozen=True)
class TradingViewSignal:
    recommendation: str
    buy_count: int
    sell_count: int
    neutral_count: int
    source: str


def parse_date(raw: str) -> date:
    return datetime.strptime(raw, "%Y-%m-%d").date()


def prompt_text(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        raise SystemExit("No input available. Exiting cleanly.")
    except KeyboardInterrupt:
        raise SystemExit("Interrupted by user.")


def normalize_user_symbol(raw_symbol: str) -> str:
    return " ".join(raw_symbol.strip().upper().replace(".", " ").split())


def normalize_company_name(name: str) -> str:
    cleaned = normalize_user_symbol(name)
    noise = [", INC", " INC", " CORPORATION", " CORP", " LTD", " LIMITED", " PLC", " HOLDINGS"]
    for token in noise:
        if cleaned.endswith(token):
            cleaned = cleaned[: -len(token)].strip()
    cleaned = cleaned.replace("&", "AND")
    return " ".join(cleaned.split())


def fetch_csv_rows(url: str) -> list[dict[str, str]]:
    payload = fetch_text_with_retries(url, attempts=2, base_delay=0.8)
    reader = csv.DictReader(payload.splitlines())
    rows: list[dict[str, str]] = []
    for row in reader:
        rows.append({str(k): str(v) for k, v in row.items()})
    return rows


def maybe_load_company_library_cache(max_age_days: int = 30) -> dict[str, str] | None:
    if not COMPANY_LIBRARY_CACHE.exists():
        return None
    try:
        payload = json.loads(COMPANY_LIBRARY_CACHE.read_text(encoding="utf-8"))
        saved_at = datetime.strptime(payload.get("saved_at", ""), "%Y-%m-%dT%H:%M:%SZ")
        if (datetime.utcnow() - saved_at).days > max_age_days:
            return None
        data = payload.get("library")
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    return None


def save_company_library_cache(library: dict[str, str]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "saved_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "library": library,
    }
    COMPANY_LIBRARY_CACHE.write_text(json.dumps(payload), encoding="utf-8")


def build_company_library() -> dict[str, str]:
    global _COMPANY_LIBRARY
    if _COMPANY_LIBRARY is not None:
        return _COMPANY_LIBRARY

    cached = maybe_load_company_library_cache()
    if cached:
        _COMPANY_LIBRARY = cached
        return _COMPANY_LIBRARY

    library: dict[str, str] = {}

    # S&P 500 constituents: ~500 names.
    sp500_url = "https://datahub.io/core/s-and-p-500-companies/r/constituents.csv"
    # NASDAQ listed companies: thousands of names.
    nasdaq_url = "https://datahub.io/core/nasdaq-listings/r/nasdaq-listed-symbols.csv"

    sources: list[tuple[str, Callable[[dict[str, str]], tuple[str, str] | None]]] = [
        (
            sp500_url,
            lambda row: (
                str(row.get("Name") or "").strip(),
                str(row.get("Symbol") or "").strip(),
            ),
        ),
        (
            nasdaq_url,
            lambda row: (
                str(row.get("Company Name") or "").strip(),
                str(row.get("Symbol") or "").strip(),
            ),
        ),
    ]

    for url, mapper in sources:
        try:
            rows = fetch_csv_rows(url)
        except Exception:
            continue
        for row in rows:
            mapped = mapper(row)
            if mapped is None:
                continue
            name, symbol = mapped
            if not name or not symbol:
                continue

            if "^" in symbol or symbol.startswith("$"):
                continue

            normalized_name = normalize_company_name(name)
            if normalized_name and normalized_name not in library:
                library[normalized_name] = symbol.upper()

    # Guaranteed offline company list (50+ entries) when network sources are unavailable.
    fallback_core = {
        "NVIDIA": "NVDA",
        "APPLE": "AAPL",
        "MICROSOFT": "MSFT",
        "TESLA": "TSLA",
        "ROBLOX": "RBLX",
        "TENCENT": "0700.HK",
        "AMAZON": "AMZN",
        "ALPHABET": "GOOGL",
        "GOOGLE": "GOOGL",
        "META": "META",
        "NETFLIX": "NFLX",
        "BERKSHIRE HATHAWAY": "BRK-B",
        "JPMORGAN CHASE": "JPM",
        "VISA": "V",
        "MASTERCARD": "MA",
        "WALMART": "WMT",
        "COSTCO": "COST",
        "HOME DEPOT": "HD",
        "LOWES": "LOW",
        "MCDONALDS": "MCD",
        "STARBUCKS": "SBUX",
        "NIKE": "NKE",
        "DISNEY": "DIS",
        "BOEING": "BA",
        "UNITEDHEALTH GROUP": "UNH",
        "AMERICAN EXPRESS": "AXP",
        "GOLDMAN SACHS": "GS",
        "MORGAN STANLEY": "MS",
        "BANK OF AMERICA": "BAC",
        "CITIGROUP": "C",
        "WELLS FARGO": "WFC",
        "JOHNSON AND JOHNSON": "JNJ",
        "PFIZER": "PFE",
        "MERCK": "MRK",
        "ELI LILLY": "LLY",
        "ABBVIE": "ABBV",
        "PROCTER AND GAMBLE": "PG",
        "COCA COLA": "KO",
        "PEPSICO": "PEP",
        "EXXON MOBIL": "XOM",
        "CHEVRON": "CVX",
        "ORACLE": "ORCL",
        "CISCO": "CSCO",
        "INTEL": "INTC",
        "ADVANCED MICRO DEVICES": "AMD",
        "BROADCOM": "AVGO",
        "QUALCOMM": "QCOM",
        "TEXAS INSTRUMENTS": "TXN",
        "ADOBE": "ADBE",
        "SALESFORCE": "CRM",
        "PALANTIR": "PLTR",
        "UBER": "UBER",
        "AIRBNB": "ABNB",
        "PAYPAL": "PYPL",
        "SHOPIFY": "SHOP",
        "SPACEX": "ARKX",
        "SPACE X": "ARKX",
    }
    for k, v in fallback_core.items():
        library.setdefault(k, v)

    _COMPANY_LIBRARY = library
    if library:
        save_company_library_cache(library)
    return _COMPANY_LIBRARY


def resolve_symbol(raw_symbol: str) -> ResolvedSymbol:
    aliases = {
        "NVDIA": "NVDA",
        "NVIDIA": "NVDA",
        "NVIDIA CORP": "NVDA",
        "APPLE": "AAPL",
        "MICROSOFT": "MSFT",
        "TESLA": "TSLA",
        "GOOGLE": "GOOGL",
        "ALPHABET": "GOOGL",
        "AMAZON": "AMZN",
        "META": "META",
        "NETFLIX": "NFLX",
        "ROBLOX": "RBLX",
        "RBLX": "RBLX",
        "BITCOIN": "BTC-USD",
        "BTC": "BTC-USD",
        "BTCUSD": "BTC-USD",
        "BTC USD": "BTC-USD",
        "GOLD": "GC=F",
        "XAU": "GC=F",
        "XAUUSD": "GC=F",
        "SILVER": "SI=F",
        "XAG": "SI=F",
        "XAGUSD": "SI=F",
        # SpaceX is private; use ARKX as a public-market proxy.
        "SPACEX": "ARKX",
        "SPACE X": "ARKX",
        "SPACE EXPLORATION TECHNOLOGIES": "ARKX",
    }

    symbol = normalize_user_symbol(raw_symbol)

    if not symbol:
        raise ValueError("Symbol cannot be empty.")

    # Numeric company codes such as 700 -> 0700.HK (Tencent).
    if symbol.isdigit() and len(symbol) <= 4:
        hk_code = symbol.zfill(4)
        return ResolvedSymbol(
            display_symbol=f"{hk_code}.HK",
            data_symbol=f"{hk_code}.HK",
            asset_type="stock_hk",
            tradingview_symbol=hk_code,
            tradingview_exchange="HKEX",
            tradingview_screener="hongkong",
        )

    canonical = aliases.get(symbol, symbol)

    # Large company-name library lookup (NASDAQ + S&P500 + cached).
    company_library = build_company_library()
    company_hit = company_library.get(normalize_company_name(canonical))
    if company_hit:
        canonical = company_hit

    if canonical == "BTC-USD":
        return ResolvedSymbol(
            display_symbol="BTC-USD",
            data_symbol="BTC-USD",
            asset_type="crypto",
            tradingview_symbol="BTCUSD",
            tradingview_exchange="COINBASE",
            tradingview_screener="crypto",
        )

    if canonical == "GC=F":
        return ResolvedSymbol(
            display_symbol="GOLD",
            data_symbol="GC=F",
            asset_type="commodity",
            tradingview_symbol="XAUUSD",
            tradingview_exchange="OANDA",
            tradingview_screener="forex",
        )

    if canonical == "SI=F":
        return ResolvedSymbol(
            display_symbol="SILVER",
            data_symbol="SI=F",
            asset_type="commodity",
            tradingview_symbol="XAGUSD",
            tradingview_exchange="OANDA",
            tradingview_screener="forex",
        )

    if canonical.endswith(".HK"):
        hk_code = canonical.split(".", maxsplit=1)[0].zfill(4)
        return ResolvedSymbol(
            display_symbol=f"{hk_code}.HK",
            data_symbol=f"{hk_code}.HK",
            asset_type="stock_hk",
            tradingview_symbol=hk_code,
            tradingview_exchange="HKEX",
            tradingview_screener="hongkong",
        )

    return ResolvedSymbol(
        display_symbol=canonical,
        data_symbol=canonical,
        asset_type="stock_us",
        tradingview_symbol=canonical,
        tradingview_exchange=None,
        tradingview_screener=None,
    )


def safe_symbol(raw_symbol: str) -> str:
    return resolve_symbol(raw_symbol).display_symbol


def to_stooq_symbol(symbol: str) -> str:
    # Stooq expects lowercase, and many US tickers use .us suffix.
    clean = symbol.lower()
    return clean if "." in clean else f"{clean}.us"


def fetch_text(url: str) -> str:
    req = Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        },
    )
    with urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8", errors="replace")


def fetch_text_nasdaq(url: str) -> str:
    req = Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json, text/plain, */*",
            "Referer": "https://www.nasdaq.com/",
            "Origin": "https://www.nasdaq.com",
        },
    )
    with urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8", errors="replace")


def clean_price(raw: str) -> float | None:
    txt = raw.replace("$", "").replace(",", "").strip()
    if not txt:
        return None
    try:
        return float(txt)
    except ValueError:
        return None


def cache_key(symbol: str) -> str:
    keep = []
    for ch in symbol.upper():
        if ch.isalnum() or ch in ("-", "_"):
            keep.append(ch)
        else:
            keep.append("_")
    return "".join(keep)


def save_history_cache(symbol: str, points: list[PricePoint], source: str) -> None:
    if not points:
        return

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / f"{cache_key(symbol)}.json"
    payload = {
        "symbol": symbol,
        "source": source,
        "saved_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rows": [
            {"day": p.day.isoformat(), "close": round(float(p.close), 8)}
            for p in points
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def load_history_cache(symbol: str, max_age_days: int = 7) -> list[PricePoint]:
    path = CACHE_DIR / f"{cache_key(symbol)}.json"
    if not path.exists():
        return []

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        saved_at = datetime.strptime(payload.get("saved_at", ""), "%Y-%m-%dT%H:%M:%SZ")
        if (datetime.utcnow() - saved_at).days > max_age_days:
            return []
        rows = payload.get("rows") or []
    except (ValueError, TypeError, json.JSONDecodeError):
        return []

    out: list[PricePoint] = []
    for row in rows:
        try:
            day = parse_date(str(row.get("day") or ""))
            close = float(row.get("close"))
            out.append(PricePoint(day=day, close=close))
        except (TypeError, ValueError):
            continue

    out.sort(key=lambda p: p.day)
    return out


def fetch_tradingview_signal(resolved: ResolvedSymbol) -> TradingViewSignal | None:
    if TA_Handler is None or Interval is None:
        return None

    attempts: list[tuple[str, str, str]] = []

    if (
        resolved.tradingview_symbol
        and resolved.tradingview_exchange
        and resolved.tradingview_screener
    ):
        attempts.append(
            (
                resolved.tradingview_screener,
                resolved.tradingview_exchange,
                resolved.tradingview_symbol,
            )
        )

    if resolved.display_symbol.endswith(".HK"):
        hk_code = resolved.display_symbol.split(".", maxsplit=1)[0].zfill(4)
        attempts.append(("hongkong", "HKEX", hk_code))

    if resolved.display_symbol.isalpha():
        attempts.append(("america", "NASDAQ", resolved.display_symbol))
        attempts.append(("america", "NYSE", resolved.display_symbol))

    # Remove exact duplicates while preserving order.
    unique_attempts: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in attempts:
        if item not in seen:
            unique_attempts.append(item)
            seen.add(item)

    for screener, exchange, symbol_name in unique_attempts:
        try:
            handler = TA_Handler(
                symbol=symbol_name,
                screener=screener,
                exchange=exchange,
                interval=Interval.INTERVAL_1_DAY,
            )
            analysis = handler.get_analysis()
            summary = analysis.summary or {}
            rec = str(summary.get("RECOMMENDATION") or "NEUTRAL")
            buy_count = int(summary.get("BUY") or 0)
            sell_count = int(summary.get("SELL") or 0)
            neutral_count = int(summary.get("NEUTRAL") or 0)
            return TradingViewSignal(
                recommendation=rec,
                buy_count=buy_count,
                sell_count=sell_count,
                neutral_count=neutral_count,
                source=f"tradingview-ta ({exchange})",
            )
        except Exception:
            continue

    return None


def fetch_text_with_retries(url: str, attempts: int = 3, base_delay: float = 1.0) -> str:
    """Retry HTTP fetch on transient failures like 429 rate-limit responses."""
    last_error: Exception | None = None

    for i in range(attempts):
        try:
            return fetch_text(url)
        except HTTPError as exc:
            last_error = exc
            if exc.code not in (429, 500, 502, 503, 504) or i == attempts - 1:
                raise
        except URLError as exc:
            last_error = exc
            if i == attempts - 1:
                raise

        time.sleep(base_delay * (2**i))

    if last_error is not None:
        raise last_error
    raise RuntimeError("Unexpected fetch retry failure.")


def fetch_live_quote_stooq(symbol: str) -> LiveQuote | None:
    candidates = [to_stooq_symbol(symbol), symbol.lower()]
    hosts = ["https://stooq.com", "https://stooq.pl"]
    for stooq_symbol in candidates:
        for host in hosts:
            url = f"{host}/q/l/?s={stooq_symbol}&f=sd2t2ohlcv&h&e=csv"
            try:
                payload = fetch_text_with_retries(url, attempts=2, base_delay=0.7)
            except (HTTPError, URLError):
                continue

            reader = csv.DictReader(payload.splitlines())
            rows = list(reader)
            if not rows:
                continue

            row = rows[0]
            close_raw = (row.get("Close") or "").strip()
            day_raw = (row.get("Date") or "").strip()
            time_raw = (row.get("Time") or "").strip()
            if not close_raw or close_raw.lower() == "nan":
                continue

            try:
                price = float(close_raw)
            except ValueError:
                continue

            quote_time = f"{day_raw} {time_raw}".strip() if day_raw else "unknown"
            return LiveQuote(price=price, quote_time=quote_time, source="stooq")

    return None


def fetch_live_quote_yahoo(symbol: str) -> LiveQuote | None:
    urls = [
        f"https://query1.finance.yahoo.com/v7/finance/quote?symbols={symbol}",
        f"https://query2.finance.yahoo.com/v7/finance/quote?symbols={symbol}",
    ]
    payload = None
    for url in urls:
        try:
            payload = fetch_text_with_retries(url)
            break
        except (HTTPError, URLError):
            continue

    if payload is None:
        return None

    try:
        data = json.loads(payload)
        result = data["quoteResponse"]["result"][0]
        price = float(result["regularMarketPrice"])
        epoch = int(result.get("regularMarketTime") or 0)
    except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
        return None

    quote_time = (
        datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S UTC")
        if epoch > 0
        else "unknown"
    )
    return LiveQuote(price=price, quote_time=quote_time, source="yahoo")


def fetch_live_quote_yfinance(symbol: str) -> LiveQuote | None:
    if yf is None:
        return None

    try:
        ticker = yf.Ticker(symbol)
        fast = getattr(ticker, "fast_info", None) or {}
        price = fast.get("lastPrice") or fast.get("regularMarketPrice")
        if price is None:
            # Fallback to 1-day history if fast_info is missing.
            hist = ticker.history(period="2d", interval="1d", auto_adjust=False)
            if hist is None or hist.empty:
                return None
            price = float(hist["Close"].dropna().iloc[-1])
        else:
            price = float(price)
    except Exception:
        return None

    return LiveQuote(
        price=price,
        quote_time=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        source="yfinance",
    )


def fetch_live_quote_nasdaq(symbol: str) -> LiveQuote | None:
    url = f"https://api.nasdaq.com/api/quote/{symbol}/info?assetclass=stocks"
    try:
        payload = fetch_text_nasdaq(url)
    except (HTTPError, URLError):
        return None

    try:
        data = json.loads(payload)
        primary = data["data"]["primaryData"]
        price_raw = str(primary.get("lastSalePrice") or "")
        quote_time = str(primary.get("lastTradeTimestamp") or "unknown")
        price = clean_price(price_raw)
        if price is None:
            return None
    except (KeyError, TypeError, json.JSONDecodeError):
        return None

    return LiveQuote(price=price, quote_time=quote_time, source="nasdaq")


def fetch_live_quote(symbol: str) -> LiveQuote | None:
    return (
        fetch_live_quote_stooq(symbol)
        or fetch_live_quote_yfinance(symbol)
        or fetch_live_quote_yahoo(symbol)
        or fetch_live_quote_nasdaq(symbol)
    )


def fetch_stooq_history(symbol: str) -> list[PricePoint]:
    candidates = [to_stooq_symbol(symbol), symbol.lower()]
    hosts = ["https://stooq.com", "https://stooq.pl"]

    best: list[PricePoint] = []
    for stooq_symbol in candidates:
        for host in hosts:
            url = f"{host}/q/d/l/?s={stooq_symbol}&i=d"
            try:
                payload = fetch_text_with_retries(url, attempts=2, base_delay=0.7)
            except HTTPError:
                continue
            except URLError:
                continue

            reader = csv.DictReader(payload.splitlines())
            out: list[PricePoint] = []
            for row in reader:
                day_raw = (row.get("Date") or "").strip()
                close_raw = (row.get("Close") or "").strip()
                if not day_raw or not close_raw or close_raw.lower() == "nan":
                    continue
                try:
                    out.append(PricePoint(day=parse_date(day_raw), close=float(close_raw)))
                except (ValueError, TypeError):
                    continue

            out.sort(key=lambda p: p.day)
            if len(out) > len(best):
                best = out

    return best


def fetch_yahoo_history(symbol: str) -> list[PricePoint]:
    urls = [
        f"https://query1.finance.yahoo.com/v8/finance/chart/{symbol}?range=10y&interval=1d&events=history",
        f"https://query2.finance.yahoo.com/v8/finance/chart/{symbol}?range=10y&interval=1d&events=history",
        f"https://query1.finance.yahoo.com/v8/finance/chart/{symbol}?range=5y&interval=1d&events=history",
        f"https://query2.finance.yahoo.com/v8/finance/chart/{symbol}?range=5y&interval=1d&events=history",
        f"https://query1.finance.yahoo.com/v8/finance/chart/{symbol}?range=1y&interval=1d&events=history",
        f"https://query2.finance.yahoo.com/v8/finance/chart/{symbol}?range=1y&interval=1d&events=history",
    ]

    payload = None
    last_http_code: int | None = None
    for url in urls:
        try:
            payload = fetch_text_with_retries(url)
            break
        except HTTPError as exc:
            last_http_code = exc.code
            continue
        except URLError:
            continue

    if payload is None:
        if last_http_code is not None:
            raise RuntimeError(f"Yahoo data request failed (HTTP {last_http_code}).")
        raise RuntimeError("Network error while fetching Yahoo data.")

    try:
        data = json.loads(payload)
        result = data["chart"]["result"][0]
        timestamps = result.get("timestamp") or []
        quotes = result.get("indicators", {}).get("quote", [{}])[0]
        closes = quotes.get("close") or []
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Failed to parse Yahoo historical data response.") from exc

    out: list[PricePoint] = []
    for ts, close in zip(timestamps, closes):
        if close is None:
            continue
        try:
            day = datetime.utcfromtimestamp(int(ts)).date()
            out.append(PricePoint(day=day, close=float(close)))
        except (TypeError, ValueError, OSError):
            continue

    out.sort(key=lambda p: p.day)
    return out


def fetch_yfinance_history(symbol: str) -> list[PricePoint]:
    if yf is None:
        raise RuntimeError("yfinance package not installed.")

    try:
        data = yf.download(
            symbol,
            period="10y",
            interval="1d",
            progress=False,
            auto_adjust=False,
            threads=False,
        )
    except Exception as exc:
        raise RuntimeError(f"yfinance history request failed: {exc}") from exc

    if data is None or data.empty:
        raise RuntimeError("yfinance returned no rows.")

    out: list[PricePoint] = []
    for idx, row in data.iterrows():
        try:
            day = idx.to_pydatetime().date()
            close_val = row.get("Close")
            if close_val is None:
                continue
            # yfinance may return a 1-element Series for Close in some layouts.
            if hasattr(close_val, "iloc"):
                close_val = close_val.iloc[0]
            close = float(close_val)
        except Exception:
            continue
        out.append(PricePoint(day=day, close=close))

    out.sort(key=lambda p: p.day)
    if not out:
        raise RuntimeError("yfinance returned no usable rows.")
    return out


def fetch_nasdaq_history(symbol: str) -> list[PricePoint]:
    to_day = date.today()
    from_day = to_day - timedelta(days=365 * 5)
    url = (
        f"https://api.nasdaq.com/api/quote/{symbol}/historical"
        f"?assetclass=stocks&fromdate={from_day.isoformat()}"
        f"&todate={to_day.isoformat()}&limit=2000"
    )

    try:
        payload = fetch_text_nasdaq(url)
    except HTTPError as exc:
        raise RuntimeError(f"Nasdaq data request failed (HTTP {exc.code}).") from exc
    except URLError as exc:
        raise RuntimeError(f"Network error while fetching Nasdaq data: {exc.reason}") from exc

    try:
        data = json.loads(payload)
        rows = data["data"]["tradesTable"]["rows"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Failed to parse Nasdaq historical data response.") from exc

    out: list[PricePoint] = []
    for row in rows:
        day_raw = str(row.get("date") or "").strip()
        close_raw = str(row.get("close") or "").strip()
        if not day_raw or not close_raw:
            continue

        try:
            day = datetime.strptime(day_raw, "%m/%d/%Y").date()
        except ValueError:
            continue

        close = clean_price(close_raw)
        if close is None:
            continue

        out.append(PricePoint(day=day, close=close))

    out.sort(key=lambda p: p.day)
    return out


def history_sources_for(resolved: ResolvedSymbol) -> list[tuple[str, callable]]:
    if resolved.asset_type == "stock_us":
        return [
            ("yfinance", fetch_yfinance_history),
            ("stooq", fetch_stooq_history),
            ("yahoo", fetch_yahoo_history),
            ("nasdaq", fetch_nasdaq_history),
        ]
    if resolved.asset_type == "stock_hk":
        return [
            ("yfinance", fetch_yfinance_history),
            ("stooq", fetch_stooq_history),
            ("yahoo", fetch_yahoo_history),
        ]
    # Commodities and crypto should not use Nasdaq's stock parser.
    return [
        ("yfinance", fetch_yfinance_history),
        ("yahoo", fetch_yahoo_history),
        ("stooq", fetch_stooq_history),
    ]


def proxy_symbols_for(resolved: ResolvedSymbol) -> list[str]:
    """Fallback proxies when direct commodity/crypto feeds are unavailable."""
    if resolved.display_symbol == "GOLD":
        return ["GLD", "IAU"]
    if resolved.display_symbol == "SILVER":
        return ["SLV"]
    if resolved.display_symbol == "BTC-USD":
        return ["IBIT", "BITO", "MSTR"]
    return []


def fetch_history(resolved: ResolvedSymbol) -> list[PricePoint]:
    """Fetch data from multiple sources, preferring the largest valid dataset."""
    candidates: list[tuple[str, list[PricePoint]]] = []
    errors: list[str] = []

    for source_name, source_fn in history_sources_for(resolved):
        try:
            points = source_fn(resolved.data_symbol)
            if points:
                candidates.append((source_name, points))
        except RuntimeError as exc:
            errors.append(f"{source_name}: {exc}")

    if candidates:
        best_source, best = max(candidates, key=lambda item: len(item[1]))
        if len(best) >= 20:
            save_history_cache(resolved.display_symbol, best, source=best_source)
            return best
        if len(best) >= 10:
            save_history_cache(resolved.display_symbol, best, source=best_source)
            return best

    # If direct feeds fail for some assets, try liquid proxy symbols.
    for proxy_symbol in proxy_symbols_for(resolved):
        proxy_resolved = ResolvedSymbol(
            display_symbol=proxy_symbol,
            data_symbol=proxy_symbol,
            asset_type="stock_us",
            tradingview_symbol=proxy_symbol,
            tradingview_exchange="NASDAQ",
            tradingview_screener="america",
        )
        for source_name, source_fn in history_sources_for(proxy_resolved):
            try:
                points = source_fn(proxy_resolved.data_symbol)
                if not points:
                    continue
                if len(points) >= 10:
                    save_history_cache(
                        resolved.display_symbol,
                        points,
                        source=f"proxy:{proxy_symbol}:{source_name}",
                    )
                    return points
            except RuntimeError:
                continue

    cached = load_history_cache(resolved.display_symbol, max_age_days=14)
    if len(cached) >= 10:
        return cached

    if errors:
        raise RuntimeError("All live sources failed: " + " | ".join(errors))
    raise RuntimeError("Not enough historical data returned for this symbol.")


def merge_live_quote(history: list[PricePoint], live_quote: LiveQuote | None) -> list[PricePoint]:
    if live_quote is None:
        return history

    today = date.today()
    merged = history[:]
    if merged and merged[-1].day == today:
        merged[-1] = PricePoint(day=today, close=live_quote.price)
    elif not merged or merged[-1].day < today:
        merged.append(PricePoint(day=today, close=live_quote.price))
    return merged


def read_history_csv(csv_path: str) -> list[PricePoint]:
    path = Path(csv_path)
    if not path.exists():
        raise RuntimeError(f"CSV file not found: {csv_path}")

    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        columns = {c.lower(): c for c in (reader.fieldnames or [])}

        date_col = columns.get("date")
        close_col = columns.get("close") or columns.get("adj close") or columns.get("adj_close")
        if not date_col or not close_col:
            raise RuntimeError("CSV needs Date and Close (or Adj Close) columns.")

        out: list[PricePoint] = []
        for row in reader:
            day_raw = (row.get(date_col) or "").strip()
            close_raw = (row.get(close_col) or "").strip()
            if not day_raw or not close_raw:
                continue
            try:
                out.append(PricePoint(day=parse_date(day_raw), close=float(close_raw)))
            except (TypeError, ValueError):
                continue

    out.sort(key=lambda p: p.day)
    if len(out) < 20:
        raise RuntimeError("CSV does not contain enough rows (need at least 20).")
    return out


def pct_returns(closes: Iterable[float]) -> list[float]:
    vals = list(closes)
    return [(vals[i] / vals[i - 1]) - 1.0 for i in range(1, len(vals)) if vals[i - 1] > 0]


def mean(values: list[float]) -> float:
    return fmean(values) if values else 0.0


def clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def linear_trend_forecast(closes: list[float], window: int = 90) -> ModelPrediction:
    y = closes[-window:] if len(closes) >= window else closes[:]
    n = len(y)
    x = list(range(n))

    x_mean = mean([float(v) for v in x])
    y_mean = mean(y)

    num = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(n))
    den = sum((x[i] - x_mean) ** 2 for i in range(n))
    slope = num / den if den else 0.0
    pred = y_mean + slope * (n - x_mean)

    last = closes[-1]
    pred_return = (pred / last) - 1.0 if last > 0 else 0.0
    return ModelPrediction("linear_trend", predicted_close=pred, predicted_return=pred_return)


def exp_smoothing_forecast(closes: list[float], alpha: float = MODEL_DEFAULT_ALPHA) -> ModelPrediction:
    alpha = clamp(alpha, 0.01, 0.99)
    level = closes[0]
    for price in closes[1:]:
        level = alpha * price + (1.0 - alpha) * level

    pred = level
    last = closes[-1]
    pred_return = (pred / last) - 1.0 if last > 0 else 0.0
    return ModelPrediction("exp_smoothing", predicted_close=pred, predicted_return=pred_return)


def ar1_return_forecast(closes: list[float], window: int = 120) -> ModelPrediction:
    returns = pct_returns(closes)
    returns = returns[-window:] if len(returns) >= window else returns

    if len(returns) < 5:
        last = closes[-1]
        return ModelPrediction("ar1_return", predicted_close=last, predicted_return=0.0)

    x = returns[:-1]
    y = returns[1:]
    x_mean = mean(x)
    y_mean = mean(y)

    num = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(len(x)))
    den = sum((x[i] - x_mean) ** 2 for i in range(len(x)))
    phi = num / den if den else 0.0
    phi = clamp(phi, -0.98, 0.98)

    mu = mean(returns)
    last_ret = returns[-1]
    pred_return = mu + phi * (last_ret - mu)

    # Keep one-day prediction realistic.
    pred_return = clamp(pred_return, -0.15, 0.15)

    last_close = closes[-1]
    pred_close = last_close * (1.0 + pred_return)
    return ModelPrediction("ar1_return", predicted_close=pred_close, predicted_return=pred_return)


def moving_average_signal_forecast(
    closes: list[float], short_window: int = MODEL_DEFAULT_SHORT_WINDOW, long_window: int = MODEL_DEFAULT_LONG_WINDOW
) -> ModelPrediction:
    short_window = max(3, short_window)
    long_window = max(short_window + 1, long_window)

    if len(closes) < long_window + 2:
        last = closes[-1]
        return ModelPrediction("ma_signal", predicted_close=last, predicted_return=0.0)

    short_ma = mean(closes[-short_window:])
    long_ma = mean(closes[-long_window:])
    signal_strength = (short_ma / long_ma) - 1.0 if long_ma > 0 else 0.0

    returns = pct_returns(closes[-(long_window + 1) :])
    vol = math.sqrt(mean([(r - mean(returns)) ** 2 for r in returns])) if returns else 0.0

    # Direction from MA crossover, magnitude scaled by recent volatility.
    pred_return = clamp(signal_strength * 2.0, -1.0, 1.0) * min(0.05, max(0.005, vol))

    last = closes[-1]
    pred_close = last * (1.0 + pred_return)
    return ModelPrediction("ma_signal", predicted_close=pred_close, predicted_return=pred_return)


def ensemble_predict(closes: list[float], alpha: float, short_window: int, long_window: int) -> tuple[float, float, list[ModelPrediction]]:
    models = [
        linear_trend_forecast(closes),
        exp_smoothing_forecast(closes, alpha=alpha),
        ar1_return_forecast(closes),
        moving_average_signal_forecast(
            closes,
            short_window=short_window,
            long_window=long_window,
        ),
    ]

    weights = {
        "linear_trend": 0.30,
        "exp_smoothing": 0.25,
        "ar1_return": 0.25,
        "ma_signal": 0.20,
    }

    pred_return = sum(weights[m.name] * m.predicted_return for m in models)
    pred_return = clamp(pred_return, -0.20, 0.20)

    last = closes[-1]
    pred_close = last * (1.0 + pred_return)
    return pred_close, pred_return, models


def predict_next_week(
    closes: list[float],
    alpha: float,
    short_window: int,
    long_window: int,
    days: int = 5,
) -> tuple[list[DayForecast], list[ModelPrediction]]:
    simulated = closes[:]
    forecasts: list[DayForecast] = []
    first_day_models: list[ModelPrediction] = []

    for day_idx in range(1, days + 1):
        pred_close, pred_return, models = ensemble_predict(
            simulated,
            alpha=alpha,
            short_window=short_window,
            long_window=long_window,
        )

        if day_idx == 1:
            first_day_models = models

        # Gradually dampen farther-out daily moves.
        damped_return = pred_return * (0.78 ** (day_idx - 1))
        next_close = simulated[-1] * (1.0 + damped_return)

        simulated.append(next_close)
        forecasts.append(
            DayForecast(
                day_index=day_idx,
                predicted_close=next_close,
                predicted_return=damped_return,
            )
        )

    return forecasts, first_day_models


def run_three_pass_cross_check(
    closes: list[float],
    alpha: float,
    short_window: int,
    long_window: int,
) -> tuple[list[CrossCheckPass], CrossCheckPass]:
    """
    Run three analyses with slight parameter variation and choose the strongest.
    """
    param_sets = [
        ("pass_1_base", alpha, short_window, long_window),
        ("pass_2_fast", clamp(alpha * 1.12, 0.01, 0.99), max(4, short_window - 1), max(short_window + 3, long_window - 2)),
        ("pass_3_slow", clamp(alpha * 0.88, 0.01, 0.99), short_window + 1, long_window + 2),
    ]

    passes: list[CrossCheckPass] = []
    for pass_name, p_alpha, p_short, p_long in param_sets:
        week_forecasts, models = predict_next_week(
            closes,
            alpha=p_alpha,
            short_window=p_short,
            long_window=p_long,
        )
        conf = direction_confidence(models)
        week_close = week_forecasts[-1].predicted_close
        week_return = (week_close / closes[-1]) - 1.0 if closes[-1] > 0 else 0.0
        passes.append(
            CrossCheckPass(
                name=pass_name,
                week_forecasts=week_forecasts,
                models=models,
                confidence=conf,
                week_return=week_return,
            )
        )

    # Prefer higher confidence, then larger absolute week move as tie-break.
    best = max(passes, key=lambda p: (p.confidence, abs(p.week_return)))
    return passes, best


def direction_confidence(models: list[ModelPrediction]) -> float:
    signs = [1 if m.predicted_return > 0 else -1 if m.predicted_return < 0 else 0 for m in models]
    up_votes = signs.count(1)
    down_votes = signs.count(-1)
    total = max(1, up_votes + down_votes)
    agreement = max(up_votes, down_votes) / total

    spread = max(m.predicted_return for m in models) - min(m.predicted_return for m in models)
    spread_penalty = clamp(spread / 0.08, 0.0, 1.0)

    confidence = agreement * (1.0 - 0.45 * spread_penalty)
    return clamp(confidence, 0.0, 1.0)


def recommendation(
    week_return: float,
    confidence: float,
    tv_signal: TradingViewSignal | None = None,
) -> tuple[str, str]:
    model_action = "HOLD"
    model_reason = "Signal is weak or mixed; risk of false direction is higher."

    if week_return >= 0.02 and confidence >= 0.55:
        model_action = "BUY"
        model_reason = "Expected upside with moderate model agreement."
    elif week_return <= -0.02 and confidence >= 0.55:
        model_action = "SELL"
        model_reason = "Expected downside with moderate model agreement."

    if tv_signal is None:
        return model_action, model_reason

    tv_buy_tags = {"BUY", "STRONG_BUY"}
    tv_sell_tags = {"SELL", "STRONG_SELL"}
    tv_action = "HOLD"
    if tv_signal.recommendation in tv_buy_tags:
        tv_action = "BUY"
    elif tv_signal.recommendation in tv_sell_tags:
        tv_action = "SELL"

    if model_action == tv_action and model_action != "HOLD":
        return (
            model_action,
            f"Model and TradingView agree on {model_action.lower()} signal.",
        )

    if model_action != "HOLD" and tv_action == "HOLD":
        return model_action, f"Model suggests {model_action.lower()}; TradingView is neutral."

    if model_action == "HOLD" and tv_action != "HOLD":
        return "HOLD", f"TradingView suggests {tv_action.lower()}, but model confidence is not strong."

    if model_action != "HOLD" and tv_action != "HOLD" and model_action != tv_action:
        return "HOLD", "Model and TradingView disagree, so holding is safer."

    return model_action, model_reason


def print_report(
    symbol: str,
    history: list[PricePoint],
    live_quote: LiveQuote | None,
    cross_check_passes: list[CrossCheckPass],
    chosen_pass: CrossCheckPass,
    tv_signal: TradingViewSignal | None,
) -> None:
    last = history[-1]
    week_forecasts = chosen_pass.week_forecasts
    models = chosen_pass.models
    conf = chosen_pass.confidence
    week_close = week_forecasts[-1].predicted_close
    week_return = (week_close / last.close) - 1.0 if last.close > 0 else 0.0
    direction = "UP" if week_return > 0 else "DOWN" if week_return < 0 else "FLAT"
    action, reason = recommendation(week_return, conf, tv_signal=tv_signal)

    print("\nStock Prediction Report (Next 5 Trading Days)")
    print("-" * 72)
    print(f"Symbol:               {symbol}")
    print(f"Last close date:      {last.day.isoformat()}")
    print(f"Last close:           {last.close:.2f}")
    if live_quote is not None:
        print(f"Live price:           {live_quote.price:.2f} ({live_quote.source}, {live_quote.quote_time})")
    else:
        print("Live price:           unavailable (using latest close only)")
    print(f"Predicted week close: {week_close:.2f}")
    print(f"Predicted week return:{week_return * 100:>9.2f}%")
    print(f"Direction (week):     {direction}")
    print(f"Confidence:           {conf * 100:.1f}%")
    print(f"Chosen pass:          {chosen_pass.name}")

    print("\nCross-check (3 passes):")
    for p in cross_check_passes:
        print(
            f"  - {p.name:<12} week_return={p.week_return * 100:>7.2f}% "
            f"confidence={p.confidence * 100:>6.1f}%"
        )

    print("\n5-day forecast path:")
    for f in week_forecasts:
        print(
            f"  Day {f.day_index}: close={f.predicted_close:>10.2f} "
            f"daily_return={f.predicted_return * 100:>7.2f}%"
        )

    print("\nModel breakdown:")
    for m in models:
        print(
            f"  - {m.name:<14} close={m.predicted_close:>10.2f} "
            f"return={m.predicted_return * 100:>7.2f}%"
        )

    print("\nTradingView check:")
    if tv_signal is None:
        print("  unavailable")
    else:
        print(f"  Source:             {tv_signal.source}")
        print(f"  Recommendation:     {tv_signal.recommendation}")
        print(f"  BUY/SELL/NEUTRAL:   {tv_signal.buy_count}/{tv_signal.sell_count}/{tv_signal.neutral_count}")

    print("\nEducational action summary:")
    print(f"  Suggested action:   {action}")
    print(f"  Why:                {reason}")
    print("\nNote: This is an educational forecast, not financial advice.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Predict next week using a multi-model ensemble and live quote merge."
    )
    parser.add_argument(
        "--csv",
        help="Optional local CSV path with Date and Close columns.",
    )
    parser.add_argument(
        "--lookback",
        type=int,
        default=260,
        help="How many most recent daily bars to use (default: 260)",
    )
    parser.add_argument(
        "--alpha",
        type=float,
        default=MODEL_DEFAULT_ALPHA,
        help=f"Exponential smoothing alpha in [0,1] (default: {MODEL_DEFAULT_ALPHA})",
    )
    parser.add_argument(
        "--short-window",
        type=int,
        default=MODEL_DEFAULT_SHORT_WINDOW,
        help=f"Short moving average window (default: {MODEL_DEFAULT_SHORT_WINDOW})",
    )
    parser.add_argument(
        "--long-window",
        type=int,
        default=MODEL_DEFAULT_LONG_WINDOW,
        help=f"Long moving average window (default: {MODEL_DEFAULT_LONG_WINDOW})",
    )
    parser.add_argument(
        "--no-tradingview",
        action="store_true",
        help="Disable TradingView library analysis step.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    raw_input_symbol = prompt_text("Enter company ticker symbol (e.g., AAPL): ")
    resolved = resolve_symbol(raw_input_symbol)
    symbol = resolved.display_symbol
    typed_symbol = normalize_user_symbol(raw_input_symbol)
    if typed_symbol and symbol != typed_symbol:
        print(f"Interpreting '{raw_input_symbol.strip()}' as ticker '{symbol}'.")

    if args.csv:
        try:
            history = read_history_csv(args.csv)
        except RuntimeError as exc:
            raise SystemExit(f"CSV error: {exc}")
        live_quote = None
    else:
        try:
            history = fetch_history(resolved)
            live_quote = fetch_live_quote(resolved.data_symbol)
        except RuntimeError as exc:
            print(f"{exc}")
            print("Live providers may be rate-limited (e.g., Yahoo 429).")
            csv_path = prompt_text("Enter CSV path to continue offline (or press Enter to quit): ").strip()
            if not csv_path:
                raise SystemExit(1)
            try:
                history = read_history_csv(csv_path)
            except RuntimeError as csv_exc:
                raise SystemExit(f"CSV error: {csv_exc}")
            live_quote = None

    history = merge_live_quote(history, live_quote)

    lookback = max(20, args.lookback)
    if len(history) > lookback:
        history = history[-lookback:]

    closes = [p.close for p in history]
    cross_check_passes, chosen_pass = run_three_pass_cross_check(
        closes,
        alpha=args.alpha,
        short_window=args.short_window,
        long_window=args.long_window,
    )

    tv_signal = None
    if not args.no_tradingview:
        tv_signal = fetch_tradingview_signal(resolved)

    print_report(
        symbol=symbol,
        history=history,
        live_quote=live_quote,
        cross_check_passes=cross_check_passes,
        chosen_pass=chosen_pass,
        tv_signal=tv_signal,
    )


if __name__ == "__main__":
    main()
