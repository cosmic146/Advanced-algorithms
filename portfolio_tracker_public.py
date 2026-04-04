# PUBLIC CENSORED MIRROR
# This file is auto-generated from portfolio_tracker.py.
# Do not edit manually. Edit portfolio_tracker.py instead.

# PUBLIC CENSORED MIRROR
# This file is auto-generated from portfolio_tracker.py.
# Do not edit manually. Edit portfolio_tracker.py instead.

#!/usr/bin/env python3
"""
Portfolio Tracker — with REDACTED_HOST integration

Every week:
  1. Run `add <TICKER>` — generates a 5-day prediction and posts the stock
     as a holding to your AI Predictions portfolio on REDACTED_HOST
     so you can watch it live on the website.
  2. Run `review` after ~7 days — fetches actual prices from the website,
     measures how accurate each prediction was, and auto-tunes model params.

Usage
-----
  python portfolio_tracker.py add NVDA        # add ticker, predict, post to site
  python portfolio_tracker.py add Apple       # company names work too
  python portfolio_tracker.py list            # show watchlist + site portfolio URL
  python portfolio_tracker.py review          # verify due predictions, clean site
  python portfolio_tracker.py remove NVDA     # stop tracking, remove from site
  python portfolio_tracker.py history         # full accuracy log
  python portfolio_tracker.py setup           # enter / update auth_token
  python portfolio_tracker.py                 # interactive menu

auth_token is stored in .env (never committed to git).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from statistics import fmean
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# ── Import prediction machinery from stock_predictor.py ────────────────────
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from stock_predictor import (  # noqa: E402
    fetch_history,
    fetch_live_quote,
    fetch_tradingview_signal,
    merge_live_quote,
    prompt_text,
    recommendation,
    resolve_symbol,
    run_three_pass_cross_check,
)

# ── Constants ───────────────────────────────────────────────────────────────
PORTFOLIO_DIR = _HERE / ".portfolio"
PORTFOLIO_FILE = PORTFOLIO_DIR / "portfolio.json"
ENV_FILE = _HERE / ".env"

# Name of the portfolio we maintain on REDACTED_HOST
SITE_PORTFOLIO_NAME = "REDACTED_USER portfolio"
SITE_BASE_URL = "https://REDACTED_HOST"
SITE_API_BASE = f"{SITE_BASE_URL}/api"

REVIEW_AFTER_DAYS = 3      # calendar days
DEFAULT_LOOKBACK = 260
DEFAULT_ALPHA = 0.25
DEFAULT_SHORT_WIN = 10
DEFAULT_LONG_WIN = 40
MIN_REVIEWS_FOR_ADJUST = 3  # minimum reviews before auto-tuning kicks in
ALLOWED_API_HOST = "REDACTED_HOST"
SECURITY_AUDIT_FILE = PORTFOLIO_DIR / "security_audit.log"
PUBLIC_CENSOR_PATTERNS = [
    r"portfolio\.REDACTED_SERVICE\.com",
    r"REDACTED_SERVICE",
]


# ── .env loader ──────────────────────────────────────────────────────────--
def load_env_file(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.exists():
        return result
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            result[key.strip()] = val.strip().strip('"').strip("'")
    return result


def get_auth_token() -> str | None:
    env = load_env_file(ENV_FILE)
    return env.get("REDACTED_SERVICE_auth_token") or None


def _redact_sensitive(text: str) -> str:
    redacted = text
    patterns = [
        r"pt_[a-f0-9]{20,}",
        r"Authorization:\s*Bearer\s+[A-Za-z0-9._\-]+",
        r"access[_-]?token\s*[:=]\s*[\"']?[A-Za-z0-9._\-]{8,}",
        r"secret\s*[:=]\s*[\"']?[^\"'\s]+",
        r"api[_-]?key\s*[:=]\s*[\"']?[A-Za-z0-9._\-]{8,}",
    ]
    for pat in patterns:
        redacted = re.sub(pat, "[REDACTED]", redacted, flags=re.IGNORECASE)
    return redacted


def _audit_security_event(event: str, detail: str = "") -> None:
    PORTFOLIO_DIR.mkdir(parents=True, exist_ok=True)
    if SECURITY_AUDIT_FILE.exists() and not _is_safe_local_file(SECURITY_AUDIT_FILE):
        return
    line = f"{datetime.utcnow().isoformat()}Z | {event} | {_redact_sensitive(detail)}\n"
    with SECURITY_AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(line)
    _ensure_private_file(SECURITY_AUDIT_FILE)


def _validate_auth_token_format(key: str) -> bool:
    return bool(re.fullmatch(r"pt_[a-f0-9]{64}", key.strip()))


def _ensure_private_file(path: Path) -> None:
    if path.exists():
        os.chmod(path, 0o600)


def _is_safe_local_file(path: Path) -> bool:
    """Reject symlinks for sensitive local files."""
    try:
        return not path.is_symlink()
    except OSError:
        return False


def _validate_ticker(ticker: str) -> str:
    t = ticker.strip().upper()
    if not re.fullmatch(r"[A-Z0-9._=\-]{1,20}", t):
        raise RuntimeError("Invalid ticker format")
    return t


def _atomic_write_text(path: Path, content: str) -> None:
    """Write file content atomically with private permissions."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    _ensure_private_file(path)


def _validate_api_base() -> None:
    parsed = urlparse(SITE_API_BASE)
    if parsed.scheme != "https" or parsed.hostname != ALLOWED_API_HOST:
        raise RuntimeError("Security policy violation: API base URL is not allowed")


def save_auth_token(key: str) -> None:
    if not _validate_auth_token_format(key):
        raise ValueError("Invalid auth_token format")
    PORTFOLIO_DIR.mkdir(parents=True, exist_ok=True)
    if ENV_FILE.exists() and not _is_safe_local_file(ENV_FILE):
        raise RuntimeError("Refusing to write auth_token to symlinked .env")
    # Update or create .env preserving other keys
    existing = load_env_file(ENV_FILE)
    existing["REDACTED_SERVICE_auth_token"] = key
    lines = [f'{k}={v}' for k, v in existing.items()]
    _atomic_write_text(ENV_FILE, "\n".join(lines) + "\n")


# ── Auto-sync model defaults across both files and publish ────────────────
def sync_model_defaults_and_publish(new_params: dict) -> None:
    """Rewrite model defaults in both files and push if anything changed."""
    import re
    import subprocess

    predictor_file = _HERE / "stock_predictor.py"
    tracker_file = _HERE / "portfolio_tracker.py"
    if not predictor_file.exists() or not tracker_file.exists():
        print("  Could not find predictor/tracker file — skipping sync.")
        return

    alpha = str(new_params["alpha"])
    short_window = str(new_params["short_window"])
    long_window = str(new_params["long_window"])

    def _replace_const(text: str, pattern: str, value: str) -> str:
        return re.sub(pattern, value, text, flags=re.MULTILINE)

    pred_src_before = predictor_file.read_text(encoding="utf-8")
    pred_src_after = pred_src_before
    pred_src_after = _replace_const(
        pred_src_after,
        r"^(MODEL_DEFAULT_ALPHA\s*:\s*float\s*=\s*).*$",
        rf"\g<1>{alpha}",
    )
    pred_src_after = _replace_const(
        pred_src_after,
        r"^(MODEL_DEFAULT_SHORT_WINDOW\s*:\s*int\s*=\s*).*$",
        rf"\g<1>{short_window}",
    )
    pred_src_after = _replace_const(
        pred_src_after,
        r"^(MODEL_DEFAULT_LONG_WINDOW\s*:\s*int\s*=\s*).*$",
        rf"\g<1>{long_window}",
    )

    tracker_src_before = tracker_file.read_text(encoding="utf-8")
    tracker_src_after = tracker_src_before
    tracker_src_after = _replace_const(
        tracker_src_after,
        r"^(DEFAULT_ALPHA\s*=\s*).*$",
        rf"\g<1>{alpha}",
    )
    tracker_src_after = _replace_const(
        tracker_src_after,
        r"^(DEFAULT_SHORT_WIN\s*=\s*).*$",
        rf"\g<1>{short_window}",
    )
    tracker_src_after = _replace_const(
        tracker_src_after,
        r"^(DEFAULT_LONG_WIN\s*=\s*).*$",
        rf"\g<1>{long_window}",
    )

    changed_files: list[str] = []
    if pred_src_after != pred_src_before:
        predictor_file.write_text(pred_src_after, encoding="utf-8")
        changed_files.append("stock_predictor.py")
    if tracker_src_after != tracker_src_before:
        tracker_file.write_text(tracker_src_after, encoding="utf-8")
        changed_files.append("portfolio_tracker.py")

    if not changed_files:
        print("  Defaults already in sync. No code changes needed.")
        return

    print(
        "  Synced model defaults in "
        + ", ".join(changed_files)
        + f": alpha={alpha} short_window={short_window} long_window={long_window}"
    )

    publish_files = [f for f in changed_files if f == "stock_predictor.py"]
    if "portfolio_tracker.py" in changed_files:
        print("  portfolio_tracker.py updated locally only (not auto-published).")

    if not publish_files:
        print("  No stock_predictor.py change to publish.")
        return

    # Safety gate: refuse auto-publish if common secret patterns are detected.
    secret_patterns = [
        r"pt_[a-f0-9]{20,}",
        r"api[_-]?key\s*=\s*[\"']?[A-Za-z0-9_\-]{8,}",
        r"secret\s*=\s*[\"']?.+",
        r"Authorization:\s*Bearer\s+[A-Za-z0-9._\-]+",
        r"access[_-]?token\s*=\s*[\"']?[A-Za-z0-9._\-]{8,}",
    ]
    for fname in publish_files:
        content = (_HERE / fname).read_text(encoding="utf-8", errors="ignore")
        for pat in secret_patterns:
            if re.search(pat, content, flags=re.IGNORECASE):
                print(f"  Publish blocked: potential secret detected in {fname}.")
                return
        for pat in PUBLIC_CENSOR_PATTERNS:
            if re.search(pat, content, flags=re.IGNORECASE):
                print(f"  Publish blocked: uncensored REDACTED_SERVICE reference found in {fname}.")
                _audit_security_event("publish_blocked_uncensored", fname)
                return

    try:
        msg = (
            f"Auto-sync model defaults: alpha={alpha} "
            f"short={short_window} long={long_window}"
        )
        subprocess.run(["git", "add", *publish_files], cwd=_HERE, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", msg], cwd=_HERE, check=True, capture_output=True)
        subprocess.run(["git", "push", "origin", "main"], cwd=_HERE, check=True, capture_output=True)
        print("  stock_predictor.py committed and pushed to GitHub.")
    except subprocess.CalledProcessError as exc:
        err = exc.stderr.decode().strip() if exc.stderr else str(exc)
        print(f"  Git publish failed: {err}")


# ── REDACTED_HOST API client ───────────────────────────────────-
class REDACTED_SERVICEClient:
    """Thin client for the REDACTED_HOST REST API."""

    def __init__(self, auth_token: str) -> None:
        if not _validate_auth_token_format(auth_token):
            raise RuntimeError("Invalid auth_token format")
        _validate_api_base()
        self._headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
            "User-Agent": "CodeCrackerPredictor/1.0",
            "Accept": "application/json",
        }

    def _request(self, method: str, path: str, body: dict | None = None) -> object:
        allowed_methods = {"GET", "POST", "PATCH", "DELETE"}
        if method not in allowed_methods:
            raise RuntimeError(f"Blocked HTTP method: {method}")
        if not path.startswith("/"):
            raise RuntimeError("Blocked API path: must be absolute")
        if ".." in path:
            raise RuntimeError("Blocked API path traversal attempt")

        url = SITE_API_BASE + path
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = Request(url, data=data, headers=self._headers, method=method)
        for attempt in range(3):
            try:
                with urlopen(req, timeout=20) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                    return json.loads(raw) if raw.strip() else {}
            except HTTPError as exc:
                raw = exc.read().decode("utf-8", errors="replace")
                # 404 on DELETE = already gone, treat as success
                if exc.code == 404 and method == "DELETE":
                    return {}
                clean = _redact_sensitive(raw[:200])
                _audit_security_event("http_error", f"{method} {path} {exc.code} {clean}")
                raise RuntimeError(
                    f"API {method} {path} failed ({exc.code}): {clean}"
                ) from exc
            except URLError as exc:
                if attempt < 2:
                    time.sleep(0.6 * (attempt + 1))
                    continue
                _audit_security_event("network_error", f"{method} {path} {exc.reason}")
                raise RuntimeError(f"Network error calling API: {_redact_sensitive(str(exc.reason))}") from exc

    # -- Portfolios --
    def get_portfolios(self) -> list[dict]:
        result = self._request("GET", "/portfolios")
        return result if isinstance(result, list) else []

    def create_portfolio(self, name: str, currency: str = "USD") -> dict:
        result = self._request("POST", "/portfolios", {"name": name, "currency": currency})
        return result if isinstance(result, dict) else {}

    def get_or_create_portfolio(self, name: str = SITE_PORTFOLIO_NAME, currency: str = "USD") -> dict:
        for p in self.get_portfolios():
            if p.get("name") == name:
                return p
        return self.create_portfolio(name, currency)

    def patch_portfolio(self, portfolio_id: int, data: dict) -> dict:
        result = self._request("PATCH", f"/portfolios/{portfolio_id}", data)
        return result if isinstance(result, dict) else {}

    # -- Holdings --
    def get_holdings(self, portfolio_id: int) -> list[dict]:
        result = self._request("GET", f"/portfolios/{portfolio_id}/holdings")
        return result if isinstance(result, list) else []

    def add_holding(
        self,
        portfolio_id: int,
        ticker: str,
        shares: float,
        avg_cost: float,
    ) -> dict:
        safe_ticker = _validate_ticker(ticker)
        safe_shares = float(shares)
        safe_cost = float(avg_cost)
        if safe_shares <= 0 or safe_shares > 1_000_000:
            raise RuntimeError("Invalid share quantity")
        if safe_cost <= 0 or safe_cost > 10_000_000:
            raise RuntimeError("Invalid average cost")
        result = self._request(
            "POST",
            f"/portfolios/{portfolio_id}/holdings",
            {
                "ticker": safe_ticker,
                "shares": safe_shares,
                "avg_cost": safe_cost,
            },
        )
        return result if isinstance(result, dict) else {}

    def remove_holding(self, portfolio_id: int, ticker: str) -> None:
        """Remove a holding by ticker symbol (per official API docs)."""
        safe_ticker = _validate_ticker(ticker)
        self._request("DELETE", f"/portfolios/{portfolio_id}/holdings/{safe_ticker}")

    def get_dashboard(self, portfolio_id: int) -> dict:
        result = self._request("GET", f"/dashboard/{portfolio_id}")
        return result if isinstance(result, dict) else {}

    def get_performance(self, portfolio_id: int) -> list[dict]:
        result = self._request("GET", f"/dashboard/{portfolio_id}/performance")
        return result if isinstance(result, list) else []

    # -- Stocks --
    def get_stock(self, ticker: str) -> dict:
        safe_ticker = _validate_ticker(ticker)
        result = self._request("GET", f"/stocks/{safe_ticker}")
        return result if isinstance(result, dict) else {}

    def refresh_stock(self, ticker: str) -> None:
        """Force the server to refresh cached stock data."""
        safe_ticker = _validate_ticker(ticker)
        self._request("POST", f"/stocks/{safe_ticker}/refresh")

    def search_stock(self, query: str) -> list[dict]:
        from urllib.parse import quote
        result = self._request("GET", f"/stocks/search?q={quote(query)}")
        return result if isinstance(result, list) else []


def get_client() -> REDACTED_SERVICEClient | None:
    """Return an authenticated client, or None if no auth_token is configured."""
    key = get_auth_token()
    if not key:
        return None
    return REDACTED_SERVICEClient(key)


def _site_prediction_description(entry: dict) -> str:
    """Build a portfolio description string capturing prediction metadata."""
    return (
        f"[AI Pred {entry['predicted_at'][:10]}] "
        f"{entry['predicted_direction']} {entry['predicted_week_return_pct']:+.2f}% | "
        f"Conf:{entry['confidence_pct']:.0f}% | Action:{entry['action']} | "
        f"Review due:{entry['review_due_date']}"
    )


# ── Portfolio I/O ─────────────────────────────────────────────────────────-
def _default_portfolio() -> dict:
    return {
        "model_params": {
            "alpha": DEFAULT_ALPHA,
            "short_window": DEFAULT_SHORT_WIN,
            "long_window": DEFAULT_LONG_WIN,
            "lookback": DEFAULT_LOOKBACK,
        },
        "accuracy_log": [],
        "watchlist": [],
        "site_portfolio_id": None,   # REDACTED_HOST portfolio ID
    }


def load_portfolio() -> dict:
    if not PORTFOLIO_FILE.exists():
        return _default_portfolio()
    if not _is_safe_local_file(PORTFOLIO_FILE):
        _audit_security_event("unsafe_portfolio_file", "Symlinked portfolio.json blocked")
        return _default_portfolio()
    try:
        if PORTFOLIO_FILE.stat().st_size > 2_000_000:
            _audit_security_event("oversized_portfolio_file", "portfolio.json exceeded 2MB")
            return _default_portfolio()
        data = json.loads(PORTFOLIO_FILE.read_text(encoding="utf-8"))
        defaults = _default_portfolio()
        for key, default_val in defaults.items():
            data.setdefault(key, default_val)
        return data
    except (json.JSONDecodeError, OSError):
        return _default_portfolio()


def save_portfolio(data: dict) -> None:
    PORTFOLIO_DIR.mkdir(parents=True, exist_ok=True)
    if PORTFOLIO_FILE.exists() and not _is_safe_local_file(PORTFOLIO_FILE):
        raise RuntimeError("Refusing to write symlinked portfolio.json")
    _atomic_write_text(PORTFOLIO_FILE, json.dumps(data, indent=2))


# ── Accuracy helpers ─────────────────────────────────────────────────────--
def _direction_accuracy(log: list[dict]) -> float:
    reviewed = [e for e in log if e.get("direction_correct") is not None]
    if not reviewed:
        return 0.0
    return sum(1 for e in reviewed if e["direction_correct"]) / len(reviewed)


def _mean_abs_pct_error(log: list[dict]) -> float:
    errors = [abs(e["pct_error"]) for e in log if e.get("pct_error") is not None]
    return fmean(errors) if errors else 0.0


def _up_bias(log: list[dict]) -> int:
    """How many times we predicted UP but actual went DOWN."""
    return sum(
        1 for e in log
        if e.get("predicted_direction") == "UP"
        and e.get("direction_correct") is False
    )


def _down_bias(log: list[dict]) -> int:
    """How many times we predicted DOWN but actual went UP."""
    return sum(
        1 for e in log
        if e.get("predicted_direction") == "DOWN"
        and e.get("direction_correct") is False
    )


def compute_new_params(accuracy_log: list[dict], current: dict) -> dict | None:
    """
    Return adjusted model params if accuracy data warrants a change, else None.
    Looks at the most recent 10 reviewed entries.
    """
    recent = [e for e in accuracy_log if e.get("direction_correct") is not None][-10:]
    if len(recent) < MIN_REVIEWS_FOR_ADJUST:
        return None

    dir_acc = _direction_accuracy(recent)
    mae = _mean_abs_pct_error(recent)
    up_wrong = _up_bias(recent)
    down_wrong = _down_bias(recent)

    alpha = float(current["alpha"])
    short_win = int(current["short_window"])
    long_win = int(current["long_window"])
    changed = False

    if dir_acc < 0.55:
        if up_wrong > down_wrong:
            # Over-optimistic: smooth more, widen short window
            alpha = round(max(0.10, alpha * 0.90), 4)
            short_win = min(20, short_win + 1)
            changed = True
        elif down_wrong > up_wrong:
            # Over-pessimistic: react faster to trends
            alpha = round(min(0.45, alpha * 1.10), 4)
            short_win = max(5, short_win - 1)
            changed = True

    if mae > 5.0 and not changed:
        # Large magnitude errors: soften the model slightly
        alpha = round(max(0.10, alpha * 0.95), 4)
        changed = True

    if not changed:
        return None

    return {
        "alpha": alpha,
        "short_window": short_win,
        "long_window": max(short_win + 5, long_win),
        "lookback": int(current.get("lookback", DEFAULT_LOOKBACK)),
    }


def _describe_adjustments(old: dict, new: dict) -> list[str]:
    lines = []
    if new["alpha"] != old["alpha"]:
        delta = new["alpha"] - old["alpha"]
        direction = "more smoothing (less trend-chasing)" if delta < 0 else "more reactive to recent prices"
        lines.append(f"  alpha          {old['alpha']:.4f} -> {new['alpha']:.4f}  ({direction})")
    if new["short_window"] != old["short_window"]:
        delta = new["short_window"] - old["short_window"]
        direction = "slower crossover signal" if delta > 0 else "faster crossover signal"
        lines.append(f"  short_window   {old['short_window']} -> {new['short_window']}  ({direction})")
    if new["long_window"] != old["long_window"]:
        lines.append(f"  long_window    {old['long_window']} -> {new['long_window']}")
    return lines


# ── Core: run prediction ─────────────────────────────────────────────────--
def run_prediction(symbol_raw: str, params: dict, use_tradingview: bool = True) -> dict:
    """Fetch data, run 3-pass cross-check, return a serialisable result dict."""
    resolved = resolve_symbol(symbol_raw)
    symbol = resolved.display_symbol

    history = fetch_history(resolved)
    live_quote = fetch_live_quote(resolved.data_symbol)
    history = merge_live_quote(history, live_quote)

    lookback = max(20, int(params.get("lookback", DEFAULT_LOOKBACK)))
    if len(history) > lookback:
        history = history[-lookback:]

    closes = [p.close for p in history]
    alpha = float(params.get("alpha", DEFAULT_ALPHA))
    short_win = int(params.get("short_window", DEFAULT_SHORT_WIN))
    long_win = int(params.get("long_window", DEFAULT_LONG_WIN))

    passes, chosen = run_three_pass_cross_check(
        closes, alpha=alpha, short_window=short_win, long_window=long_win
    )

    tv_signal = fetch_tradingview_signal(resolved) if use_tradingview else None
    action, reason = recommendation(chosen.week_return, chosen.confidence, tv_signal=tv_signal)

    week_close = chosen.week_forecasts[-1].predicted_close
    current_price = history[-1].close
    week_return_pct = ((week_close / current_price) - 1.0) * 100 if current_price > 0 else 0.0
    direction = "UP" if week_return_pct > 0 else "DOWN" if week_return_pct < 0 else "FLAT"
    review_due = (date.today() + timedelta(days=REVIEW_AFTER_DAYS)).isoformat()

    return {
        "symbol": symbol,
        "predicted_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "price_at_prediction": round(current_price, 4),
        "predicted_week_close": round(week_close, 4),
        "predicted_week_return_pct": round(week_return_pct, 3),
        "predicted_direction": direction,
        "confidence_pct": round(chosen.confidence * 100, 1),
        "action": action,
        "reason": reason,
        "tv_recommendation": tv_signal.recommendation if tv_signal else None,
        "alpha_used": alpha,
        "short_window_used": short_win,
        "long_window_used": long_win,
        "lookback_used": lookback,
        "day_forecasts": [
            {
                "day_index": f.day_index,
                "predicted_close": round(f.predicted_close, 4),
                "predicted_return_pct": round(f.predicted_return * 100, 3),
            }
            for f in chosen.week_forecasts
        ],
        "review_due_date": review_due,
        "reviewed_at": None,
        "actual_price_at_review": None,
        "actual_week_return_pct": None,
        "direction_correct": None,
        "pct_error": None,
        "site_ticker": None,   # ticker used on REDACTED_HOST
    }


# ── Commands ─────────────────────────────────────────────────────────────--
def cmd_add(symbol_raw: str, use_tradingview: bool = True) -> None:
    data = load_portfolio()
    params = data["model_params"]

    if not symbol_raw or len(symbol_raw.strip()) > 64:
        print("Invalid symbol input.")
        return
    resolved = resolve_symbol(symbol_raw)
    symbol = resolved.display_symbol

    # Check if already tracked.
    existing = [e for e in data["watchlist"] if e["symbol"] == symbol]
    if existing:
        print(f"\n{symbol} is already in your watchlist (predicted {existing[0]['predicted_at'][:10]}).")
        answer = prompt_text("Re-run prediction and update entry? [y/N]: ").strip().lower()
        if answer != "y":
            return
        # Remove old holding from website before replacing
        client = get_client()
        old_site_ticker = existing[0].get("site_ticker")
        if client and old_site_ticker and data.get("site_portfolio_id"):
            try:
                client.remove_holding(data["site_portfolio_id"], old_site_ticker)
            except RuntimeError:
                pass
        data["watchlist"] = [e for e in data["watchlist"] if e["symbol"] != symbol]

    print(f"Fetching data and running prediction for {symbol} ...")
    try:
        entry = run_prediction(symbol_raw, params, use_tradingview=use_tradingview)
    except Exception as exc:
        print(f"Error running prediction: {exc}")
        return

    # ── Post to REDACTED_HOST ─────────────────────────────────
    client = get_client()
    site_url = None
    if client:
        try:
            # Get-or-create the dedicated AI predictions portfolio
            portfolio = client.get_or_create_portfolio()
            pid = portfolio["id"]
            data["site_portfolio_id"] = pid

            # Find the website ticker — use a search to validate it exists
            site_ticker = resolved.data_symbol
            # For futures symbols like GC=F, SI=F, try searching the display name
            if "=" in site_ticker or site_ticker.endswith("-USD"):
                search_results = client.search_stock(symbol)
                if search_results:
                    site_ticker = search_results[0]["ticker"]

            holding = client.add_holding(
                pid,
                ticker=site_ticker,
                shares=1,
                avg_cost=entry["price_at_prediction"],
            )
            if holding.get("ticker"):
                entry["site_ticker"] = holding["ticker"]
                site_url = f"{SITE_BASE_URL}/portfolios/{pid}"
                print(f"Posted to REDACTED_HOST (ticker {holding['ticker']})")
        except RuntimeError as exc:
            print(f"Website sync skipped: {exc}")
    else:
        print("Tip: run 'setup' to connect REDACTED_HOST for live tracking.")

    data["watchlist"].append(entry)
    save_portfolio(data)

    print(f"\n{'=' * 60}")
    print(f"  Added to portfolio:  {symbol}")
    print(f"  Price now:           ${entry['price_at_prediction']:.2f}")
    print(f"  Predicted week end:  ${entry['predicted_week_close']:.2f}  "
          f"({entry['predicted_week_return_pct']:+.2f}%)")
    print(f"  Direction:           {entry['predicted_direction']}")
    print(f"  Confidence:          {entry['confidence_pct']:.1f}%")
    print(f"  Action:              {entry['action']}")
    print(f"  Reason:              {entry['reason']}")
    if entry["tv_recommendation"]:
        print(f"  TradingView signal:  {entry['tv_recommendation']}")
    print(f"  5-day forecast path:")
    for f in entry["day_forecasts"]:
        print(f"    Day {f['day_index']}: ${f['predicted_close']:.2f}  ({f['predicted_return_pct']:+.2f}%)")
    print(f"  Review due:          {entry['review_due_date']}")
    if site_url:
        print(f"  Live on website:     {site_url}")
    print(f"{'=' * 60}")


def cmd_list() -> None:
    data = load_portfolio()
    watchlist = data["watchlist"]
    today_str = date.today().isoformat()
    pid = data.get("site_portfolio_id")

    if not watchlist:
        print("Your watchlist is empty. Use 'add <TICKER>' to start tracking.")
        if pid:
            print(f"Live portfolio: {SITE_BASE_URL}/portfolios/{pid}")
        return

    # Try to enrich with live pnl + dashboard stats from website
    live_pnl: dict[str, float] = {}
    client = get_client()
    if client and pid:
        try:
            holdings = client.get_holdings(pid)
            for h in holdings:
                live_pnl[h["ticker"]] = h.get("pnl_pct", 0.0)
        except RuntimeError:
            pass
        try:
            dash = client.get_dashboard(pid)
            total_val = dash.get("total_value")
            total_pnl = dash.get("total_pnl_pct")
            if total_val is not None:
                print(f"Portfolio value: {total_val:,.2f}  |  Overall PnL: {total_pnl:+.2f}%" if total_pnl is not None else f"Portfolio value: {total_val:,.2f}")
        except RuntimeError:
            pass

    print(f"\n{'Symbol':<10} {'Pred Date':>10} {'Pred%':>8} {'Dir':^5} "
          f"{'Conf%':>6} {'Action':^7} {'Live PnL%':>10} {'Review Due':>12} {'Status':>10}")
    print("-" * 88)

    for e in watchlist:
        if e.get("reviewed_at"):
            status = "REVIEWED"
        elif e["review_due_date"] <= today_str:
            status = "DUE NOW"
        else:
            status = "PENDING"

        live_str = ""
        sym = e["symbol"]
        if sym in live_pnl:
            pnl = live_pnl[sym]
            live_str = f"{pnl:+.2f}%"

        print(
            f"{sym:<10} "
            f"{e['predicted_at'][:10]:>10} "
            f"{e['predicted_week_return_pct']:>+8.2f}% "
            f"{e['predicted_direction']:^5} "
            f"{e['confidence_pct']:>6.1f}% "
            f"{e['action']:^7} "
            f"{live_str:>10} "
            f"{e['review_due_date']:>12} "
            f"{status:>10}"
        )

    # Summary line.
    log = data.get("accuracy_log", [])
    reviewed = [e for e in log if e.get("direction_correct") is not None]
    if reviewed:
        dir_acc = _direction_accuracy(reviewed) * 100
        mae = _mean_abs_pct_error(reviewed)
        print(f"\nOverall: {dir_acc:.0f}% direction correct | mean error: {mae:.2f}% | {len(reviewed)} reviews")

    p = data["model_params"]
    print(f"Model params: alpha={p['alpha']}  short_window={p['short_window']}  long_window={p['long_window']}")

    if pid:
        print(f"\nLive portfolio: {SITE_BASE_URL}/portfolios/{pid}")
    elif not get_auth_token():
        print("\nTip: run 'setup' to connect REDACTED_HOST for live tracking.")


def _generate_weekly_summary(accuracy_log: list[dict]) -> tuple[str, str]:
    """Generate weekly summary of all predictions in past week.
    
    Returns (summary_text, summary_html) for display and portfolio notes.
    """
    today = date.today()
    week_ago = today - timedelta(days=7)
    week_reviews = [
        e for e in accuracy_log 
        if e.get("direction_correct") is not None 
        and e.get("reviewed_at", "")[:10] >= week_ago.isoformat()
    ]
    
    if not week_reviews:
        return "", ""
    
    correct = sum(1 for e in week_reviews if e.get("direction_correct"))
    total = len(week_reviews)
    dir_acc = (correct / total * 100) if total > 0 else 0
    mae = _mean_abs_pct_error(week_reviews)
    
    summary_lines = [
        f"Weekly Summary — {week_ago.isoformat()} to {today.isoformat()}",
        f"Predictions reviewed: {total}",
        f"Direction accuracy: {dir_acc:.0f}% ({correct}/{total})",
        f"Mean absolute error: {mae:.2f}%",
        "",
        "Predictions:",
    ]
    
    for e in week_reviews:
        result = "✓ CORRECT" if e.get("direction_correct") else "✗ WRONG"
        line = f"  {e['symbol']:6} {e.get('predicted_at', '')[:10]} → {result} | pred: {e.get('predicted_return_pct', 0):+.2f}% actual: {e.get('actual_return_pct', 0):+.2f}%"
        summary_lines.append(line)
    
    return "\n".join(summary_lines), "\n".join(summary_lines)


def cmd_review(use_tradingview: bool = True) -> None:
    data = load_portfolio()
    today_str = date.today().isoformat()
    pid = data.get("site_portfolio_id")

    due = [
        e for e in data["watchlist"]
        if e.get("reviewed_at") is None and e["review_due_date"] <= today_str
    ]

    if not due:
        print("No predictions are due for review yet.")
        pending = [e for e in data["watchlist"] if e.get("reviewed_at") is None]
        if pending:
            next_due = min(pending, key=lambda e: e["review_due_date"])
            print(f"Next review: {next_due['symbol']} on {next_due['review_due_date']}.")
        if pid:
            print(f"Live portfolio: {SITE_BASE_URL}/portfolios/{pid}")
        return

    print(f"Reviewing {len(due)} prediction(s) now...\n")

    # Pre-fetch all live holdings from website for batch price lookup
    client = get_client()
    site_holdings_by_ticker: dict[str, dict] = {}
    if client and pid:
        try:
            # Refresh stock data before reviewing so prices are current
            for e in due:
                st = e.get("site_ticker") or e["symbol"]
                try:
                    client.refresh_stock(st)
                except RuntimeError:
                    pass
            holdings = client.get_holdings(pid)
            for h in holdings:
                site_holdings_by_ticker[h["ticker"]] = h
        except RuntimeError as exc:
            print(f"Warning: could not fetch site holdings ({exc})")

    any_reviewed = False

    for entry in due:
        symbol = entry["symbol"]
        print(f"{'─' * 60}")
        print(f"  Reviewing: {symbol}")
        print(f"  Predicted on:      {entry['predicted_at'][:10]}")
        print(f"  Price at pred:     ${entry['price_at_prediction']:.2f}")
        print(f"  Predicted return:  {entry['predicted_week_return_pct']:+.2f}%  ({entry['predicted_direction']})")
        print(f"  Predicted action:  {entry['action']}")

        # ── Get actual price: prefer website holding data, fall back to live quote ──
        actual_price: float | None = None
        site_ticker_key = entry.get("site_ticker") or symbol
        site_holding = site_holdings_by_ticker.get(site_ticker_key)
        if site_holding:
            actual_price = site_holding.get("current_price_native") or site_holding.get("current_price")
            print(f"  Source:            REDACTED_HOST (live)")

        if actual_price is None:
            try:
                resolved = resolve_symbol(symbol)
                live_q = fetch_live_quote(resolved.data_symbol)
                actual_price = live_q.price if live_q else None
                if actual_price:
                    print(f"  Source:            local live quote")
            except Exception:
                pass

        if actual_price is None:
            print(f"  Could not fetch current price for {symbol}. Skipping.")
            continue

        base_price = entry["price_at_prediction"]
        actual_return_pct = ((actual_price / base_price) - 1.0) * 100 if base_price > 0 else 0.0
        actual_direction = "UP" if actual_return_pct > 0.2 else "DOWN" if actual_return_pct < -0.2 else "FLAT"
        predicted_direction = entry["predicted_direction"]

        if predicted_direction == "FLAT":
            direction_correct = abs(actual_return_pct) < 1.0
        else:
            direction_correct = predicted_direction == actual_direction

        pct_error = actual_return_pct - entry["predicted_week_return_pct"]

        # Update the watchlist entry.
        entry["reviewed_at"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        entry["actual_price_at_review"] = round(actual_price, 4)
        entry["actual_week_return_pct"] = round(actual_return_pct, 3)
        entry["direction_correct"] = direction_correct
        entry["pct_error"] = round(pct_error, 3)

        # Append to the accuracy log.
        data["accuracy_log"].append({
            "symbol": symbol,
            "predicted_at": entry["predicted_at"][:10],
            "reviewed_at": entry["reviewed_at"][:10],
            "predicted_direction": predicted_direction,
            "actual_direction": actual_direction,
            "predicted_return_pct": entry["predicted_week_return_pct"],
            "actual_return_pct": round(actual_return_pct, 3),
            "direction_correct": direction_correct,
            "pct_error": round(pct_error, 3),
            "confidence_pct": entry["confidence_pct"],
        })

        result_label = "CORRECT" if direction_correct else "WRONG"
        result_marker = "[OK]" if direction_correct else "[XX]"
        print(f"  Actual price now:  ${actual_price:.2f}")
        print(f"  Actual return:     {actual_return_pct:+.2f}%  ({actual_direction})")
        print(f"  Direction:         {result_marker} {result_label}")
        print(f"  Error magnitude:   {abs(pct_error):.2f}% off prediction")

        # Explain mis-predictions
        if not direction_correct:
            if predicted_direction == "UP" and actual_direction == "DOWN":
                print("  What went wrong:   Model was too optimistic — predicted uptrend but price fell.")
                print("                     Possible causes: sudden news, market sell-off, over-smoothed signal.")
            elif predicted_direction == "DOWN" and actual_direction == "UP":
                print("  What went wrong:   Model was too pessimistic — predicted downtrend but price rose.")
                print("                     Possible causes: earnings beat, sector rally, short-covering.")

        # ── Remove the holding from the website now that review is done ────
        if client and pid:
            st = entry.get("site_ticker") or symbol
            try:
                client.remove_holding(pid, st)
                result_tag = "CORRECT" if direction_correct else "WRONG"
                print(f"  Removed from site:  {st} ({result_tag})")
            except RuntimeError as exc:
                print(f"  Website removal skipped: {exc}")

        print()
        any_reviewed = True

    if any_reviewed:
        # Check if model adjustment is recommended.
        new_params = compute_new_params(data["accuracy_log"], data["model_params"])
        print("─" * 60)
        if new_params:
            old = data["model_params"]
            dir_acc = _direction_accuracy(
                [e for e in data["accuracy_log"] if e.get("direction_correct") is not None][-10:]
            ) * 100
            print(f"Model auto-adjusted  (recent direction accuracy: {dir_acc:.0f}%):")
            for line in _describe_adjustments(old, new_params):
                print(line)
            data["model_params"] = new_params
            print("Parameters updated. Future predictions will use the new values.")
            sync_model_defaults_and_publish(new_params)
            if client and pid:
                try:
                    p = new_params
                    client.patch_portfolio(pid, {
                        "description": (
                            f"Auto-tuned {date.today().isoformat()} | "
                            f"alpha={p['alpha']} short={p['short_window']} long={p['long_window']} | "
                            f"Dir acc: {dir_acc:.0f}%"
                        )
                    })
                except RuntimeError:
                    pass
        else:
            reviewed_all = [e for e in data["accuracy_log"] if e.get("direction_correct") is not None]
            if reviewed_all:
                dir_acc = _direction_accuracy(reviewed_all) * 100
                mae = _mean_abs_pct_error(reviewed_all)
                print(f"Model is performing acceptably: {dir_acc:.0f}% direction correct | mean error: {mae:.2f}%")
            if len(reviewed_all) < MIN_REVIEWS_FOR_ADJUST:
                remaining = MIN_REVIEWS_FOR_ADJUST - len(reviewed_all)
                print(f"Need {remaining} more review(s) before auto-tuning becomes active.")

        # ── Generate and display weekly summary, then update portfolio notes ────
        print()
        weekly_summary, _ = _generate_weekly_summary(data["accuracy_log"])
        if weekly_summary:
            print("─" * 60)
            print(weekly_summary)
            print("─" * 60)
        
        save_portfolio(data)
        print("Portfolio saved.")
        
        # Update portfolio notes on website with summary
        if client and pid:
            try:
                p = data["model_params"]
                reviewed_all = [e for e in data["accuracy_log"] if e.get("direction_correct") is not None]
                if reviewed_all:
                    dir_acc = _direction_accuracy(reviewed_all) * 100
                    desc = (
                        f"AI Predictions — Last tuned: {date.today().isoformat()}\n"
                        f"Accuracy: {dir_acc:.0f}% | Model: alpha={p['alpha']} short={p['short_window']} long={p['long_window']}\n"
                        f"{weekly_summary}"
                    )
                    client.patch_portfolio(pid, {"description": desc})
                    print("Portfolio notes updated on website.")
            except RuntimeError as e:
                print(f"Note: could not update portfolio notes ({e})")
        
def cmd_remove(symbol_raw: str) -> None:
    data = load_portfolio()
    if not symbol_raw or len(symbol_raw.strip()) > 64:
        print("Invalid symbol input.")
        return
    resolved = resolve_symbol(symbol_raw)
    symbol = resolved.display_symbol

    before = len(data["watchlist"])
    removed = [e for e in data["watchlist"] if e["symbol"] == symbol]
    data["watchlist"] = [e for e in data["watchlist"] if e["symbol"] != symbol]
    after = len(data["watchlist"])

    if before == after:
        print(f"{symbol} is not in your watchlist.")
        return

    # Remove from website too
    client = get_client()
    pid = data.get("site_portfolio_id")
    if client and pid and removed:
        st = removed[0].get("site_ticker") or symbol
        try:
            client.remove_holding(pid, st)
            print(f"Removed {st} from REDACTED_HOST.")
        except RuntimeError as exc:
            print(f"Website removal skipped: {exc})")


    save_portfolio(data)
    print(f"Removed {symbol} from watchlist.")


def cmd_setup() -> None:
    """Interactively set or update the REDACTED_HOST auth_token."""
    current = get_auth_token()
    if current:
        masked = current[:8] + "..." + current[-6:]
        print(f"Current auth_token: {masked}")
        answer = prompt_text("Update it? [y/N]: ").strip().lower()
        if answer != "y":
            return

    print(f"\nPaste your auth_token from {SITE_BASE_URL}")
    key = prompt_text("auth_token: ").strip()
    if not key:
        print("No key entered. Cancelled.")
        return
    if not _validate_auth_token_format(key):
        print("Invalid key format. Expected: pt_ followed by 64 lowercase hex chars.")
        _audit_security_event("invalid_key_format", "User entered malformed auth_token")
        return

    # Quick validation
    print("Validating key...")
    try:
        client = REDACTED_SERVICEClient(key)
        portfolios = client.get_portfolios()
        save_auth_token(key)
        print(f"Key saved to .env — authenticated ({len(portfolios)} portfolios found).")
        print(f"Next time you run 'add', predictions will be posted to {SITE_BASE_URL}")
    except RuntimeError as exc:
        print(f"Key validation failed: {exc}")
        print("Key NOT saved. Check the key and try again.")


def cmd_history() -> None:
    data = load_portfolio()
    log = data.get("accuracy_log", [])

    if not log:
        print("No review history yet. After a week, run 'review' to see results.")
        return

    reviewed = [e for e in log if e.get("direction_correct") is not None]
    dir_acc = _direction_accuracy(reviewed) * 100
    mae = _mean_abs_pct_error(reviewed)

    # Show most recent 20, newest first.
    display = list(reversed(log[-20:]))

    print(f"\n{'Symbol':<10} {'Pred Date':>10} {'Pred%':>8} {'Actual%':>9} "
          f"{'Error':>7} {'Dir':^5} {'Result':>9}")
    print("-" * 68)

    for e in display:
        pred_dir_arrow = "^" if e.get("predicted_direction") == "UP" else "v" if e.get("predicted_direction") == "DOWN" else "-"
        result_str = "OK" if e.get("direction_correct") else "WRONG"
        print(
            f"{e['symbol']:<10} "
            f"{e.get('predicted_at', '')[:10]:>10} "
            f"{e.get('predicted_return_pct', 0):>+8.2f}% "
            f"{e.get('actual_return_pct', 0):>+9.2f}% "
            f"{e.get('pct_error', 0):>+7.2f}% "
            f"{pred_dir_arrow:^5} "
            f"{result_str:>9}"
        )

    print("-" * 68)
    print(f"Direction accuracy: {dir_acc:.0f}%  |  Mean absolute error: {mae:.2f}%  |  Total reviews: {len(reviewed)}")

    p = data["model_params"]
    print(f"\nCurrent model params:  alpha={p['alpha']}  short_window={p['short_window']}  long_window={p['long_window']}")


# ── Interactive menu ──────────────────────────────────────────────────────-
def cmd_interactive() -> None:
    print("\nPortfolio Tracker")
    print("Commands: add <TICKER>, list, review, remove <TICKER>, history, setup, quit")
    pid = load_portfolio().get("site_portfolio_id")
    if pid:
        print(f"Live portfolio: {SITE_BASE_URL}/portfolios/{pid}")

    while True:
        try:
            raw = prompt_text("\n> ").strip()
        except SystemExit:
            break

        if not raw:
            continue

        parts = raw.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("quit", "exit", "q"):
            break
        elif cmd == "add":
            if not arg:
                arg = prompt_text("Ticker or company name: ").strip()
            if arg:
                cmd_add(arg)
        elif cmd == "list":
            cmd_list()
        elif cmd == "review":
            cmd_review()
        elif cmd in ("remove", "rm", "delete"):
            if not arg:
                arg = prompt_text("Ticker to remove: ").strip()
            if arg:
                cmd_remove(arg)
        elif cmd in ("history", "log"):
            cmd_history()
        elif cmd == "setup":
            cmd_setup()
        elif cmd == "help":
            print("  add <TICKER>         — predict & post to REDACTED_HOST")
            print("  list                 — show watchlist with live PnL from website")
            print("  review               — check due predictions, auto-tune model")
            print("  remove <TICKER>      — remove from watchlist and website")
            print("  history              — show full accuracy log")
            print("  setup                — set / update REDACTED_HOST auth_token")
            print("  quit                 — exit")
        else:
            print(f"Unknown command '{cmd}'. Type 'help' for available commands.")


# ── Entry point ───────────────────────────────────────────────────────────-
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Portfolio tracker — monitor stocks and verify predictions over time.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python portfolio_tracker.py add AAPL\n"
            "  python portfolio_tracker.py add 'Nvidia'\n"
            "  python portfolio_tracker.py list\n"
            "  python portfolio_tracker.py review\n"
            "  python portfolio_tracker.py history\n"
        ),
    )
    sub = parser.add_subparsers(dest="command")

    add_p = sub.add_parser("add", help="Add a ticker and save a 5-day prediction.")
    add_p.add_argument("ticker", help="Ticker symbol or company name (e.g. AAPL or Apple)")
    add_p.add_argument("--no-tradingview", action="store_true", help="Skip TradingView analysis.")

    sub.add_parser("list", help="Show the watchlist with live PnL from REDACTED_HOST.")
    sub.add_parser("review", help="Review due predictions, clean up website, auto-tune model.")

    rm_p = sub.add_parser("remove", help="Remove a ticker from watchlist and website portfolio.")
    rm_p.add_argument("ticker")

    sub.add_parser("history", help="Show the full accuracy log.")
    sub.add_parser("setup", help="Set or update the REDACTED_HOST auth_token.")

    args = parser.parse_args()

    if args.command == "add":
        cmd_add(args.ticker, use_tradingview=not args.no_tradingview)
    elif args.command == "list":
        cmd_list()
    elif args.command == "review":
        cmd_review()
    elif args.command == "remove":
        cmd_remove(args.ticker)
    elif args.command == "history":
        cmd_history()
    elif args.command == "setup":
        cmd_setup()
    else:
        cmd_interactive()


if __name__ == "__main__":
    main()
