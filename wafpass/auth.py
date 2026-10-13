"""Zero-knowledge credential store for `wafpass login` sessions.

Credentials file: ~/.wafpass/credentials.json  (chmod 600)
Only the JWT tokens are stored — the password is never written to disk.
"""
from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx

_CREDS_FILE = Path.home() / ".wafpass" / "credentials.json"


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class Credentials:
    server_url: str        # base URL, e.g. https://wafpass.example.com
    access_token: str      # short-lived JWT (HS256)
    refresh_token: str     # opaque long-lived token
    username: str
    role: str
    expires_at: str        # ISO-8601 UTC — from JWT `exp` claim

    def is_expired(self) -> bool:
        try:
            exp = datetime.fromisoformat(self.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            # Treat as expired 30 s early to avoid race conditions
            return (datetime.now(timezone.utc) - exp).total_seconds() > -30
        except Exception:
            return True

    def bearer(self) -> str:
        return f"Bearer {self.access_token}"


# ── Storage helpers ───────────────────────────────────────────────────────────

def save(creds: Credentials) -> None:
    _CREDS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CREDS_FILE.write_text(json.dumps(asdict(creds), indent=2))
    try:
        _CREDS_FILE.chmod(0o600)
    except OSError:
        pass


def load() -> Credentials | None:
    if not _CREDS_FILE.exists():
        return None
    try:
        return Credentials(**json.loads(_CREDS_FILE.read_text()))
    except Exception:
        return None


def clear() -> None:
    try:
        _CREDS_FILE.unlink(missing_ok=True)
    except OSError:
        pass


# ── JWT helpers ───────────────────────────────────────────────────────────────

def _exp_from_jwt(token: str) -> str:
    """Extract `exp` claim from a JWT without verifying signature. Returns ISO-8601 UTC."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("not a JWT")
        padding = "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + padding))
        exp_ts = payload["exp"]
        return datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat()
    except Exception:
        # Fall back to 1 hour from now
        from datetime import timedelta
        return (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()


# ── Network helpers ───────────────────────────────────────────────────────────

def do_login(server_url: str, username: str, password: str) -> Credentials:
    """POST /api/v1/auth/login and return stored credentials. Raises httpx errors on failure."""
    url = f"{server_url.rstrip('/')}/api/v1/auth/login"
    resp = httpx.post(
        url,
        json={"username": username, "password": password},
        headers={"Content-Type": "application/json"},
        timeout=15,
        follow_redirects=True,
    )
    resp.raise_for_status()
    data = resp.json()
    creds = Credentials(
        server_url=server_url.rstrip("/"),
        access_token=data["access_token"],
        refresh_token=data["refresh_token"],
        username=data["user"]["username"],
        role=data["user"]["role"],
        expires_at=_exp_from_jwt(data["access_token"]),
    )
    save(creds)
    return creds


def do_refresh(creds: Credentials) -> Credentials | None:
    """Exchange refresh token for a new access token. Returns updated Credentials or None."""
    try:
        url = f"{creds.server_url.rstrip('/')}/api/v1/auth/refresh"
        resp = httpx.post(
            url,
            json={"refresh_token": creds.refresh_token},
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        updated = Credentials(
            server_url=creds.server_url,
            access_token=data["access_token"],
            refresh_token=creds.refresh_token,
            username=creds.username,
            role=creds.role,
            expires_at=_exp_from_jwt(data["access_token"]),
        )
        save(updated)
        return updated
    except Exception:
        return None


def do_logout(creds: Credentials) -> None:
    """POST /api/v1/auth/logout to revoke the refresh token on the server."""
    try:
        httpx.post(
            f"{creds.server_url.rstrip('/')}/api/v1/auth/logout",
            json={"refresh_token": creds.refresh_token},
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
    except Exception:
        pass  # Best-effort; local session is cleared regardless


# ── Public API ────────────────────────────────────────────────────────────────

def get_valid_credentials() -> Credentials | None:
    """Load stored credentials, auto-refreshing if the access token is expired.

    Returns None if not logged in or if refresh also fails (re-login required).
    """
    creds = load()
    if creds is None:
        return None
    if creds.is_expired():
        creds = do_refresh(creds)
    return creds


def resolve_push_target(push_arg: str | None) -> tuple[str | None, dict[str, str]]:
    """Resolve the push URL and auth headers for a --push argument.

    push_arg values:
      None / ""  →  no push
      "@"        →  use stored server URL + /api/v1/runs with Bearer token
      any URL    →  use that URL; inject Bearer token if stored creds match

    Returns (url_or_none, extra_headers).
    """
    if not push_arg:
        return None, {}

    creds = get_valid_credentials()

    if push_arg == "@":
        if creds is None:
            return None, {}          # caller must handle the error
        return f"{creds.server_url}/api/v1/runs", {"Authorization": creds.bearer()}

    # Explicit URL — inject Bearer if we have creds for that server
    url = push_arg
    headers: dict[str, str] = {}
    if creds and url.startswith(creds.server_url):
        headers["Authorization"] = creds.bearer()
    return url, headers
