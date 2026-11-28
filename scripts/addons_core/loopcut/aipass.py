"""AI Pass wallet authorization for Loopcut's desktop provider."""

import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

from . import chatgpt_auth, credentials

ORIGIN = "https://aipass.one"
API_BASE = ORIGIN + "/v1"
PROVIDER_URL = "aipass://wallet"
# Loopcut maintainers set this to their public OAuth client ID for packaged builds.
PUBLIC_CLIENT_ID = ""
PORT = 43129
CALLBACK = f"http://127.0.0.1:{PORT}/auth/callback"
_SCOPE = "api:access"
_SESSION = "aipass_wallet"


class WalletError(RuntimeError):
    def __init__(self, message: str, code: str = ""):
        super().__init__(message)
        self.code = code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def client_id() -> str:
    return os.environ.get("LOOPCUT_AIPASS_CLIENT_ID", "").strip() or PUBLIC_CLIENT_ID


def _request(path: str, body: dict | None = None, *, form: bool = False) -> dict:
    data = None
    if body is not None:
        data = (urllib.parse.urlencode(body) if form else json.dumps(body)).encode()
    headers = {"Accept": "application/json", "User-Agent": "Loopcut",
               "Content-Type": "application/x-www-form-urlencoded" if form else "application/json"}
    request = urllib.request.Request(ORIGIN + path, data=data, headers=headers)
    try:
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=15) as response:
            result = json.load(response) if response.status != 204 and not form else {}
    except urllib.error.HTTPError as ex:
        with ex:
            try:
                error = json.loads(ex.read(8192)).get("error")
            except (ValueError, AttributeError):
                error = None
        if error in ("invalid_grant", "invalid_token"):
            raise WalletError("Your AI Pass connection expired. Connect your wallet again.", error) from None
        raise WalletError(f"AI Pass returned HTTP {ex.code}. Try again.") from None
    except (OSError, ValueError):
        raise WalletError("Couldn't reach AI Pass or read its reply. Try again.") from None
    if not isinstance(result, dict):
        raise WalletError("AI Pass returned an unexpected reply.")
    return result


def _record(data: dict, identity: str) -> dict:
    record = data.get(_SESSION)
    if (identity and isinstance(record, dict) and record.get("client_id") == identity
            and all(isinstance(record.get(key), str) and record[key] for key in ("refresh_token", "connection_id"))):
        return record
    return {}


def connection_id() -> str:
    return _record(credentials._read(), client_id()).get("connection_id", "")


def connected() -> bool:
    return bool(connection_id())


def _session(tokens: dict, identity: str, connection: str = "") -> dict:
    access, refresh = tokens.get("access_token"), tokens.get("refresh_token")
    scope = tokens.get("scope")
    expires = tokens.get("expires_in")
    if (not isinstance(access, str) or not access or not isinstance(refresh, str) or not refresh
            or not isinstance(expires, int) or expires <= 0 or not isinstance(scope, str)
            or _SCOPE not in scope.split() or str(tokens.get("token_type", "")).lower() != "bearer"):
        raise WalletError("AI Pass didn't return a usable wallet connection.")
    return {"client_id": identity, "access_token": access, "refresh_token": refresh,
            "expires_at": time.time() + expires, "connection_id": connection or secrets.token_urlsafe(16)}


def connect(open_browser, cancelled) -> None:
    identity = client_id()
    if not identity:
        raise WalletError("This build needs a public AI Pass client ID.")
    if cancelled():
        return
    try:
        callback = chatgpt_auth._CallbackServer(PORT, allow_fallback=False)
    except OSError:
        raise WalletError(f"Port {PORT} is in use. Close the other application and try again.") from None
    verifier, challenge = chatgpt_auth.pkce_pair()
    state = secrets.token_urlsafe(32)
    callback.expected_state = state
    params = {"client_id": identity, "response_type": "code", "redirect_uri": CALLBACK, "scope": _SCOPE,
              "state": state, "code_challenge": challenge, "code_challenge_method": "S256"}
    try:
        open_browser(f"{ORIGIN}/oauth2/authorize?{urllib.parse.urlencode(params)}")
        reply = callback.wait(time.monotonic() + 300, cancelled)
    except chatgpt_auth.ChatGPTAuthError as ex:
        if ex.code == "cancelled":
            return
        raise WalletError("AI Pass sign-in timed out. Try connecting again.") from None
    finally:
        callback.close()
    if cancelled():
        return
    if reply.get("error") or not reply.get("code"):
        raise WalletError("AI Pass wallet access was declined or cancelled.")
    tokens = _request("/oauth2/token", {"grantType": "authorization_code", "clientId": identity,
                                        "code": reply["code"], "codeVerifier": verifier, "redirectUri": CALLBACK})
    record = _session(tokens, identity)
    with credentials._transaction() as target:
        if not cancelled():
            data = credentials._read(target=target, strict=True)
            data[_SESSION] = record
            credentials._write(data, target=target)
            return
    _revoke(record)


def authorization(connection: str) -> tuple[str, str]:
    """Refresh the turn's selected wallet atomically. Stop if another wallet was connected mid-turn."""
    identity = client_id()
    with credentials._transaction() as target:
        data = credentials._read(target=target, strict=True)
        record = _record(data, identity)
        if not record:
            raise WalletError("Connect your wallet in Preferences > Add-ons > Loopcut.")
        if record["connection_id"] != connection:
            raise WalletError("The AI Pass wallet changed. Start a new turn to use it.")
        token = record.get("access_token")
        expires = record.get("expires_at", 0)
        if isinstance(token, str) and token and isinstance(expires, (int, float)) and expires > time.time() + 30:
            return identity, token
        try:
            tokens = _request("/oauth2/token", {"grantType": "refresh_token", "clientId": identity,
                                                "refreshToken": record["refresh_token"]})
        except WalletError as ex:
            if ex.code in ("invalid_grant", "invalid_token"):
                data.pop(_SESSION, None)
                credentials._write(data, target=target)
            raise
        record = _session(tokens, identity, connection)
        data[_SESSION] = record
        credentials._write(data, target=target)
        return identity, record["access_token"]


def _revoke(record: dict) -> None:
    failed = False
    for name in ("refresh_token", "access_token"):
        if record.get(name):
            try:
                _request("/oauth2/revoke", {"token": record[name], "client_id": record["client_id"]}, form=True)
            except WalletError as ex:
                failed = failed or ex.code != "invalid_token"
    if failed:
        raise WalletError("Disconnected on this computer. Check connected apps in AI Pass to revoke remote access.")


def disconnect() -> None:
    with credentials._transaction() as target:
        data = credentials._read(target=target, strict=True)
        record = _record(data, client_id())
        if not record:
            return
        data.pop(_SESSION, None)
        credentials._write(data, target=target)
    _revoke(record)


def list_models() -> list[str]:
    catalog = _request("/v1/models?capability=vision&method=chat_completions")
    rows = catalog.get("data")
    if not isinstance(rows, list):
        raise WalletError("AI Pass returned an unexpected model catalog.")
    return [row["id"] for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)
            and isinstance(row.get("capabilities"), list)
            and "vision" in row["capabilities"] and "tools" in row["capabilities"]]
