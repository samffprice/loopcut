"""AI Pass desktop authorization and chat transport. No live spending."""

import base64
import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.error import HTTPError
from urllib.request import urlopen
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "addons_core"))

from loopcut import aipass, chatgpt_auth, credentials, llm  # noqa: E402


def tokens(access="test-access", refresh="test-refresh", expires_in=3600):
    return {"access_token": access, "refresh_token": refresh, "token_type": "Bearer",
            "scope": "api:access", "expires_in": expires_in}


class WalletTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.enterContext(patch.dict(os.environ, {"LOOPCUT_CONFIG_DIR": folder.name,
                                                 "LOOPCUT_AIPASS_CLIENT_ID": "test-client"}))
        self.folder = Path(folder.name)

    def test_callback_validates_state_and_exchanges_pkce(self):
        # Use an ephemeral port in the test, while ensuring the identical callback reaches token exchange.
        callback = chatgpt_auth._CallbackServer(0, allow_fallback=False)
        self.addCleanup(callback.close)
        answers = []
        browser = None
        challenge = None

        def open_browser(url):
            nonlocal browser, challenge
            fields = parse_qs(urlsplit(url).query)
            self.assertEqual(fields["scope"], ["api:access"])
            self.assertEqual(fields["code_challenge_method"], ["S256"])
            challenge = fields["code_challenge"][0]
            self.assertEqual(fields["redirect_uri"], [callback.redirect_uri])

            def visit():
                for state in ("wrong", fields["state"][0]):
                    query = urlencode({"state": state, "code": "test-code"})
                    try:
                        with urlopen(f"{callback.redirect_uri}?{query}", timeout=3) as response:
                            answers.append(response.status)
                    except HTTPError as ex:
                        with ex:
                            answers.append(ex.code)

            browser = threading.Thread(target=visit)
            browser.start()

        with (patch.object(aipass, "CALLBACK", callback.redirect_uri),
              patch.object(chatgpt_auth, "_CallbackServer", return_value=callback),
              patch.object(aipass, "_request", return_value=tokens()) as exchange):
            aipass.connect(open_browser, lambda: False)
            browser.join(5)
        self.assertEqual(answers, [400, 200])
        path, body = exchange.call_args.args
        self.assertEqual((path, body["clientId"], body["code"], body["redirectUri"]),
                         ("/oauth2/token", "test-client", "test-code", callback.redirect_uri))
        self.assertEqual(len(body["codeVerifier"]), 64)
        self.assertEqual(base64.urlsafe_b64encode(
            hashlib.sha256(body["codeVerifier"].encode()).digest()).rstrip(b"=").decode(), challenge)
        self.assertEqual(aipass.authorization(aipass.connection_id()), ("test-client", "test-access"))
        if os.name != "nt":
            self.assertEqual((self.folder / "credentials.json").stat().st_mode & 0o777, 0o600)

    def test_cancelled_browser_connection_leaves_credentials_untouched(self):
        callback = chatgpt_auth._CallbackServer(0, allow_fallback=False)
        cancel = threading.Event()
        with (patch.object(chatgpt_auth, "_CallbackServer", return_value=callback),
              patch.object(aipass, "_request") as exchange):
            aipass.connect(lambda _: cancel.set(), cancel.is_set)
        exchange.assert_not_called()
        self.assertFalse(aipass.connected())

    def test_refresh_rotates_and_disconnect_revokes_only_wallet(self):
        credentials.store("https://example.com", "unrelated-key")
        credentials._write({**credentials._read(), aipass._SESSION: {
            **aipass._session(tokens(), "test-client"), "expires_at": 0,
        }})
        connection = aipass.connection_id()
        with patch.object(aipass, "_request", side_effect=[tokens("new-access", "new-refresh"), {}, {}]) as request:
            with self.assertRaisesRegex(aipass.WalletError, "wallet changed"):
                aipass.authorization("other-wallet")
            self.assertEqual(aipass.authorization(connection), ("test-client", "new-access"))
            self.assertEqual(aipass.authorization(connection), ("test-client", "new-access"))
            aipass.disconnect()
        self.assertEqual([call.args[0] for call in request.call_args_list],
                         ["/oauth2/token", "/oauth2/revoke", "/oauth2/revoke"])
        self.assertEqual(request.call_args_list[1].args[1]["token"], "new-refresh")
        self.assertEqual(request.call_args_list[2].args[1]["token"], "new-access")
        self.assertFalse(aipass.connected())
        self.assertEqual(credentials.api_key("https://example.com"), "unrelated-key")

    def test_missing_scope_is_refused(self):
        with self.assertRaises(aipass.WalletError):
            aipass._session({**tokens(), "scope": "profile:read"}, "test-client")

    def test_model_list_filters_for_tool_support(self):
        with patch.object(aipass, "_request", return_value={"data": [
            {"id": "with-tools", "capabilities": ["vision", "tools"]},
            {"id": "without-tools", "capabilities": ["vision"]},
        ]}):
            self.assertEqual(aipass.list_models(), ["with-tools"])

    def test_stream_uses_the_wallet_and_does_not_retry_a_failed_paid_request(self):
        events = []
        reply = {"status": 503}
        stream = (
            b'data: {"choices":[{"delta":{"content":"OK"},"finish_reason":"stop"}]}\n\n'
            b'data: {"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":1}}\n\n'
            b'data: [DONE]\n\n'
        )

        class Provider(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                events.append((self.path, self.headers["Authorization"], self.headers["X-AIPass-OAuth-Client-Id"], body))
                data = stream if reply["status"] == 200 else b'{"error":{"message":"Service unavailable"}}'
                self.send_response(reply["status"])
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), Provider) as server:
            worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            worker.start()
            try:
                with (patch.object(aipass, "API_BASE", f"http://127.0.0.1:{server.server_port}/v1"),
                      patch.object(aipass, "authorization", return_value=("test-client", "test-access"))):
                    kwargs = dict(base_url=aipass.PROVIDER_URL, api_key="unused", model="test-model",
                                  messages=[{"role": "user", "content": "Reply OK"}], tools=[], reasoning_effort="low",
                                  on_text=lambda _: None, is_cancelled=lambda: False)
                    with self.assertRaises(llm.LLMError):
                        llm.stream_chat(**kwargs)
                    self.assertEqual(len(events), 1)
                    reply["status"] = 200
                    completion = llm.stream_chat(**kwargs)
            finally:
                server.shutdown()
                worker.join(5)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[1][:3], ("/v1/chat/completions", "Bearer test-access", "test-client"))
        self.assertTrue(events[1][3]["stream"])
        self.assertEqual(completion.text, "OK")
