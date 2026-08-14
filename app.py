#!/usr/bin/env python3
"""
Public demo: Zoho IMAP BODYSTRUCTURE vs BODY[2.MIME] filename corruption.

The homepage shows captured evidence and a live IMAP login form.
Credentials are used only for that request and are never stored.

  python3 app.py
  # open http://127.0.0.1:8080
"""

from __future__ import annotations

import html
import imaplib
import os
import re
import secrets
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


DEFAULT_HOST = os.environ.get("ZOHO_IMAP_HOST", "imap.zoho.eu")
DEFAULT_PORT = int(os.environ.get("ZOHO_IMAP_PORT", "993"))
DEFAULT_SUBJECT = os.environ.get("DEMO_SUBJECT", "Test file attachment name encoding")
HTTP_PORT = int(os.environ.get("PORT", "8080"))
SOURCE_URL = os.environ.get(
    "SOURCE_URL",
    "https://github.com/darkpal/zoho-imap-bodystructure-demo",
)
BASE_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = BASE_DIR / "samples"
ALLOWED_EML = {
    "test-a-zoho-web.eml": "Test A — Zoho Web sent",
    "test-c-gmail-to-zoho.eml": "Test C — Gmail received in Zoho",
    "test-b-gmail-outbox-working.eml": "Test B — Gmail outbox (working reference)",
}
LIVE_EML: dict[str, tuple[float, bytes, str]] = {}
LIVE_EML_TTL = 15 * 60

STATIC_CASES = [
    {
        "title": "Test A — sent from Zoho Web",
        "eml": "test-a-zoho-web.eml",
        "headers": (
            "Date: Wed, 22 Jul 2026 11:00:07 +0300\n"
            "Message-Id: <redacted@example.com>\n"
            "Subject: Test file attachment name encoding (Zoho Web-version)"
        ),
        "rows": [
            {
                "label": "BODYSTRUCTURE filename #1 (encoded)",
                "text": "utf8''%D0%A0%D0%B0%D1%85%D1%83%D0%BD%D0%BE%D0%BA%20%D0%BD%D0%B0%20%D0%BE%D0%BF%D0%BB%D0%B0%D1%82%D1%83%20%E2%84%96%20%D0%9D%D0%A4-340%20%D0%B2%D1%96%D0%B4%2015.07.2026.pdf",
                "hex": "75 74 66 38 27 27 25 44 30 25 41 30 …",
                "qmarks": 0,
                "bad": False,
            },
            {
                "label": "BODYSTRUCTURE filename #2 (broken)",
                "text": "??????? ?? ?????? ? ??-340 ??? 15.07.2026.pdf",
                "hex": "3f 3f 3f 3f 3f 3f 3f 20 3f 3f 20 3f 3f 3f 3f 3f 3f 20 3f 20 3f 3f 2d 33 34 30 20 3f 3f 3f 20 31 35 2e 30 37 2e 32 30 32 36 2e 70 64 66",
                "qmarks": 21,
                "bad": True,
            },
        ],
        "mime_lines": [
            "Content-Type: application/pdf; name*=utf8''%D0%A0%D0%B0%D1%85%D1%83%D0%BD%D0%BE%D0%BA%20...15.07.2026.pdf",
            "Content-Disposition: attachment; filename*=utf8''%D0%A0%D0%B0%D1%85%D1%83%D0%BD%D0%BE%D0%BA%20...15.07.2026.pdf",
        ],
    },
    {
        "title": "Test C — sent from Gmail, received in Zoho",
        "eml": "test-c-gmail-to-zoho.eml",
        "headers": (
            "Date: Wed, 22 Jul 2026 10:59:33 +0300\n"
            "Message-ID: <redacted@mail.gmail.com>\n"
            "Subject: Test file attachment name encoding (Gmail Web-version)"
        ),
        "rows": [
            {
                "label": "BODYSTRUCTURE filename (broken)",
                "text": "??????? ?? ?????? ? ??-340 ??? 15.07.2026.pdf",
                "hex": "3f 3f 3f 3f 3f 3f 3f 20 3f 3f 20 3f 3f 3f 3f 3f 3f 20 3f 20 3f 3f 2d 33 34 30 20 3f 3f 3f 20 31 35 2e 30 37 2e 32 30 32 36 2e 70 64 66",
                "qmarks": 21,
                "bad": True,
            },
        ],
        "mime_lines": [
            'Content-Type: application/pdf; name="=?UTF-8?B?0KDQsNGF0YPQvdC+0Log...?="',
            'Content-Disposition: attachment; filename="=?UTF-8?B?0KDQsNGF0YPQvdC+0Log...?="',
        ],
    },
]


def hexdump(data: bytes, limit: int = 96) -> str:
    chunk = data[:limit]
    return " ".join(f"{b:02x}" for b in chunk) + (" …" if len(data) > limit else "")


def extract_pdf_names(raw: bytes) -> list[bytes]:
    return re.findall(rb'"([^"]+\.pdf)"', raw, flags=re.I)


def mask_user(user: str) -> str:
    if "@" in user and len(user) > 4:
        local, domain = user.split("@", 1)
        return local[:2] + "***@" + domain
    return "***"


def fetch_live(user: str, password: str, host: str, subject: str) -> dict:
    host = (host or DEFAULT_HOST).strip() or DEFAULT_HOST
    subject = (subject or DEFAULT_SUBJECT).strip() or DEFAULT_SUBJECT
    user = user.strip()
    if not user or not password:
        return {"ok": False, "error": "Email and password are required."}

    conn = imaplib.IMAP4_SSL(host, DEFAULT_PORT, ssl_context=ssl.create_default_context())
    conn._encoding = "utf-8"  # noqa: SLF001
    try:
        conn.login(user, password)
        typ, _ = conn.select("INBOX")
        if typ != "OK":
            return {"ok": False, "error": "Cannot SELECT INBOX"}

        typ, data = conn.search(None, "TEXT", f'"{subject}"')
        if typ != "OK" or not data or not data[0]:
            typ, data = conn.search(None, "ALL")
        if typ != "OK" or not data or not data[0]:
            return {
                "ok": False,
                "error": f'No messages found. Put a Cyrillic-attachment test email in INBOX (subject containing "{subject}").',
            }

        seq = None
        headers = ""
        for cand in reversed(data[0].split()):
            typ2, hdr = conn.fetch(cand, "(BODY.PEEK[HEADER.FIELDS (SUBJECT MESSAGE-ID DATE)])")
            if typ2 != "OK" or not hdr or not isinstance(hdr[0], tuple):
                continue
            blob = hdr[0][1].decode("utf-8", errors="replace")
            if subject.lower() in blob.lower():
                seq = cand
                headers = blob.strip()
                break
        if seq is None:
            seq = data[0].split()[-1]
            typ2, hdr = conn.fetch(seq, "(BODY.PEEK[HEADER.FIELDS (SUBJECT MESSAGE-ID DATE)])")
            headers = (
                hdr[0][1].decode("utf-8", errors="replace").strip()
                if typ2 == "OK" and hdr and isinstance(hdr[0], tuple)
                else ""
            )

        typ, bs_data = conn.fetch(seq, "(BODYSTRUCTURE)")
        bodystructure = b""
        if typ == "OK" and bs_data:
            for item in bs_data:
                if isinstance(item, tuple):
                    bodystructure += b"".join(p for p in item if isinstance(p, bytes))
                elif isinstance(item, bytes):
                    bodystructure += item

        typ, mime_data = conn.fetch(seq, "(BODY.PEEK[2.MIME])")
        mime = b""
        if typ == "OK" and mime_data and isinstance(mime_data[0], tuple):
            mime = mime_data[0][1] if isinstance(mime_data[0][1], bytes) else b""

        rows = []
        for i, name in enumerate(extract_pdf_names(bodystructure), 1):
            q = name.count(b"?")
            rows.append(
                {
                    "label": f"BODYSTRUCTURE filename #{i}",
                    "text": name.decode("latin-1", errors="replace"),
                    "hex": hexdump(name),
                    "qmarks": q,
                    "bad": q >= 5 and not name.upper().startswith(b"=?UTF-8?"),
                }
            )

        mime_text = mime.decode("utf-8", errors="replace")
        mime_lines = [
            line
            for line in mime_text.splitlines()
            if line.lower().startswith(("content-type:", "content-disposition:"))
        ]
        mime_ok = (b"=?UTF-8?" in mime.upper()) or (b"utf8''" in mime.lower())
        bug = any(r["bad"] for r in rows) and mime_ok

        eml_token = ""
        typ, rfc = conn.fetch(seq, "(RFC822)")
        if typ == "OK" and rfc and isinstance(rfc[0], tuple) and isinstance(rfc[0][1], bytes):
            now = time.time()
            for old_token, (ts, _, _) in list(LIVE_EML.items()):
                if now - ts > LIVE_EML_TTL:
                    LIVE_EML.pop(old_token, None)
            eml_token = secrets.token_urlsafe(16)
            LIVE_EML[eml_token] = (now, rfc[0][1], "live-check.eml")

        return {
            "ok": True,
            "host": host,
            "user_masked": mask_user(user),
            "seq": seq.decode(),
            "headers": headers,
            "rows": rows,
            "mime_lines": mime_lines,
            "mime_ok": mime_ok,
            "bug": bug,
            "eml_token": eml_token,
        }
    except imaplib.IMAP4.error as e:
        return {"ok": False, "error": f"IMAP error: {e}"}
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def render_cards(rows: list[dict]) -> str:
    out = ""
    for row in rows:
        cls = "bad" if row["bad"] else "good"
        out += f"""
        <div class="card {cls}">
          <h3>{html.escape(row['label'])}</h3>
          <div class="fname">{html.escape(row['text'])}</div>
          <div class="meta">hex: <code>{html.escape(row['hex'])}</code></div>
          <div class="meta">byte 0x3F ('?') count: <strong>{row['qmarks']}</strong></div>
        </div>"""
    return out


def page(live_result: dict | None = None, form: dict | None = None) -> str:
    form = form or {}
    email_val = html.escape(form.get("email", ""))
    host_val = html.escape(form.get("host", DEFAULT_HOST))
    subject_val = html.escape(form.get("subject", DEFAULT_SUBJECT))

    cases_html = ""
    for case in STATIC_CASES:
        mime_block = "\n".join(html.escape(x) for x in case["mime_lines"])
        eml_name = case.get("eml", "")
        eml_btn = (
            f'<p><a class="btn secondary" href="/samples/{html.escape(eml_name)}">Download this .eml</a></p>'
            if eml_name
            else ""
        )
        cases_html += f"""
        <section class="panel">
          <h2>{html.escape(case['title'])}</h2>
          {eml_btn}
          <pre>{html.escape(case['headers'])}</pre>
          <div class="grid">{render_cards(case['rows'])}</div>
          <h3>Same message — BODY[2.MIME]</h3>
          <pre>{mime_block}</pre>
        </section>"""

    live_block = ""
    if live_result is not None:
        if live_result.get("ok"):
            mime_block = "\n".join(html.escape(x) for x in live_result["mime_lines"]) or "(none)"
            verdict = (
                '<div class="verdict bad"><strong>Live check: SERVER BUG CONFIRMED.</strong> '
                "BODYSTRUCTURE has literal '?' while BODY[2.MIME] is correctly encoded.</div>"
                if live_result["bug"]
                else '<div class="verdict warn"><strong>Live check:</strong> pattern not matched — keep a Cyrillic-attachment test mail in INBOX.</div>'
            )
            live_block = f"""
            {verdict}
            <section class="panel">
              <h2>Live IMAP result</h2>
              <pre>{html.escape(live_result['headers'])}</pre>
              <p class="meta">host={html.escape(live_result['host'])} · mailbox={html.escape(live_result['user_masked'])} · seq={html.escape(live_result['seq'])}</p>
              <div class="grid">{render_cards(live_result['rows'])}</div>
              <h3>BODY[2.MIME]</h3>
              <pre>{mime_block}</pre>
              {f'<p><a class="btn" href="/live-eml/{html.escape(live_result["eml_token"])}">Download this live message as .eml</a></p>' if live_result.get("eml_token") else ""}
            </section>"""
        else:
            live_block = f'<div class="verdict bad"><strong>Live error:</strong> {html.escape(live_result.get("error",""))}</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Zoho IMAP BODYSTRUCTURE demo</title>
  <style>
    :root {{
      --bg: #0f1419; --panel: #1a222c; --text: #e8eef4; --muted: #93a1b0;
      --good: #1f6f4a; --bad: #8b2e2e; --accent: #3d8bfd; --border: #2b3642;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      background: radial-gradient(1200px 600px at 10% -10%, #1b2a3d, var(--bg));
      color: var(--text); line-height: 1.45;
    }}
    main {{ max-width: 980px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }}
    h1 {{ font-size: 1.75rem; margin: 0 0 .5rem; letter-spacing: -0.02em; }}
    h2 {{ font-size: 1.1rem; margin: 0 0 .75rem; }}
    h3 {{ margin: 1rem 0 .5rem; font-size: .95rem; color: var(--muted); }}
    .lead {{ color: var(--muted); max-width: 44rem; }}
    .actions {{ display: flex; gap: .75rem; flex-wrap: wrap; margin: 1.25rem 0; align-items: center; }}
    button, .btn {{
      appearance: none; border: 0; border-radius: 8px; padding: .7rem 1rem;
      background: var(--accent); color: white; font-weight: 600; cursor: pointer;
      text-decoration: none; display: inline-block;
    }}
    .btn.secondary {{ background: transparent; border: 1px solid var(--border); color: var(--text); }}
    .grid {{ display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }}
    .card, .panel, .verdict {{
      background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 1rem 1.1rem; margin: 1rem 0;
    }}
    .card.good {{ border-color: #2f8f5b; box-shadow: inset 3px 0 0 var(--good); }}
    .card.bad {{ border-color: #b04848; box-shadow: inset 3px 0 0 var(--bad); }}
    .fname {{ font-family: ui-monospace, Menlo, monospace; font-size: .95rem; word-break: break-all; margin: .4rem 0 .7rem; }}
    .meta {{ color: var(--muted); font-size: .85rem; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #0c1117; border-radius: 8px; padding: .85rem; font-size: .82rem; }}
    .verdict.bad {{ border-color: #b04848; }}
    .verdict.warn {{ border-color: #a07820; }}
    code {{ font-family: ui-monospace, Menlo, monospace; font-size: .8rem; }}
    ol {{ color: var(--muted); }}
    ol strong {{ color: var(--text); }}
    footer {{ margin-top: 2rem; color: var(--muted); font-size: .85rem; }}
    label {{ display: block; font-size: .85rem; color: var(--muted); margin: .7rem 0 .25rem; }}
    input {{
      width: 100%; padding: .65rem .7rem; border-radius: 8px; border: 1px solid var(--border);
      background: #0c1117; color: var(--text); font-size: 1rem;
    }}
    .form-grid {{ display: grid; gap: .4rem 1rem; grid-template-columns: 1fr 1fr; }}
    @media (max-width: 700px) {{ .form-grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
<main>
  <h1>Zoho IMAP attachment filename demo</h1>
  <p class="lead">
    Compare <code>FETCH BODYSTRUCTURE</code> vs <code>FETCH BODY[2.MIME]</code>
    on a Zoho Mail IMAP account. Credentials are used only for this request and are not stored.
  </p>

  <div class="actions">
    <a class="btn secondary" href="{html.escape(SOURCE_URL)}" target="_blank" rel="noopener">View source on GitHub</a>
  </div>

  <section class="panel">
    <h2>Live IMAP check</h2>
    <p class="meta">Use a Zoho Mail address and an <strong>App-Specific Password</strong>. Put a test email with a Cyrillic attachment filename in INBOX first.</p>
    <form method="post" action="/run" autocomplete="off">
      <div class="form-grid">
        <div>
          <label for="email">Email</label>
          <input id="email" name="email" type="email" required placeholder="you@yourdomain.com" value="{email_val}" />
        </div>
        <div>
          <label for="password">App password</label>
          <input id="password" name="password" type="password" required placeholder="Zoho app-specific password" />
        </div>
        <div>
          <label for="host">IMAP host</label>
          <input id="host" name="host" type="text" value="{host_val}" />
        </div>
        <div>
          <label for="subject">Subject contains</label>
          <input id="subject" name="subject" type="text" value="{subject_val}" />
        </div>
      </div>
      <p style="margin: 1rem 0 0;"><button type="submit">Connect and compare filenames</button></p>
    </form>
  </section>

  <section class="panel">
    <h2>Download sample .eml files</h2>
    <p class="meta">Raw messages used in the captured tests below. Open them in any email client or a text editor.</p>
    <div class="actions">
      <a class="btn secondary" href="/samples/test-a-zoho-web.eml">Test A — Zoho Web .eml</a>
      <a class="btn secondary" href="/samples/test-c-gmail-to-zoho.eml">Test C — Gmail → Zoho .eml</a>
      <a class="btn secondary" href="/samples/test-b-gmail-outbox-working.eml">Test B — Gmail outbox (working) .eml</a>
    </div>
  </section>

  {live_block}

  <div class="verdict bad">
    <strong>Captured server-side evidence.</strong>
    Hex <code>3f 3f 3f…</code> is already in Zoho’s BODYSTRUCTURE response.
    Wrong UTF-8→latin-1 decoding would produce mojibake, not question marks.
    Test C (Gmail→Zoho) proves this is not “how the sender sends the email”.
  </div>

  {cases_html}

  <section class="panel">
    <h2>What this proves</h2>
    <ol>
      <li><strong>Same IMAP server, same message, same session.</strong></li>
      <li><strong>BODY[2.MIME]</strong> is correctly encoded.</li>
      <li><strong>BODYSTRUCTURE</strong> contains literal <code>?</code> (<code>0x3F</code>).</li>
      <li>Clients that trust BODYSTRUCTURE (Spark, Apple Mail, Canary) show <code>????</code>.</li>
      <li>Gmail-origin mail still breaks after Zoho delivery → not a sender MIME issue alone.</li>
    </ol>
  </section>

  <footer>
    Source: {html.escape(SOURCE_URL)} · Credentials are never stored in this app.
  </footer>
</main>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        # Do not log query strings or POST bodies (may contain credentials).
        print(f"{self.address_string()} {self.command} {urlparse(self.path).path}")

    def _send(self, code: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_bytes(self, code: int, data: bytes, content_type: str, filename: str | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, page())
        elif path == "/health":
            self._send(200, "ok\n", "text/plain; charset=utf-8")
        elif path.startswith("/samples/"):
            name = path.rsplit("/", 1)[-1]
            if name not in ALLOWED_EML:
                self._send(404, "Not found\n", "text/plain; charset=utf-8")
                return
            file_path = SAMPLES_DIR / name
            if not file_path.is_file():
                self._send(404, "Not found\n", "text/plain; charset=utf-8")
                return
            self._send_bytes(200, file_path.read_bytes(), "message/rfc822", name)
        elif path.startswith("/live-eml/"):
            token = path.rsplit("/", 1)[-1]
            item = LIVE_EML.get(token)
            if not item:
                self._send(404, "Download expired. Run the live check again.\n", "text/plain; charset=utf-8")
                return
            ts, data, filename = item
            if time.time() - ts > LIVE_EML_TTL:
                LIVE_EML.pop(token, None)
                self._send(404, "Download expired. Run the live check again.\n", "text/plain; charset=utf-8")
                return
            self._send_bytes(200, data, "message/rfc822", filename)
        else:
            self._send(404, "Not found\n", "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/run":
            self._send(404, "Not found\n", "text/plain; charset=utf-8")
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > 8192:
            self._send(413, page({"ok": False, "error": "Request too large"}))
            return
        raw = self.rfile.read(length) if length else b""
        form = parse_qs(raw.decode("utf-8", errors="replace"))
        email = (form.get("email") or [""])[0]
        password = (form.get("password") or [""])[0]
        host = (form.get("host") or [DEFAULT_HOST])[0]
        subject = (form.get("subject") or [DEFAULT_SUBJECT])[0]
        result = fetch_live(email, password, host, subject)
        self._send(200, page(result, {"email": email, "host": host, "subject": subject}))


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    print(f"Listening on http://0.0.0.0:{HTTP_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
