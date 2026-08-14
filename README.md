# Zoho IMAP BODYSTRUCTURE — public demo

Public page with:

1. A **login form** (email + app password) to run a live IMAP check
2. Captured evidence: BODYSTRUCTURE `????` vs correct BODY[2.MIME]

Repo: https://github.com/darkpal/zoho-imap-bodystructure-demo

Credentials are used only for that HTTP request. They are **not stored** and **not committed**.

## Deploy on Render

1. Connect this repository
2. Start command: `python3 app.py`
3. No secrets required

## Local run

```bash
python3 app.py
# http://127.0.0.1:8080
```

No pip packages required.

## How to test

1. Keep a test email in INBOX with a Cyrillic attachment filename
2. Open the page
3. Enter Zoho Mail address + App-Specific Password
4. Click **Connect and compare filenames**
5. Use **Download this live message as .eml** if you need the raw message
