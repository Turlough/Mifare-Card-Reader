"""
Flask web interface for Mifare card reader.

Uses the same card reading logic as read_card.py.
Run: python card_reader_web.py
Then open http://127.0.0.1:5000 in a browser.
"""

import sys
from threading import Lock

from flask import Flask, jsonify, render_template_string
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import NoCardException, CardConnectionException

# Import from read_card
from read_card import (
    ATR_CARD_TYPES,
    identify_card,
    get_uid,
    uid_to_card_number,
    select_reader,
)

app = Flask(__name__)

# Shared state for card reads
_last_uid = None
_last_card_data = None
_state_lock = Lock()
_reader = None


def _ensure_reader():
    """Lazily select the card reader."""
    global _reader
    if _reader is None:
        _reader = select_reader()
    return _reader


def _try_read_card():
    """Attempt to read a card. Returns dict with status and optional card data."""
    global _last_uid, _last_card_data

    try:
        target = _ensure_reader()
        conn = target.createConnection()
        conn.connect(CardConnection.T0_protocol | CardConnection.T1_protocol)

        uid = get_uid(conn)
        uid_str = toHexString(uid) if uid else None

        if uid_str:
            atr = conn.getATR()
            card_type, _, _ = identify_card(atr)

        conn.disconnect()

        if uid_str:
            card_number = uid_to_card_number(uid)

            data = {
                "card_type": card_type,
                "uid": uid_str,
                "card_number": card_number,
            }

            with _state_lock:
                if uid_str != _last_uid:
                    _last_uid = uid_str
                    _last_card_data = data
                    return {"status": "new_card", "card": data}
                return {"status": "same_card", "card": data}

    except (NoCardException, CardConnectionException):
        with _state_lock:
            if _last_uid is not None:
                _last_uid = None
                _last_card_data = None
        return {"status": "no_card"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

    return {"status": "no_card"}


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mifare Card Reader</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            max-width: 480px;
            margin: 2rem auto;
            padding: 1.5rem;
            background: #1a1a2e;
            color: #eee;
            min-height: 100vh;
        }
        h1 {
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            color: #444;
        }
        .card-box {
            background: #16213e;
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border: 1px solid #0f3460;
        }
        .card-number {
            font-size: 2rem;
            font-weight: 700;
            color: #e94560;
            letter-spacing: 0.05em;
            margin: 0.5rem 0;
        }
        .label { color: #8892b0; font-size: 0.85rem; }
        .status {
            padding: 0.5rem;
            border-radius: 6px;
            margin-top: 1rem;
            font-size: 0.9rem;
        }
        .status.waiting { background: #0f3460; color: #a0aec0; }
        .status.read { background: #22543d; color: #9ae6b4; }
        .status.error { background: #742a2a; color: #feb2b2; }
        .card-list {
            background: #16213e;
            border-radius: 12px;
            padding: 1rem 1.5rem;
            border: 1px solid #0f3460;
        }
        .card-list-title { color: #8892b0; font-size: 0.85rem; margin-bottom: 0.5rem; }
        .card-list-items { padding-left: 1.5rem; margin: 0; }
        .card-list-items li { padding: 0.25rem 0; color: #bbbb44; font-family: monospace; font-size: 1.05rem; }
    </style>
</head>
<body>
    <h1>Mifare Card Reader</h1>
    <div class="card-box">
        <div id="status" class="status waiting">Place a card on the reader...</div>
        <div id="card-info" style="display:none;">
            <div class="label">Card Type</div>
            <div id="card-type"></div>
            <div class="label">UID</div>
            <div id="uid"></div>
            <div class="label">Card Number</div>
            <div id="card-number" class="card-number"></div>
        </div>
    </div>
    <div class="card-list">
        <div class="card-list-title">Cards read</div>
        <ol id="card-list-items" class="card-list-items"></ol>
    </div>
    <script>
        const statusEl = document.getElementById('status');
        const cardInfo = document.getElementById('card-info');
        const cardTypeEl = document.getElementById('card-type');
        const uidEl = document.getElementById('uid');
        const cardNumberEl = document.getElementById('card-number');
        const cardListEl = document.getElementById('card-list-items');

        const cardsRead = [];

        function renderCardList() {
            cardListEl.innerHTML = '';
            cardsRead.forEach(n => {
                const li = document.createElement('li');
                li.textContent = n;
                cardListEl.appendChild(li);
            });
        }

        async function poll() {
            try {
                const r = await fetch('/api/read');
                const data = await r.json();
                if (data.status === 'new_card' || data.status === 'same_card') {
                    const c = data.card;
                    statusEl.textContent = 'Card detected';
                    statusEl.className = 'status read';
                    cardInfo.style.display = 'block';
                    cardTypeEl.textContent = c.card_type;
                    uidEl.textContent = c.uid;
                    cardNumberEl.textContent = c.card_number ?? '(could not derive)';
                    if (data.status === 'new_card') {
                        const n = c.card_number != null ? String(c.card_number) : c.uid;
                        cardsRead.push(n);
                        renderCardList();
                    }
                } else if (data.status === 'no_card') {
                    statusEl.textContent = 'Place a card on the reader...';
                    statusEl.className = 'status waiting';
                    cardInfo.style.display = 'none';
                } else {
                    statusEl.textContent = 'Error: ' + (data.message || 'Unknown');
                    statusEl.className = 'status error';
                }
            } catch (e) {
                statusEl.textContent = 'Error: ' + e.message;
                statusEl.className = 'status error';
            }
        }

        poll();
        setInterval(poll, 500);
    </script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/read")
def api_read():
    return jsonify(_try_read_card())


def main():
    print("=" * 60)
    print("  Mifare Card Reader (Flask)")
    print("=" * 60)

    try:
        _ensure_reader()
        print(f"Using reader: {_reader}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    print("Open http://127.0.0.1:5000 in your browser")
    print("Place a card on the reader to see it detected.")
    print()

    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
