"""
Crypto Messenger — Flask Backend
==================================
DH Endpoints:
  POST /dh/generate          → generate keypair, store private in session
  POST /dh/compute           → compute shared secret, derive session keys

Crypto Endpoints:
  POST /encrypt  { message, session_id }   → all encryption steps
  POST /decrypt  { encrypted, session_id } → all decryption steps

  GET  /                     → web app
"""

from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from cryptography.fernet import Fernet
from crypto import (
    dh_generate_keypair, dh_compute_shared, derive_session_keys,
    encrypt_message, decrypt_message
)

app = Flask(__name__)
app.secret_key = "crypto-messenger-secret-2024"   # for Flask sessions
CORS(app, supports_credentials=True)

# In-memory store: session_id → { private, vigenere_key, fernet }
_sessions: dict = {}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── DH: Step 1 — Generate keypair ────────────────────────────────────────────
@app.route("/dh/generate", methods=["POST"])
def dh_generate():
    data       = request.get_json(silent=True) or {}
    session_id = data.get("session_id", "default")

    private_key, public_key = dh_generate_keypair()

    # Store private key server-side — never sent to client
    _sessions[session_id] = {"private": private_key, "ready": False}

    return jsonify({
        "public_key":  public_key,
        "session_id":  session_id,
        "p_preview":   hex(int(public_key))[:18] + "…",   # for display only
    })


# ── DH: Step 2 — Compute shared secret & derive keys ─────────────────────────
@app.route("/dh/compute", methods=["POST"])
def dh_compute():
    data         = request.get_json(silent=True) or {}
    session_id   = data.get("session_id", "default")
    their_public = data.get("their_public", "")

    if session_id not in _sessions:
        return jsonify({"error": "Session not found. Call /dh/generate first."}), 400

    my_private = _sessions[session_id]["private"]
    shared_hex = dh_compute_shared(their_public, my_private)
    keys       = derive_session_keys(shared_hex)

    # Save derived keys, discard private
    _sessions[session_id] = {
        "ready":        True,
        "vigenere_key": keys["vigenere_key"],
        "fernet":       Fernet(keys["fernet_key"].encode()),
        "shared_bits":  len(bin(int(shared_hex, 16))) - 2,   # bit length for display
    }

    return jsonify({
        "status":           "key_exchange_complete",
        "shared_preview":   shared_hex[:8] + "…" + shared_hex[-8:],
        "shared_bits":      _sessions[session_id]["shared_bits"],
        "vigenere_key":     keys["vigenere_key"],      # shown for educational purposes
        "fernet_key_hint":  keys["fernet_key"][:12] + "…",
    })


# ── Encrypt ──────────────────────────────────────────────────────────────────
@app.route("/encrypt", methods=["POST"])
def encrypt():
    data       = request.get_json(silent=True) or {}
    message    = data.get("message", "").strip()
    session_id = data.get("session_id", "default")

    if not message:
        return jsonify({"error": "Message is required"}), 400

    sess = _sessions.get(session_id, {})
    if sess.get("ready"):
        result = encrypt_message(message,
                                 vigenere_key=sess["vigenere_key"],
                                 fernet_instance=sess["fernet"])
    else:
        result = encrypt_message(message)   # fallback to static keys

    return jsonify(result)


# ── Decrypt ──────────────────────────────────────────────────────────────────
@app.route("/decrypt", methods=["POST"])
def decrypt():
    data       = request.get_json(silent=True) or {}
    encrypted  = data.get("encrypted", "").strip()
    session_id = data.get("session_id", "default")

    if not encrypted:
        return jsonify({"error": "Encrypted text is required"}), 400

    try:
        sess = _sessions.get(session_id, {})
        if sess.get("ready"):
            result = decrypt_message(encrypted,
                                     vigenere_key=sess["vigenere_key"],
                                     fernet_instance=sess["fernet"])
        else:
            result = decrypt_message(encrypted)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 400


# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)
