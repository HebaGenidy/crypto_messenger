# Crypto Messenger
### Triple-Layer Encrypted Chat — Cryptography Project

---

## How it works

Every message travels through **3 encryption layers** before reaching Firebase:

```
Plaintext
   │
   ▼ Layer 1 — Caesar Cipher (shift: 7)
   │
   ▼ Layer 2 — Vigenere Cipher (key: QUANTUM)
   │
   ▼ Layer 3 — AES-128 via Fernet
   │
   ▼ Stored in Firebase (encrypted)
   │
   ▼ Decryption: AES → Vigenere → Caesar
   │
Plaintext ✓
```

---

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Firebase Setup
1. Go to [console.firebase.google.com](https://console.firebase.google.com)
2. Create a new project
3. Enable **Realtime Database** (test mode)
4. Go to Project Settings → copy your web config
5. Replace the `firebaseConfig` object in `templates/index.html`

### 3. Run Flask
```bash
python app.py
```

### 4. Open the app
- Open **two browser windows** at `http://127.0.0.1:5000`
- One window picks **Agent A**, the other picks **Agent B**
- Messages are encrypted by Flask, stored in Firebase, then decrypted on arrival

---

## Algorithms

| Layer | Algorithm | Type | Key |
|-------|-----------|------|-----|
| 1 | Caesar Cipher | Classical — Substitution | shift = 7 |
| 2 | Vigenere Cipher | Classical — Polyalphabetic | `QUANTUM` |
| 3 | AES-128 (Fernet) | Modern — Symmetric | auto-generated |

---

## Project Structure
```
crypto_messenger/
├── app.py          # Flask backend (encrypt / decrypt endpoints)
├── crypto.py       # All encryption logic
├── requirements.txt
├── secret.key      # AES key (auto-generated on first run)
└── templates/
    └── index.html  # Frontend + Firebase real-time listener
```
