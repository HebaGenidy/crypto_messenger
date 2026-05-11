"""
Triple-Layer Encryption + Diffie-Hellman Key Exchange
======================================================
DH Key Exchange  →  Both agents derive a shared secret
Layer 1          →  Caesar Cipher       (Classical - Substitution)
Layer 2          →  Vigenere Cipher     (Classical - Polyalphabetic)
Layer 3          →  AES-128 via Fernet  (Modern   - Symmetric)

The Vigenere key and AES key are BOTH derived from the DH shared secret,
so every new session uses completely different encryption keys.
"""

import random
import hashlib
import base64
from cryptography.fernet import Fernet

# ─── Diffie-Hellman Parameters (RFC 2409 – 512-bit Safe Prime) ────────────────
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16
)
DH_G = 2


def dh_generate_keypair() -> tuple:
    """
    Generate a DH keypair.
      private_key : random int in [2, p-2]   — kept SECRET
      public_key  : g^private mod p          — shared openly via Firebase
    """
    private = random.randint(2, DH_P - 2)
    public  = pow(DH_G, private, DH_P)
    return str(private), str(public)


def dh_compute_shared(their_public_str: str, my_private_str: str) -> str:
    """
    Compute shared secret = their_public^my_private mod p
    Both agents arrive at the same number without transmitting private keys.
    Returns SHA-256 of the raw shared value as hex (64 chars = 32 bytes).
    """
    raw    = pow(int(their_public_str), int(my_private_str), DH_P)
    raw_b  = raw.to_bytes((raw.bit_length() + 7) // 8, "big")
    return hashlib.sha256(raw_b).hexdigest()


def derive_session_keys(shared_hex: str) -> dict:
    """
    Derive Vigenere key and Fernet key from the DH shared secret.
      Vigenere key : 8 uppercase letters mapped from first 8 hex nibbles
      Fernet  key  : URL-safe base64 of the 32-byte shared secret
    """
    vigenere_key = "".join(
        chr(ord("A") + int(c, 16) % 26) for c in shared_hex[:8]
    ).upper()
    fernet_key = base64.urlsafe_b64encode(bytes.fromhex(shared_hex)).decode()
    return {"vigenere_key": vigenere_key, "fernet_key": fernet_key}


# ─── Fallback static keys (used before DH completes) ─────────────────────────
_STATIC_VIGENERE = "QUANTUM"
_static_fernet   = Fernet(
    base64.urlsafe_b64encode(hashlib.sha256(b"static-fallback").digest())
)

CAESAR_SHIFT = 7


# ─── Layer 1: Caesar Cipher ───────────────────────────────────────────────────
def caesar_encrypt(text: str, shift: int = CAESAR_SHIFT) -> str:
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)

def caesar_decrypt(text: str, shift: int = CAESAR_SHIFT) -> str:
    return caesar_encrypt(text, -shift)


# ─── Layer 2: Vigenere Cipher ────────────────────────────────────────────────
def vigenere_encrypt(text: str, key: str) -> str:
    key, out, ki = key.upper(), [], 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            k    = ord(key[ki % len(key)]) - ord("A")
            out.append(chr((ord(ch) - base + k) % 26 + base))
            ki  += 1
        else:
            out.append(ch)
    return "".join(out)

def vigenere_decrypt(text: str, key: str) -> str:
    key, out, ki = key.upper(), [], 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            k    = ord(key[ki % len(key)]) - ord("A")
            out.append(chr((ord(ch) - base - k + 26) % 26 + base))
            ki  += 1
        else:
            out.append(ch)
    return "".join(out)


# ─── Full Pipeline ────────────────────────────────────────────────────────────
def encrypt_message(plaintext: str, vigenere_key: str = None, fernet_instance=None) -> dict:
    vk     = vigenere_key    or _STATIC_VIGENERE
    fernet = fernet_instance or _static_fernet
    l1 = caesar_encrypt(plaintext)
    l2 = vigenere_encrypt(l1, vk)
    l3 = fernet.encrypt(l2.encode()).decode()
    return {
        "original": plaintext, "layer1_caesar": l1,
        "layer2_vigenere": l2, "layer3_aes": l3,
        "transmitted": l3, "vigenere_key_used": vk,
    }

def decrypt_message(ciphertext: str, vigenere_key: str = None, fernet_instance=None) -> dict:
    vk     = vigenere_key    or _STATIC_VIGENERE
    fernet = fernet_instance or _static_fernet
    l2       = fernet.decrypt(ciphertext.encode()).decode()
    l1       = vigenere_decrypt(l2, vk)
    original = caesar_decrypt(l1)
    return {
        "received": ciphertext, "layer3_aes": l2,
        "layer2_vigenere": l1, "layer1_caesar": original,
        "original": original, "vigenere_key_used": vk,
    }
