from __future__ import annotations

import pathlib
from dataclasses import dataclass
from typing import Any, Iterator, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asy_padding
from cryptography.hazmat.primitives import serialization, hashes

from encoding import b64u_encode, b64u_decode, canonical_json_bytes

"""
Cryptographic primitives for SOCP v1.3 (RSA-only)

This module provides:
- RSAKeys: Key management for an RSA-4096 keypair (load-or-create),
           public-key export (DER->base64url), and payload signing/verify
           using RSASSA-PSS(SHA-256).
- RSA-OAEP(SHA-256) helpers:
    * rsa_encrypt(pub_der_b64u, plaintext: bytes) -> base64url
    * rsa_decrypt(priv, ciphertext_b64u: str) -> bytes
    * rsa_chunk_iter(data: bytes, chunk_size: int = 446) -> (index, chunk)
      (446 is the safe max single-block OAEP payload for 4096-bit RSA with SHA-256)

Design notes:
- We use **RSA-4096** for both *signatures* (PSS/SHA-256) and *confidentiality*
  (OAEP/SHA-256). This is intentionally simple for the project and matches your
  “RSA-only” v1.3 requirement. If you later reintroduce hybrid crypto, add an
  AEAD (e.g., AES-256-GCM) and only wrap the symmetric key with RSA-OAEP.
- Public keys are transported as DER(SPKI) encoded with **base64url (no padding)**
  for convenient JSON embedding.
"""


__all__ = [
    "RSAKeys",
    "rsa_encrypt",
    "rsa_decrypt",
    "rsa_chunk_iter",
    "RSA4096_OAEP_MAX",
]

# --- RSA-4096 OAEP(SHA-256) single-block plaintext size -----------------------
# For RSA modulus n = 4096 bits => 512 bytes.
# OAEP with SHA-256: max message length = k - 2*hLen - 2
#   where k = 512, hLen = 32 (SHA-256 digest size)
# => 512 - 2*32 - 2 = 446 bytes
RSA4096_BYTES = 512
SHA256_LEN = 32
RSA4096_OAEP_MAX = RSA4096_BYTES - 2 * SHA256_LEN - 2  # 446


@dataclass
class RSAKeys:
    """
    Container for an RSA-4096 private/public keypair used in SOCP v1.3.

    Responsibilities:
    - Persist/restore the private key in PKCS#8 PEM format (unencrypted file).
    - Export public key as DER(SPKI) ➝ base64url for JSON transport.
    - Sign/verify canonicalized JSON payloads with RSASSA-PSS(SHA-256).

    Example:
        >>> keys = RSAKeys.load_or_create(Path("data/user.pem"))
        >>> pub_b64 = keys.pub_der_b64u()
        >>> sig = keys.sign_payload({"msg":"hi", "ts":123})
        >>> RSAKeys.verify_payload(pub_b64, {"msg":"hi", "ts":123}, sig)
        True
    """
    priv: rsa.RSAPrivateKey
    pub: rsa.RSAPublicKey

    # ---- Construction / Persistence -----------------------------------------

    @staticmethod
    def load_or_create(path: pathlib.Path, bits: int = 4096) -> "RSAKeys":
        """
        Load an RSA private key from PEM; create and save one if missing.

        Args:
            path: Filesystem path of the PEM file.
            bits: Key size in bits (default 4096).

        Returns:
            RSAKeys: wrapper holding the private/public keypair.
        """
        if path.exists():
            data = path.read_bytes()
            priv = serialization.load_pem_private_key(data, password=None)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
            pem = priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            path.write_bytes(pem)
        return RSAKeys(priv=priv, pub=priv.public_key())

    # ---- Public key export ---------------------------------------------------

    def pub_der_b64u(self) -> str:
        """
        Export the public key as DER(SPKI), encoded with base64url (no padding).

        Returns:
            Base64url string suitable for JSON transport.
        """
        der = self.pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return b64u_encode(der)

    # ---- Sign / Verify (RSASSA-PSS, SHA-256) --------------------------------

    def sign_payload(self, payload_obj: Any) -> str:
        """
        Sign a JSON-serializable payload using RSASSA-PSS(SHA-256).

        The payload is first canonicalized via `encoding.canonical_json_bytes`
        to ensure stable bytes over the wire (key order, separators).

        Args:
            payload_obj: Any JSON-serializable object.

        Returns:
            Base64url signature string.
        """
        sig = self.priv.sign(
            canonical_json_bytes(payload_obj),
            asy_padding.PSS(
                mgf=asy_padding.MGF1(hashes.SHA256()),
                salt_length=asy_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return b64u_encode(sig)

    @staticmethod
    def verify_payload(pub_der_b64u: str, payload_obj: Any, sig_b64u: str) -> bool:
        """
        Verify a payload signature using the given public key.

        Args:
            pub_der_b64u: Public key as DER(SPKI) base64url.
            payload_obj:  The JSON-serializable object that was signed.
            sig_b64u:     Base64url signature string to verify.

        Returns:
            True if signature is valid; False otherwise.
        """
        try:
            pub = serialization.load_der_public_key(b64u_decode(pub_der_b64u))
            pub.verify(
                b64u_decode(sig_b64u),
                canonical_json_bytes(payload_obj),
                asy_padding.PSS(
                    mgf=asy_padding.MGF1(hashes.SHA256()),
                    salt_length=asy_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False


# ---- RSA-OAEP(SHA-256) convenience helpers ----------------------------------

def rsa_chunk_iter(data: bytes, chunk_size: int = RSA4096_OAEP_MAX) -> Iterator[Tuple[int, bytes]]:
    """
    Yield `(index, chunk)` slices of `data` that fit a single RSA-OAEP block.

    Use this when you need to encrypt arbitrarily long byte streams by
    sending multiple RSA-OAEP blocks.

    Args:
        data:       Raw bytes to split.
        chunk_size: Max OAEP block payload (default 446 for RSA-4096 + SHA-256).

    Yields:
        (index, chunk) pairs where `index` starts at 0.
    """
    for i in range(0, len(data), chunk_size):
        yield (i // chunk_size, data[i:i + chunk_size])


def rsa_encrypt(pub_der_b64u: str, plaintext: bytes) -> str:
    """
    Encrypt a small blob with RSA-4096 OAEP(SHA-256) -> base64url ciphertext.

    Note:
        For large payloads, split first with `rsa_chunk_iter()` and encrypt each
        chunk separately.

    Args:
        pub_der_b64u: Recipient public key (DER(SPKI) base64url).
        plaintext:    Bytes to encrypt (<= 446B per block).

    Returns:
        Base64url-encoded ciphertext.
    """
    pub = serialization.load_der_public_key(b64u_decode(pub_der_b64u))
    ct = pub.encrypt(
        plaintext,
        asy_padding.OAEP(
            mgf=asy_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return b64u_encode(ct)


def rsa_decrypt(priv: rsa.RSAPrivateKey, ciphertext_b64u: str) -> bytes:
    """
    Decrypt an RSA-4096 OAEP(SHA-256) base64url ciphertext -> bytes.

    Args:
        priv:              Recipient private key.
        ciphertext_b64u:   Base64url-encoded ciphertext.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        Exception on malformed ciphertext or verify failure.
    """
    ct = b64u_decode(ciphertext_b64u)
    pt = priv.decrypt(
        ct,
        asy_padding.OAEP(
            mgf=asy_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return pt
