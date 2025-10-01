from __future__ import annotations

import pathlib

from dataclasses import dataclass
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from encoding import b64u_encode, b64u_decode, canonical_json_bytes


"""Cryptographic primitives for SOCP

- RSA-4096 keys for signatures (RSASSA-PSS/SHA-256) and key wrapping (RSA-OAEP/SHA-256)
- AES-256-GCM for content confidentiality/integrity (AEAD).
- Public keys encoded as DER(SPKI) then base64url (no padding) for JSON transport
"""

@dataclass
class RSAKeys:
    """Container for an RSA-4096 private/public keypair"""

    priv: rsa.RSAPrivateKey
    pub: rsa.RSAPublicKey

    @staticmethod
    def load_or_create(path: pathlib.Path, bits: int = 4096) -> RSAKeys:
        """Loads an RSA private key from PEM, or creates and saves one if missing

        Args:
            path (pathlib.Path): Filesystem path of the PEM file
            bits (int): Key size in bits (default 4096)

        Returns:
            RSAKeys: Wrapper with loaded or newly generated keypair
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

    def pub_der_b64u(self) -> str:
        """Exports the public key as DER(SPKI) encoded with base64url (no padding)

        Returns:
            str: Base64url-encoded DER public key
        """

        der = self.pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return b64u_encode(der)

    def sign_payload(self, payload_obj: Any) -> str:
        """Signs a JSON-serializable payload (canonicalized) with RSASSA-PSS/SHA-256

        Args:
            payload_obj (Any): Object serialized via `canonical_json_bytes()`

        Returns:
            str: Base64url signature
        """

        sig = self.priv.sign(
            canonical_json_bytes(payload_obj),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return b64u_encode(sig)

    @staticmethod
    def verify_payload(pub_der_b64u: str, payload_obj: Any, sig_b64u: str) -> bool:
        """Verifies a payload signature using the provided DER(SPKI) public key

        Args:
            pub_der_b64u (str): Base64url DER(SPKI) public key
            payload_obj (Any): Object serialized via `canonical_json_bytes()`
            sig_b64u (str): Base64url signature to verify

        Returns:
            bool: True if the signature is valid; False otherwise

        Raises:
            Exception: On malformed inputs (caught and returned as False)
        """

        try:
            pub = serialization.load_der_public_key(b64u_decode(pub_der_b64u))
            pub.verify(
                b64u_decode(sig_b64u),
                canonical_json_bytes(payload_obj),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False


# ---- End-to-end helpers (AES-256-GCM + RSA-OAEP) --------------------------------


def e2e_encrypt_for(recipient_pub_der_b64u: str, plaintext: bytes) -> Dict[str, str]:
    """Encrypts `plaintext` for a recipient using AES-256-GCM and RSA-OAEP key wrap

    Args:
        recipient_pub_der_b64u (str): Recipient public key in base64url DER(SPKI)
        plaintext (bytes): Message bytes to encrypt

    Returns:
        Dict[str, str]: JSON-ready fields (all base64url, no padding):
            {
              "ciphertext": ...,
              "iv": ...,
              "tag": ...,
              "wrapped_key": ...
            }
    """

    import os
    key = os.urandom(32)
    iv  = os.urandom(12)
    ct_tag = AESGCM(key).encrypt(iv, plaintext, None)
    ciphertext, tag = ct_tag[:-16], ct_tag[-16:]
    pub = serialization.load_der_public_key(b64u_decode(recipient_pub_der_b64u))
    wrapped_key = pub.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return {
        "ciphertext": b64u_encode(ciphertext),
        "iv":         b64u_encode(iv),
        "tag":        b64u_encode(tag),
        "wrapped_key":b64u_encode(wrapped_key),
    }

def e2e_decrypt_with(privkey: rsa.RSAPrivateKey, bundle: Dict[str, str]) -> bytes:
    """Decrypts an AES-256-GCM bundle using RSA-OAEP-wrapped key

    Args:
        privkey (rsa.RSAPrivateKey): Recipient RSA private key
        bundle (Dict[str, str]): Fields from `e2e_encrypt_for`: ciphertext, iv, tag, wrapped_key

    Returns:
        bytes: Decrypted plaintext
    """

    key = privkey.decrypt(
        b64u_decode(bundle["wrapped_key"]),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    iv = b64u_decode(bundle["iv"])
    ct = b64u_decode(bundle["ciphertext"]) + b64u_decode(bundle["tag"])
    return AESGCM(key).decrypt(iv, ct, None)
