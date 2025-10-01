import base64
import json
from typing import Any, Tuple

_DEF_SEP: Tuple[str, str] = (",", ":")


"""Encoding helpers: base64url (no padding) and canonical JSON"""

def b64u_encode(b: bytes) -> str:
    """Encodes bytes as base64url without padding

    Args:
        b (bytes): Raw bytes to encode

    Returns:
        str: Base64url-encoded string (no '=' padding)

    Raises:
        Exception: If encoding fails unexpectedly
    """

    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

def b64u_decode(s: str) -> bytes:
    """Decodes a base64url string without padding back to bytes

    Args:
        s (str): Base64url-encoded string (may be missing '=' padding)

    Returns:
        bytes: Decoded raw bytes

    Raises:
        binascii.Error: If `s` has invalid base64 characters/length
        Exception: For other decoding errors
    """

    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

def canonical_json_bytes(obj: Any) -> bytes:
    """Serializes an object to canonical JSON bytes

    Canonicalization:
      - Keys sorted (sort_keys=True)
      - Minimal separators (',' and ':')
      - UTF-8 encoded

    Args:
        obj (Any): JSON-serializable object

    Returns:
        bytes: Canonical JSON representation (UTF-8)

    Raises:
        TypeError: If `obj` contains non-JSON-serializable types
        ValueError: If JSON serialization fails
    """

    return json.dumps(obj, sort_keys=True, separators=_DEF_SEP).encode('utf-8')
