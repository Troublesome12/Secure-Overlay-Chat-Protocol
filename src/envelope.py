import time
from typing import Any, Dict
from crypto import RSAKeys

"""SOCP envelope creation and signing

Per SOCP, signatures are computed over the canonical **payload** only
"""

def make_env(msg_type: str, frm: str, to: str, payload: Dict[str, Any], keys: RSAKeys) -> Dict[str, Any]:
    """Creates a signed SOCP envelope

    Args:
        msg_type (str): SOCP message type (e.g., "MSG_PRIVATE", "USER_ADVERTISE")
        frm (str): Sender identifier (server_uuid or user_uuid)
        to (str): Recipient identifier ("server_uuid", "user_uuid", or "*")
        payload (Dict[str, Any]): Message-specific payload object to be signed
        keys (RSAKeys): RSA key wrapper used to sign the payload (RSASSA-PSS/SHA-256)

    Returns:
        Dict[str, Any]: A JSON-ready envelope with fields:
            {
              "type": <msg_type>,
              "from": <frm>,
              "to": <to>,
              "ts": <unix_ms>,
              "payload": <payload>,
              "sig": <base64url signature over canonical payload>
            }
    """

    env = {
        "type": msg_type,
        "from": frm,
        "to": to,
        "ts": int(time.time() * 1000),
        "payload": payload,
        "sig": "",
    }
    env["sig"] = keys.sign_payload(payload)
    return env
