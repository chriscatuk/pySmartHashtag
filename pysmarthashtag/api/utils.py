import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Dict

_LOGGER = logging.getLogger(__name__)

def _create_sign(nonce, params, timestamp, method, url, body=None):
    """Create a signature for the request."""
    md5sum = base64.urlsafe_b64encode(hashlib.md5(json.dumps(body).encode('utf-8')).digest()).decode() if body else "1B2M2Y8AsgTpgAmY7PhCfg=="
    url_params = "&".join([f"{key}={value}" for key, value in params.items()])
    payload = f"""application/json;responseformat=3
x-api-signature-nonce:{nonce}
x-api-signature-version:1.0

{url_params}
{md5sum}
{timestamp}
{method}
{url}"""
    _LOGGER.debug("Payload: %s", payload)
    secret = base64.b64decode("NzRlNzQ2OWFmZjUwNDJiYmJlZDdiYmIxYjM2YzE1ZTk=")
    payload = payload.encode("utf-8")
    hashed = hmac.new(secret, payload, hashlib.sha1).digest()
    signature = base64.b64encode(hashed).decode()
    _LOGGER.debug("Signature: %s", signature)
    return signature

def generate_default_header(device_id, access_token, params, method: str, url: str, body=None) -> Dict[str, str]:
    """Generate a header for HTTP requests to the server."""
    timestamp = int(time.time())
    nonce = secrets.token_hex(8)
    sign = _create_sign(nonce, params, timestamp, method, url, body)
    header = {
        "x-app-id": "SmartAPPEU",
        "accept": "application/json;responseformat=3",
        "x-agent-type": "iOS",
        "x-device-type": "mobile",
        "x-operator-code": "SMART",
        "x-device-identifier": device_id,
        "x-env-type": "production",
        "x-version": "smartNew",
        "accept-language": "en_US",
        "x-api-signature-version": "1.0",
        "x-api-signature-nonce": nonce,
        "x-device-manufacture": "Apple",
        "x-device-brand": "Apple",
        "x-device-model": "iPhone",
        "x-agent-version": "17.1",
        "content-type": "application/json; charset=utf-8",
        "user-agent": "Hello smart/1.4.0 (iPhone; iOS 17.1; Scale/3.00)",
        "x-signature": sign,
        "x-timestamp": str(timestamp)
    }
    if access_token:
        header["authorization"] = access_token

    _LOGGER.debug("Header: %s", header)
    return header
