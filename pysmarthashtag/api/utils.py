import base64
import hashlib
import hmac
import logging
import secrets
import time

_LOGGER = logging.getLogger(__name__)


def join_url_params(args: dict) -> str:
    """Join params for adding to URL."""
    return "&".join([f"{key}={value}" for key, value in args.items()])


def create_correct_timestamp() -> str:
    """Create a correct timestamp for the request."""
    return str(int(time.time() * 1000))


def _create_sign(nonce: str, params: dict, timestamp: str, method: str, url: str, body=None) -> str:
    """Create a signature for the request."""
    md5sum = base64.b64encode(hashlib.md5(body.encode()).digest()).decode() if body else "1B2M2Y8AsgTpgAmY7PhCfg=="
    url_params = join_url_params(params)
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


def generate_default_header(
    device_id: str, access_token: str, params: dict, method: str, url: str, body=None
) -> dict[str, str]:
    """Generate a header for HTTP requests to the server."""
    timestamp = create_correct_timestamp()
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
        "x-timestamp": str(timestamp),
    }
    if access_token:
        header["authorization"] = access_token

    _LOGGER.debug(
        f"Constructed Login: {join_url_params(params)} - {access_token} - {method} - {url} - {body} -> {header}"
    )
    return header


def _create_sign_v2(timestamp: str, access_token: str, method: str, url: str, body=None) -> str:
    """Create a signature for the request."""
    # Handle None values by converting to empty strings
    timestamp_str = timestamp if timestamp is not None else ""
    access_token_str = access_token if access_token is not None else ""
    body_str = body if body is not None else ""

    to_sign = timestamp_str + access_token_str + body_str
    xs_sign_value = hashlib.sha256(to_sign.encode()).hexdigest()
    _LOGGER.info("Signature: %s", xs_sign_value)
    _LOGGER.info("Token 3/3: %s", access_token)
    return xs_sign_value


def generate_default_header_v2(device_id: str, access_token: str, method: str, url: str, body=None) -> dict[str, str]:
    """Generate a header for HTTP requests to the server."""
    timestamp = create_correct_timestamp()
    _LOGGER.info("Token 2/3: %s", access_token)
    sign = _create_sign_v2(timestamp, access_token, method, url, body)
    header = {
        "accept": "*/*",
        # "cookie": "gmid=gmid.ver4.AcbHPqUK5Q.xOaWPhRTb7gy-6-GUW6cxQVf_t7LhbmeabBNXqqqsT6dpLJLOWCGWZM07EkmfM4j.u2AMsCQ9ZsKc6ugOIoVwCgryB2KJNCnbBrlY6pq0W2Ww7sxSkUa9_WTPBIwAufhCQYkb7gA2eUbb6EIZjrl5mQ.sc3; ucid=hPzasmkDyTeHN0DinLRGvw; hasGmid=ver4; gig_bootstrap_3_L94eyQ-wvJhWm7Afp1oBhfTGXZArUfSHHW9p9Pncg513hZELXsxCfMWHrF8f5P5a=auth_ver4",  # noqa: E501
        "connection": "keep-alive",
        "user-agent": "Hello smart/2.0.3 (iPhone; iOS 26.0; Scale/3.00)",
        "xs-auth-token": access_token,
        "xs-sign-value": sign,
        "xs-app-ver": "2.0.3",
        "xs-os": "iOS",
        "xs-sign-uuid": device_id,
        "xs-sign-timestamp": str(timestamp),
        "xs-sign-type": "SHA256",
        "xs-channel-id": "APP_EU",
        "content-type": "application/json",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": "en-US,en;q=0.9",
    }

    _LOGGER.info(f"Constructed Headers: {header}")
    return header
