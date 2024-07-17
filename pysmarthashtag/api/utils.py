import base64
import hashlib
import hmac
import logging
import secrets
import time
from typing import Dict

_LOGGER = logging.getLogger(__name__)


def join_url_params(args: Dict) -> str:
    """Join params for adding to URL."""
    return "&".join([f"{key}={value}" for key, value in args.items()])


def _create_sign(nonce: str, params: Dict, timestamp: str, method: str, url: str, body=None) -> str:
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
    secret = base64.b64decode("MGU0MzFhZGY0YmY5NGE2YWI3YmUyYzY4NjhkNGMwNjQ=")
    payload = payload.encode("utf-8")
    hashed = hmac.new(secret, payload, hashlib.sha1).digest()
    signature = base64.b64encode(hashed).decode()
    _LOGGER.debug("Signature: %s", signature)
    return signature


def generate_default_header(
    device_id: str, access_token: str, params: Dict, method: str, url: str, body=None
) -> Dict[str, str]:
    """Generate a header for HTTP requests to the server."""
    timestamp = create_correct_timestamp()
    nonce = secrets.token_hex(8)
    sign = _create_sign(nonce, params, timestamp, method, url, body)
    header = {
        "X-App-Id": "volvo_global_app",
	"platform": "NON-CMA",
        "accept": "application/json;responseformat=3",
        "x-agent-type": "iOS",
	"x-operator-code": "VOLVO-GLOBAL",
        "x-device-type": "mobile",
        "x-device-identifier": device_id,
        "x-env-type": "production",
        "accept-language": "en_GB",
        "x-api-signature-version": "1.0",
        "x-api-signature-nonce": nonce,
        "x-device-manufacture": "Apple",
        "x-device-brand": "Apple",
        "x-device-model": "iPhone",
        "x-agent-version": "17.5.1",
        "content-type": "application/json; charset=utf-8",
        "user-agent": "volvocar/1.6.0 (iPhone; iOS 17.5.1; Scale/3.00)",
        "x-signature": sign,
        "x-timestamp": str(timestamp),
    }
    if access_token:
        header["authorization"] = access_token

    _LOGGER.debug(
        f"Constructed Login: {join_url_params(params)} - {access_token} - {method} - {url} - {body} -> {header}"
    )
    return header


def create_correct_timestamp() -> str:
    """Create a correct timestamp for the request."""
    return str(int(time.time() * 1000))
