"""Authentication management for Smart APIs."""

import asyncio
import datetime
import json
import logging
import math
import secrets
from collections import defaultdict
from typing import AsyncGenerator, Generator, Optional

import httpx
from httpx._models import Request, Response

from pysmarthashtag.api import utils
from pysmarthashtag.const import (
    API_BASE_URL_VOLVO,
    API_KEY_VOLVO,
    APP_ID_VOLVO,
    AUTH_URL_VOLVO,
    TOKEN_URL_VOLVO,
    AUTHN_FLOW_URL_VOLVO,
    HTTPX_TIMEOUT,
    API_SESION_URL,
)   
from pysmarthashtag.models import SmartAPIError

EXPIRES_AT_OFFSET = datetime.timedelta(seconds=HTTPX_TIMEOUT * 2)

_LOGGER = logging.getLogger(__name__)

from pysmarthashtag.api.abstractauthentication import AbstractAuthentication


class VolvoAuthentication(AbstractAuthentication):
    """Authentication and Retry Handler for the Volvo API."""
    def __init__(
        self,   
        username: str,
        password: str,
        access_token: Optional[str] = None,
        expires_at: Optional[datetime.datetime] = None,
        refresh_token: Optional[str] = None,
    ):
        self.username: str = username
        self.password: str = password
        self.access_token: Optional[str] = access_token
        self.expires_at: Optional[datetime.datetime] = expires_at
        self.refresh_token: Optional[str] = refresh_token
        self.device_id: str = secrets.token_hex(8)
        self._lock: Optional[asyncio.Lock] = None
        self.api_access_token: Optional[str] = None
        self.api_refresh_token: Optional[str] = None
        self.api_user_id: Optional[str] = None
        self.is_two_step: Optional[bool] = True
        self.shared_client = None
        _LOGGER.debug("Device ID: %s", self.device_id)

    async def _init_login(self):
        """Login to Volvo ID (stage 1 - username and password and OTP generation)."""
        client = VolvoLoginClient()
        self.shared_client = client
        
        # Get login id
        r_login_id = await client.get(
            AUTH_URL_VOLVO + "?acr_values=urn%3Avolvoid%3Aaal%3Abronze%3A2sv&client_id=wgiamte_10&response_mode=pi.flow&response_type=code&scope=openid%20profile%20email",
            headers={'user-agent': 'ex30-ios/1.6.0'},
            follow_redirects=True,
        )
        try:
            login_id = r_login_id.json()["id"]
            client.login_id = login_id
            _LOGGER.debug("Login id: %s", login_id)
        except KeyError:
            client.aclose()
            raise SmartAPIError("Could not get login id from login flow")

        # Do username and password auth

        r_login_pw = await client.post(
            AUTHN_FLOW_URL_VOLVO + client.login_id + "?action=checkUsernamePassword",
            data="{\"password\":\"" + self.password + "\",\"username\":\"" + self.username + "\"}",
            headers={
                'user-agent': 'ex30-ios/1.6.0',
                'X-Xsrf-Header': 'PingFederate'
            },
        )
        try:
            pw_login_result = r_login_pw.json()
            if (pw_login_result["status"] != "OTP_REQUIRED"):
                raise SmartAPIError("Username and password login failed")
        except (KeyError, ValueError):
            client.aclose()
            raise SmartAPIError("Username and password login failed")

        return "REQUIRES_OTP"

    async def _login(self, otp):
        """Login to Volvo ID (stage 2 - otp input and login to geely platform)."""
        client = self.shared_client

        _LOGGER.info("Aquiring access token.")

        r_login_otp = await client.post(
            AUTHN_FLOW_URL_VOLVO + client.login_id + "?action=checkOtp",
            data="{\"otp\":\"" + otp + "\"}",
            headers={
                'user-agent': 'ex30-ios/1.6.0',
                'X-Xsrf-Header': 'PingFederate'
            },
        )
        try:
            otp_login_result = r_login_otp.json()
            if (otp_login_result["status"] != "OTP_VERIFIED"):
                raise SmartAPIError("OTP Verification failed")
        except (KeyError, ValueError):
            client.aclose()
            raise SmartAPIError("OTP Verification failed")

        r_login_continue = await client.post(
            AUTHN_FLOW_URL_VOLVO + client.login_id + "?action=continueAuthentication",
            data='{}',
            headers={
                'user-agent': 'ex30-ios/1.6.0',
                'X-Xsrf-Header': 'PingFederate'
            },
        )
        try:
            login_result = r_login_continue.json()
            login_code = login_result["authorizeResponse"]["code"]
        except (KeyError, ValueError):
            client.aclose()
            raise SmartAPIError("Could not get login code from login flow")

        auth_url = TOKEN_URL_VOLVO + "?code=" + login_code + "&grant_type=authorization_code"
        r_auth = await client.post(
            auth_url,
            headers={
                'user-agent': 'ex30-ios/1.6.0',
                'Authorization': 'Basic d2dpYW10ZV8xMDp3M3R6a2w2ZWR1dTIxZnAydGF0ZmhxbnpjaHlseGlvb3RjYW90azAyN24yMDBrZ3lzZWxxMTFuYzYzdXloYzZw'
            },
        )
        try:
            print(r_auth.text)
            auth_result = r_auth.json()
            access_token = auth_result["access_token"]
            refresh_token = auth_result["refresh_token"]
            expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                seconds=int(auth_result["expires_in"]))
        except KeyError:
            client.aclose()
            raise SmartAPIError ("Could not get access token from auth page")

        data = json.dumps({"accessToken": access_token}).replace(" ", "")

        r_api_access = await client.post(
            API_BASE_URL_VOLVO + API_SESION_URL + "?identity_type=volvo-global",
            headers={
                **utils.generate_default_header(
                    self,
                    params={
                        "identity_type": "volvo-global",
                    },
                    method="POST",
                    url=API_SESION_URL,
                    body=data,
                )
            },
            data=data,
        )
        api_result = r_api_access.json()
        _LOGGER.debug("API access result: %s", api_result)
        try:
            api_access_token = api_result["data"]["accessToken"]
            api_refresh_token = api_result["data"]["refreshToken"]
            api_user_id = api_result["data"]["userId"]
        except KeyError:
            client.aclose()
            raise SmartAPIError("Could not get API access token from API")


            client.aclose()
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "api_access_token": api_access_token,
            "api_refresh_token": api_refresh_token,
            "api_user_id": api_user_id,
            "expires_at": expires_at,
        }


class VolvoLoginClient(httpx.AsyncClient):
    """Client to login to the Volvo API."""

    login_id = None

    def __init__(self, *args, **kwargs):
        # Increase timeout to 30 seconds
        kwargs["timeout"] = httpx.Timeout(HTTPX_TIMEOUT)

        # Register event hooks
        kwargs["event_hooks"] = defaultdict(list, **kwargs.get("event_hooks", {}))

        # Event hook for raise_for_status on all requests
        async def raise_for_status_handler(response: httpx.Response):
            """Eventhandler that automaticvalle raises HTTPStatusError when attached to a request.

            Only raise on 4xx/5xx errors but not on 429.
            """
            if response.is_error and response.status_code != 429:
                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    _LOGGER.error(
                        "Error handling request %s: %s",
                        response.url,
                        exc,
                    )
                    raise

        kwargs["event_hooks"]["response"].append(raise_for_status_handler)

        async def log_request(request):
            if request.method == "POST":
                await request.aread()
                _LOGGER.debug(
                    f"Request: {request.method} {request.url} - {request.content.decode()} - {request.headers}"
                )
            else:
                _LOGGER.debug(f"Request: {request.method} {request.url}")

        async def log_response(response):
            await response.aread()
            request = response.request
            _LOGGER.debug(f"Response: {request.method} {request.url} - Status {response.status_code}")

        kwargs["event_hooks"]["response"].append(log_response)
        kwargs["event_hooks"]["request"].append(log_request)

        super().__init__(**kwargs)


class VolvoLoginRetry(httpx.Auth):
    """httpx.Auth uses as waorkauround to retry and sleep in 429."""

    def sync_auth_flow(self, request: Request) -> Generator[Request, Response, None]:
        raise RuntimeError("Cannot use a async authentication class with httpx.Client")

    async def async_auth_flow(self, request: Request) -> AsyncGenerator[Request, Response]:
        # Try getting a response
        response: httpx.Response = yield request

        for _ in range(3):
            if response.status_code == 429:
                await response.aread()
                wait_time = get_retry_wait_time(response)
                _LOGGER.debug("Rate limit exceeded. Waiting %s seconds", wait_time)
                await asyncio.sleep(wait_time)
                response = yield request

                # Only checking for 429 errors, all other errors are raised in SmartLoginClient
                if response.status_code == 429:
                    try:
                        response.raise_for_status()
                    except httpx.HTTPStatusError as exc:
                        _LOGGER.error(
                            "Error handling request %s: %s",
                            request.url,
                            exc,
                        )
                        raise


def get_retry_wait_time(response: httpx.Response) -> int:
    """Get the wait time to wait twice as long before retrying."""
    try:
        retry_after = next(iter([int(i) for i in response.json().get("message", "") if i.isdigit()]))
    except Exception:
        retry_after = 2
    return math.ceil(retry_after * 2)
