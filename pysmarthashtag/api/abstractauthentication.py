from abc import ABC, abstractmethod

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
from pysmarthashtag.models import SmartReauthenicationRequired

EXPIRES_AT_OFFSET = datetime.timedelta(seconds=HTTPX_TIMEOUT * 2)

_LOGGER = logging.getLogger(__name__)

class AbstractAuthentication(ABC):
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
        self.is_two_step: Optional[bool] = False
        _LOGGER.debug("Device ID: %s", self.device_id)

    @property
    def login_lock(self) -> asyncio.Lock:
        """Make sure there is only one login at a time."""
        if not self._lock:
            self._lock = asyncio.Lock()
        return self._lock

    def sync_auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        """Handle synchronous authentication flow for requests."""
        raise RuntimeError("Cannot use an async authentication class with httpx.Client")

    async def async_auth_flow(self, request: Request) -> AsyncGenerator[Request, Response]:
        """Asynchronous authentication flow for handling requests."""
        _LOGGER.debug("Handling request %s", request.url)
        # Get an initial login on first call
        async with self.login_lock:
            if not self.access_token:
                await self.login()
        request.headers["Authorization"] = f"Bearer {self.access_token}"

        response: httpx.Response = yield request

        if response.is_success:
            return

        await response.aread()

        retry_count = 0
        while (
            response.status_code == 429 or (response.status_code == 403 and "quota" in response.text.lower())
        ) and retry_count < 3:
            wait_time = get_retry_wait_time(response)
            _LOGGER.debug("Rate limit exceeded. Waiting %s seconds", wait_time)
            await asyncio.sleep(wait_time)
            response = yield request
            await response.aread()
            retry_count += 1

        if response.status_code == 401:
            async with self.login_lock:
                _LOGGER.debug("Token expired. Refreshing token")
                await self.login()
                request.headers["Authorization"] = f"Bearer {self.access_token}"

            _LOGGER.debug("Token expired. Refreshing token")
            await self.login()
            request.headers["Authorization"] = f"Bearer {self.access_token}"
            response = yield request
            await response.aread()

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            _LOGGER.error(
                "Error handling request %s: %s",
                request.url,
                exc,
            )
            raise

    async def login(self) -> None:
        """Login to the identity provider and geely API."""
        """Identity providers that need two step login process (volvo) can only use this method if there is a valid refresh token available, if not then a full reauthentication is needed"""
        _LOGGER.debug("Logging in to identity provider and geely API")
        token_data = {}
        if self.refresh_token:
            token_data = await self._refresh_access_token()
        if not token_data:
            if (self.is_two_step):
                raise SmartReauthenicationRequired("Full reauthentication required")
            else:
                token_data = await self._login(self, None)
        try:
            token_data["expires_at"] = token_data["expires_at"] - EXPIRES_AT_OFFSET

            self.access_token = token_data["access_token"]
            self.refresh_token = token_data["refresh_token"]
            self.api_access_token = token_data["api_access_token"]
            self.api_refresh_token = token_data["api_refresh_token"]
            self.api_user_id = token_data["api_user_id"]
            self.expires_at = token_data["expires_at"]
            _LOGGER.debug(f"Login successful: {token_data}")
            return "success"
        except KeyError:
            raise SmartAPIError("Could not login to Smart API")

    async def full_login_stage_1(self) -> None:
        """Some identity providers (volvo) need a two stage login process as we need to prompt back to the user mid way through for an OTP code"""
        """This method is used for that first step, for other identity providers this is unnecessary and should not be called"""
        _LOGGER.debug("Full login/reauthentication in to identity provider and geely API - stage 1 (username/password login)")

        result = await self._init_login()
        print(result)
        if (result == "REQUIRES_OTP"):
            return "otp required"
        else:
            raise SmartAPIError("Could not login to Smart API")

    async def full_login_stage_2(self, otp) -> None:
        """Some identity providers (volvo) need a two stage login process as we need to prompt back to the user mid way through for an OTP code"""
        """This method is used for that second step, for other identity providers this is unnecessary and should not be called"""
        _LOGGER.debug("Full login/reauthentication in to identity provider and geely API - stage 2 (OTP Code)")
        token_data = {}
        token_data = await self._login(otp)
        try:
            token_data["expires_at"] = token_data["expires_at"] - EXPIRES_AT_OFFSET

            self.access_token = token_data["access_token"]
            self.refresh_token = token_data["refresh_token"]
            self.api_access_token = token_data["api_access_token"]
            self.api_refresh_token = token_data["api_refresh_token"]
            self.api_user_id = token_data["api_user_id"]
            self.expires_at = token_data["expires_at"]
            _LOGGER.debug(f"Login successful: {token_data}")
            return "success"
        except KeyError:
            raise SmartAPIError("Could not login to Smart API")


    async def _refresh_access_token(self):
        """Refresh the access token."""
        try:
            async with SmartLoginClient() as _:
                _LOGGER.debug("Refreshing access token via relogin because refresh token is not implemented")
                await self._login()
        except SmartAPIError:
            _LOGGER.debug("Refreshing access token failed. Logging in again")
            return {}

    @abstractmethod
    async def _login(self, otp):
        """Do second step actual login to identity provider and geely api"""


    @abstractmethod
    async def _init_login(self):
        """Do first step actual login to identity provider and geely api"""