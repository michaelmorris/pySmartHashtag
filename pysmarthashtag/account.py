"""Access to geely account for your vehicles therin."""

import datetime
import json
import logging
from dataclasses import InitVar, dataclass, field
from typing import Dict

from pysmarthashtag.api import utils
from pysmarthashtag.api.authentication import SmartAuthentication
from pysmarthashtag.api.authentication_volvo import VolvoAuthentication
from pysmarthashtag.api.client import SmartClient, SmartClientConfiguration
from pysmarthashtag.const import API_BASE_URL, API_BASE_URL_VOLVO, API_CARS_URL, API_SELECT_CAR_URL
from pysmarthashtag.models import SmartAuthError, SmartHumanCarConnectionError, SmartTokenRefreshNecessary
from pysmarthashtag.vehicle.vehicle import SmartVehicle

VALID_UNTIL_OFFSET = datetime.timedelta(seconds=10)

_LOGGER = logging.getLogger(__name__)


@dataclass
class SmartAccount:
    """Create a new connection to the Geely web service."""

    username: str
    """Username for the user identity account."""

    password: str
    """Password for the user identity account."""

    identity_provider: str
    """identity provider, volvo or smart"""

    config: SmartClientConfiguration = None
    """Configuration for the Smart client."""

    log_responses: bool = False
    """Optional. If set, all responses from the server will be logged to this directory."""

    vehicles: Dict[str, SmartVehicle] = field(default_factory=dict, init=False)
    """Vehicles associated with the account."""

    _API_BASE_URL: str = None

    def __post_init__(self):
        """Initialize the account."""           

        if (self.identity_provider is not None):
            if (self.identity_provider == 'volvo'):
                self._API_BASE_URL = API_BASE_URL_VOLVO
            if (self.identity_provider == 'smart'):
                self._API_BASE_URL = API_BASE_URL

        if (self._API_BASE_URL is None):
            self._API_BASE_URL = API_BASE_URL
            self.identity_provider = 'smart'

        if self.config is None:
            if (self.identity_provider == 'smart'):
                self.config = SmartClientConfiguration(
                    SmartAuthentication(self.username, self.password),
                    log_responses=self.log_responses,
                )
            if (self.identity_provider == 'volvo'):
                self.config = SmartClientConfiguration(
                    VolvoAuthentication(self.username, self.password),
                    log_responses=self.log_responses,
                )   

    async def login(self, force_refresh: bool = False) -> None:
        """Get the vehicles associated with the account."""
        if force_refresh is None:
            self.config.authentication = None
        await self.config.authentication.login()



    async def reauth_phase1(self) -> None:
        """Do phase 1 of full reauthentication (login using username and password)"""
        await self.config.authentication.full_login_stage_1()


    async def reauth_phase2(self, otp) -> None:
        """Do phase 2 of full reauthentication (Confirm login using otp code)"""
        await self.config.authentication.full_login_stage_2(otp)

    async def _init_vehicles(self) -> None:
        """Initialize vehicles from geely servers."""
        _LOGGER.debug("Getting initial vehicle list")

        fetched_at = datetime.datetime.now(datetime.timezone.utc)

        async with SmartClient(self.config) as client:
            params = {
                "needSharedCar": 1,
                "userId": self.config.authentication.api_user_id,
            }
            for retry in range(2):
                try:
                    vehicles_response = await client.get(
                        self._API_BASE_URL + API_CARS_URL + "?" + utils.join_url_params(params),
                        headers={
                            **utils.generate_default_header(
                                client.config.authentication,
                                params=params,
                                method="GET",
                                url=API_CARS_URL,
                            )
                        },
                    )
                    _LOGGER.debug(f"Got response {vehicles_response.status_code} from {vehicles_response.text}")
                except SmartTokenRefreshNecessary:
                    _LOGGER.debug(f"Got Token Error, retry: {retry}")
                    continue
                except SmartHumanCarConnectionError:
                    _LOGGER.debug(f"Got Human Car Connection Error, retry: {retry}")
                    self._init_vehicles()
                    continue
                break

            for vehicle in vehicles_response.json()["data"]["list"]:
                _LOGGER.debug(f"Found vehicle {vehicle}")
                self.add_vehicle(vehicle, fetched_at)

    def add_vehicle(self, vehicle, fetched_at):
        """Add a vehicle to the account."""
        self.vehicles[vehicle.get("vin")] = SmartVehicle(self, vehicle, fetched_at=fetched_at)

    async def get_vehicles(self, force_init: bool = False) -> None:
        """Get the vehicles associated with the account."""
        if self.config.authentication.api_user_id is None:
            await self.config.authentication.login()

        _LOGGER.debug("Getting vehicles for account")

        if len(self.vehicles) == 0 or force_init:
            await self._init_vehicles()

        for vin, vehicle in self.vehicles.items():
            _LOGGER.debug(f"Getting vehicle {vehicle.data}")
            await self.select_active_vehicle(vin)
            vehicle_info = await self.get_vehicle_information(vin)
            vehicle.combine_data(vehicle_info)

    async def select_active_vehicle(self, vin) -> None:
        """Select the active vehicle."""
        _LOGGER.debug(f"Selecting vehicle {vin}")
        data = json.dumps(
            {
                "vin": vin,
                "sessionToken": self.config.authentication.api_access_token,
                "language": "",
            }
        )
        async with SmartClient(self.config) as client:
            for retry in range(2):
                try:
                    r_car_info = await client.post(
                        self._API_BASE_URL + API_SELECT_CAR_URL,
                        headers={
                            **utils.generate_default_header(
                                client.config.authentication,
                                params={},
                                method="POST",
                                url=API_SELECT_CAR_URL,
                                body=data,
                            )
                        },
                        data=data,
                    )
                    _LOGGER.debug(f"Got response {r_car_info.status_code} from {r_car_info.text}")
                except SmartTokenRefreshNecessary:
                    _LOGGER.debug(f"Got Token Error, retry: {retry}")
                    continue
                except SmartHumanCarConnectionError:
                    _LOGGER.debug(f"Got Human Car Connection Error, retry: {retry}")
                    self.select_active_vehicle(vin)
                    continue
                break

    async def get_vehicle_information(self, vin) -> str:
        """Get information about a vehicle."""
        _LOGGER.debug(f"Getting information for vehicle {vin}")
        params = {
            "latest": True,
            "target": "basic%2Cmore",
            "userId": self.config.authentication.api_user_id,
        }
        data = {}
        async with SmartClient(self.config) as client:
            for retry in range(2):
                try:
                    r_car_info = await client.get(
                        self._API_BASE_URL + "/remote-control/vehicle/status/" + vin + "?" + utils.join_url_params(params),
                        headers={
                            **utils.generate_default_header(
                                client.config.authentication,
                                params=params,
                                method="GET",
                                url="/remote-control/vehicle/status/" + vin,
                            )
                        },
                    )
                    _LOGGER.debug(f"Got response {r_car_info.status_code} from {r_car_info.text}")
                    self.vehicles.get(vin).combine_data(r_car_info.json()["data"])
                    data = r_car_info.json()["data"]
                except SmartTokenRefreshNecessary:
                    _LOGGER.debug(f"Got Token Error, retry: {retry}")
                    continue
                except SmartHumanCarConnectionError:
                    _LOGGER.debug(f"Got Human Car Connection Error, retry: {retry}")
                    self.select_active_vehicle(vin)
                    continue
                break
            if retry > 1:
                raise SmartAuthError("Could not get vehicle information")
        return data
