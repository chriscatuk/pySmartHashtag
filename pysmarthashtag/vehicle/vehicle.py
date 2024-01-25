"""State and remote services of one vehicle."""

import datetime
import logging
from typing import Optional

from pysmarthashtag.vehicle.battery import Battery

_LOGGER = logging.getLogger(__name__)

class SmartVehicle:
    """Models state and remote services of one vehicle.

    :param account: The account associated with the vehicle.
    :param attributes: attributes of the vehicle as provided by the server.
    """

    data: dict = {}

    battery: Optional[Battery] = None

    def __init__(
        self,
        account: "SmartAccount",  # noqa: F821
        vehicle_base: dict,
        vehicle_state: Optional[dict] = None,
        charging_settings: Optional[dict] = None,
        fetched_at: Optional[datetime.datetime] = None,
    ) -> None:
        """Initialize the vehicle."""
        self.account = account
        self.combine_data(vehicle_base, vehicle_state, charging_settings, fetched_at)
        self.battery = Battery.from_vehicle_data(self.data)
        _LOGGER.debug(
            "Initialized vehicle %s (%s)", self.name, self.vin,
        )

    def combine_data(
        self,
        vehicle_base: dict,
        vehicle_state: Optional[dict] = None,
        charging_settings: Optional[dict] = None,
        fetched_at: Optional[datetime.datetime] = None,
    ) -> dict:
        """Combine all data into one dictionary."""
        self.data.update(vehicle_base)
        if vehicle_state:
            self.data.update(vehicle_state)
        if charging_settings:
            self.data.update(charging_settings)
        if fetched_at:
            self.data["fetched_at"] = fetched_at
        self._parse_data()
        self.battery = Battery.from_vehicle_data(self.data)

    def _parse_data(self) -> None:
        self.vin = self.data.get("vin")
        self.name = self.data.get("modelName")
