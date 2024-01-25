"""Platform for dns updater integration."""
from __future__ import annotations

import logging
import voluptuous as vol
from typing import Final
import homeassistant.helpers.config_validation as cv
from homeassistant.components.sensor import (
    PLATFORM_SCHEMA,
    RestoreSensor,
)
from homeassistant.const import (
    CONF_DOMAIN
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType
from homeassistant.components.network import async_get_enabled_source_ips, IPv6Address

import aiohttp
from typing import Literal
import socket

_LOGGER = logging.getLogger(__name__)

DOMAIN: Final = "ionos_dns_updater"

# Validation of the user's configuration
PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_DOMAIN): cv.string,
    }
)


async def async_setup_platform(
    hass: HomeAssistant,
    config: ConfigType,
    add_entities: AddEntitiesCallback,
    discovery_info: DiscoveryInfoType | None = None,
) -> None:   

    domain = config[CONF_DOMAIN]

    # Add entities
    add_entities(
        IpSensor(interf)
        for interf in [LocalInterface(hass), IonosInterface(domain)]
    )

class GetIpInterface:
    def __init__(self) -> None:
        pass

    async def get_ipv6_address(self) -> str:
        return ""

    def get_sensor_type(self) -> Literal["local_ipv6_address", "upstream_ipv6_address"]:
        pass


class LocalInterface(GetIpInterface):
    def __init__(self, hass: HomeAssistant) -> None:
        self._hass = hass
        super().__init__()

    async def get_ipv6_address(self) -> str:
        ips = await async_get_enabled_source_ips(self._hass)
        
        out_ip: str = ""
        for ip in ips:
            if isinstance(ip, IPv6Address):
                if ip.is_global:
                    out_ip = str(ip).split('%', 1)[0] # this does something like ...aaaa:ffff%0 for the interface. Sadly this kills its own functions, lol

        if out_ip == "":
            _LOGGER.error("Local Platform could not detect configured ipv6 address")

        return out_ip
    
    def get_sensor_type(self) -> Literal["local_ipv6_address", "upstream_ipv6_address"]:
        return "local_ipv6_address"

class IonosInterface(GetIpInterface):
    def __init__(self, url:str) -> None:
        self._url = url
        super().__init__()

    async def get_ipv6_address(self) -> str:
        out_ip: str = ""
        
        try:
            out_ip = socket.getaddrinfo(self._url, None, socket.AF_INET6)[0][4][0]
        except Exception as e:
            _LOGGER.error("DNS lookup failed: " + str(e))

        if out_ip == "":
            _LOGGER.error("Remote Platform could not resolve ipv6 address from dns")

        return out_ip
    
    def get_sensor_type(self) -> Literal["local_ipv6_address", "upstream_ipv6_address"]:
        return "upstream_ipv6_address"
    
class IpSensor(RestoreSensor):
    """Ip address Sensor"""

    name_additions = {
        "local_ipv6_address": "Local",
        "upstream_ipv6_address": "DNS lookup",
    }

    def __init__(
        self,
        sensor:GetIpInterface,
    ) -> None:
        self._sensor = sensor
        self._name = "IPv6 Address" + " " + self.name_additions[sensor.get_sensor_type()]

        self._native_value = ""

    @property
    def name(self) -> str:
        return self._name

    @property
    def native_value(self):
        return self._native_value

    async def async_update(self):
        ip = await self._sensor.get_ipv6_address()

        if ip != "":
            self._native_value = ip

    async def async_added_to_hass(self) -> None:
        """Restore native_value on reload"""
        await super().async_added_to_hass()
        if (last_sensor_data := await self.async_get_last_sensor_data()) is not None:
            self._native_value = last_sensor_data.native_value
            _LOGGER.info(
                f"After re-adding, loaded ip address sensor state value for {self._entitiy_id}: {self._native_value}"
            )