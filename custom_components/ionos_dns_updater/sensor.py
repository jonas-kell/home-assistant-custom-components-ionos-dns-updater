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
from homeassistant.const import CONF_DOMAIN
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType
from homeassistant.components.network import async_get_enabled_source_ips, IPv6Address

import aiohttp
from typing import Literal
from typing import Optional
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
    prefix = config[CONF_DOMAIN]
    encryption = config[CONF_DOMAIN]

    local_sensor = IpSensor(LocalInterface(hass), "ipv6_address_local")
    dns_sensor = IpSensor(IonosInterface(domain), "ipv6_address_dns_lookup")
    dns_updater = IonosDNSUpdater(domain, prefix, encryption, local_sensor, dns_sensor)
    dns_sensor.set_updater(dns_updater)

    # Add entities
    add_entities([local_sensor, dns_sensor])


class GetIpInterface:
    def __init__(self) -> None:
        pass

    async def get_ipv6_address(self) -> str:
        return ""

    def get_sensor_type(
        self,
    ) -> Literal["ipv6_address_local", "ipv6_address_dns_lookup"]:
        return "ipv6_address_local"


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
                    out_ip = str(ip).split("%", 1)[
                        0
                    ]  # this does something like ...aaaa:ffff%0 for the interface. Sadly this kills its own functions, lol

        if out_ip == "":
            _LOGGER.error("Local Platform could not detect configured ipv6 address")

        return out_ip

    def get_sensor_type(
        self,
    ) -> Literal["ipv6_address_local", "ipv6_address_dns_lookup"]:
        return "ipv6_address_local"


class IonosInterface(GetIpInterface):
    def __init__(self, url: str) -> None:
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

    def get_sensor_type(
        self,
    ) -> Literal["ipv6_address_local", "ipv6_address_dns_lookup"]:
        return "ipv6_address_dns_lookup"


class IpSensor(RestoreSensor):
    """Ip address Sensor"""

    name_additions = {
        "ipv6_address_local": "Local",
        "ipv6_address_dns_lookup": "DNS Lookup",
    }

    def __init__(
        self,
        sensor: GetIpInterface,
        unique_id: str,
    ) -> None:
        self._sensor = sensor
        self._name = (
            "IPv6 Address" + " " + self.name_additions[sensor.get_sensor_type()]
        )
        self._attr_unique_id = unique_id

        self._native_value = ""
        self._updater: Optional[DNSUpdater] = None

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

        # Perform update if necessary
        if self._updater is not None:
            await self._updater.update_ipv6_address_entry()

    def set_updater(self, updater: DNSUpdater):
        self._updater = updater

    async def async_added_to_hass(self) -> None:
        """Restore native_value on reload"""
        await super().async_added_to_hass()
        if (last_sensor_data := await self.async_get_last_sensor_data()) is not None:
            self._native_value = last_sensor_data.native_value
            _LOGGER.info(
                f"After re-adding, loaded ip address sensor state value for {self._attr_unique_id}: {self._native_value}"
            )


class DNSUpdater:
    def __init__(self) -> None:
        pass

    async def update_ipv6_address_entry(self) -> bool:
        return False


class IonosDNSUpdater(DNSUpdater):
    def __init__(
        self,
        domain: str,
        prefix: str,
        encryption: str,
        local_sensor: IpSensor,
        dns_sensor: IpSensor,
    ) -> None:
        self._domain = domain
        self._dns_sensor = dns_sensor
        self._local_sensor = local_sensor
        self._encryption = encryption
        self._prefix = prefix
        super().__init__()

    async def update_ipv6_address_entry(self) -> bool:
        local_address = IPv6Address(self._local_sensor.native_value)
        dns_address = IPv6Address(self._dns_sensor.native_value)
        local_address_short = str(local_address.compressed)
        dns_address_short = str(dns_address.compressed)

        if local_address_short != dns_address_short:
            _LOGGER.error(
                f"local address {local_address_short} doesn't match {dns_address_short}"
            )

        return True
