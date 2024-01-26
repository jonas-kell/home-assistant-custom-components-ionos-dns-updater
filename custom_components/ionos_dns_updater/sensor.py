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
from typing import Literal, Optional, Dict
import socket

_LOGGER = logging.getLogger(__name__)

DOMAIN: Final = "ionos_dns_updater"

CONF_ZONE_DOMAIN: Final = "zone_domain"
CONF_PREFIX: Final = "prefix"
CONF_ENCRYPTION: Final = "encryption"
CONF_LOG_HTTP_ERRORS: Final = "log_http_errors"

# Validation of the user's configuration
PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_DOMAIN): cv.string,
        vol.Optional(CONF_ZONE_DOMAIN, default=""): cv.string,
        vol.Optional(CONF_PREFIX, default=""): cv.string,
        vol.Optional(CONF_ENCRYPTION, default=""): cv.string,
        vol.Optional(CONF_LOG_HTTP_ERRORS, default=False): cv.boolean,
    }
)


async def async_setup_platform(
    hass: HomeAssistant,
    config: ConfigType,
    add_entities: AddEntitiesCallback,
    discovery_info: DiscoveryInfoType | None = None,
) -> None:
    domain = config[CONF_DOMAIN]
    zone_domain = config[CONF_ZONE_DOMAIN]
    prefix = config[CONF_PREFIX]
    encryption = config[CONF_ENCRYPTION]
    log_http_errors = config[CONF_LOG_HTTP_ERRORS]

    local_sensor = IpSensor(LocalInterface(hass), "ipv6_address_local")
    dns_sensor = IpSensor(IonosInterface(domain), "ipv6_address_dns_lookup")
    dns_updater = await IonosDNSUpdater.initialize_instance_async(
        domain,
        zone_domain,
        prefix,
        encryption,
        local_sensor,
        dns_sensor,
        log_http_errors,
    )
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
    def __init__(self, log_http_errors: bool, timeout: int) -> None:
        self._log_http_errors = log_http_errors
        self._timeout = timeout

    async def update_ipv6_address_entry(self) -> bool:
        return False

    async def request(
        self,
        url: str,
        call_type: Literal["GET", "PUT"],
        headers: Dict[str, str],
        body: Optional[str],
    ):
        status_code = 0
        json = {}
        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                if call_type == "GET":
                    async with session.get(url, timeout=self._timeout) as resp:
                        status_code = resp.status
                        if status_code == 200 or status_code == 201:
                            json = await resp.json()
                elif call_type == "PUT":
                    async with session.put(
                        url, timeout=self._timeout, data=body
                    ) as resp:
                        status_code = resp.status
                        if status_code == 200 or status_code == 201:
                            json = await resp.json()

        except Exception as ex:
            if self._log_http_errors:
                _LOGGER.error(
                    f"Could not connect to DNS update API because of  {type(ex).__name__}, {str(ex.args)}"
                )
            return False, {}

        if status_code != 200 and status_code != 201:
            _LOGGER.error(
                f"Could connect to DNS update API but returned status code {status_code} {json}"
            )
            return False, {}

        return True, json


class IonosDNSUpdater(DNSUpdater):
    _domain: str
    _zone_domain: str
    _dns_sensor: IpSensor
    _local_sensor: IpSensor
    _encryption: str
    _prefix: str
    _auth_header_key: str
    _auth_header: str
    _zone_id: Optional[str]
    _record_id: Optional[str]

    async def initialize_ids(self) -> None:
        # INIT the zone and record id
        got_all = False
        try:
            result_zones_success, result_zones_lookup = await self.request(
                "https://api.hosting.ionos.com/dns/v1/zones",
                "GET",
                {self._auth_header_key: self._auth_header},
                None,
            )
            if result_zones_success:
                for result_zone_obj in result_zones_lookup:
                    if result_zone_obj["name"] == self._zone_domain:
                        self._zone_id = result_zone_obj["id"]

                if self._zone_id is None:
                    _LOGGER.error(
                        f"Did not find the zone id to the zone_domain value {self._zone_domain}"
                    )
                else:
                    result_records_success, result_records_lookup = await self.request(
                        f"https://api.hosting.ionos.com/dns/v1/zones/{self._zone_id}",
                        "GET",
                        {self._auth_header_key: self._auth_header},
                        None,
                    )
                    if result_records_success:
                        for result_record_obj in result_records_lookup["records"]:
                            if (
                                result_record_obj["name"] == self._domain
                                and result_record_obj["type"] == "AAAA"
                            ):
                                self._record_id = result_record_obj["id"]
                                got_all = True
        except Exception as ex:
            _LOGGER.error(f"Parsing exception {type(ex).__name__}, {str(ex.args)}")

        if not got_all:
            _LOGGER.warning(f"DNS updater initialization never found all necessary ids")

    @classmethod
    async def initialize_instance_async(
        cls,
        domain: str,
        zone_domain: str,
        prefix: str,
        encryption: str,
        local_sensor: IpSensor,
        dns_sensor: IpSensor,
        log_http_errors: bool,
    ):
        self = cls(log_http_errors, 3)

        self._domain = domain
        self._zone_domain = zone_domain
        self._dns_sensor = dns_sensor
        self._local_sensor = local_sensor
        self._encryption = encryption
        self._prefix = prefix

        self._auth_header_key = "X-API-Key"
        self._auth_header = f"{self._prefix}.{self._encryption}"

        self._zone_id = None
        self._record_id = None
        if self._zone_domain != "" and self._encryption != "" and self._prefix != "":
            await self.initialize_ids()
        else:
            _LOGGER.warning(
                f"Some of the Update-required psoperties are not set. Therefore dns updater integration only provides the sensors in read mode."
            )

        return self

    async def update_ipv6_address_entry(self) -> bool:
        local_address = IPv6Address(self._local_sensor.native_value)
        dns_address = IPv6Address(self._dns_sensor.native_value)
        local_address_short = str(local_address.compressed)
        dns_address_short = str(dns_address.compressed)

        if local_address_short != dns_address_short:
            # differs, should be updated
            _LOGGER.info(f"Attempting update of DNS entry on IONOS API")
            status, _ = await self.request(
                f"https://api.hosting.ionos.com/dns/v1/zones/{self._zone_id}/records/{self._record_id}",
                "PUT",
                {
                    self._auth_header_key: self._auth_header,
                    "Content-Type": "application/json",
                },
                f'{{"disabled": false, "content": "{local_address_short}", "ttl": 3600, "prio": 0}}',
            )
            if status:
                _LOGGER.info(
                    f"Used the IONOS DNS API to set the AAAA entry for {self._domain} to {local_address_short}"
                )

            return status

        return False
