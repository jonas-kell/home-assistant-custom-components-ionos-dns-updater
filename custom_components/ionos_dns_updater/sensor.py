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
from homeassistant.core import HomeAssistant, State
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType
from homeassistant.components.network import async_get_enabled_source_ips, IPv6Address

import aiohttp
from typing import Literal, Optional, Dict, List
import socket

_LOGGER = logging.getLogger(__name__)

DOMAIN: Final = "ionos_dns_updater"

CONF_ZONE_DOMAIN: Final = "zone_domain"
CONF_PREFIX: Final = "prefix"
CONF_ENCRYPTION: Final = "encryption"
CONF_LOG_HTTP_ERRORS: Final = "log_http_errors"
CONF_DNS_API_TIMEOUT: Final = "dns_api_timeout"
CONF_TTL: Final = "time_to_live"

# Validation of the user's configuration
PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_DOMAIN): cv.string,
        vol.Optional(CONF_ZONE_DOMAIN, default=""): cv.string,
        vol.Optional(CONF_PREFIX, default=""): cv.string,
        vol.Optional(CONF_ENCRYPTION, default=""): cv.string,
        vol.Optional(CONF_LOG_HTTP_ERRORS, default=False): cv.boolean,
        vol.Optional(CONF_DNS_API_TIMEOUT, default=10): cv.positive_int,
        vol.Optional(CONF_TTL, default=300): cv.positive_int,
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
    dns_api_timeout = config[CONF_DNS_API_TIMEOUT]
    time_to_live = config[CONF_TTL]

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
        dns_api_timeout,
        time_to_live,
    )
    dns_sensor.set_updater(dns_updater)

    # Add entities
    add_entities([local_sensor, dns_sensor])


class GetIpInterface:
    def __init__(self) -> None:
        pass

    async def get_ipv6_address(
        self, previous_ip: str | None, current_ip: str | None
    ) -> str:
        _ = previous_ip
        _ = current_ip
        return ""

    def get_sensor_type(
        self,
    ) -> Literal["ipv6_address_local", "ipv6_address_dns_lookup"]:
        return "ipv6_address_local"


class LocalInterface(GetIpInterface):
    def __init__(self, hass: HomeAssistant) -> None:
        self._hass = hass
        super().__init__()

    async def get_ipv6_address(
        self, previous_ip: str | None, current_ip: str | None
    ) -> str:
        ips = await async_get_enabled_source_ips(self._hass)

        possibilities = []
        for ip in ips:
            if isinstance(ip, IPv6Address):
                if ip.is_global:
                    out_ip = str(ip).split("%", 1)[
                        0
                    ]  # this does something like ...aaaa:ffff%0 for the interface. Sadly this kills its own functions, lol
                    out_ip_ip = IPv6Address(out_ip)
                    out_ip_short = str(out_ip_ip.compressed)
                    possibilities.append(out_ip_short)

        if len(possibilities) == 1:
            _LOGGER.info(f"Local Sensor detected IP to be {possibilities[0]}")
            return possibilities[0]

        if len(possibilities) > 1:
            _LOGGER.warning(
                f"Detected {len(possibilities)} possible IPv6 adresses, {possibilities} exept logic with p->{previous_ip} c->{current_ip}"
            )

            filtered_results = []
            if previous_ip is not None and current_ip is not None:
                if previous_ip in possibilities:
                    _LOGGER.warning(
                        "Previous ip in possibilities -> we are after the update -> ignore the previous one"
                    )
                    for test_ip in possibilities:
                        if test_ip != previous_ip:
                            filtered_results.append(test_ip)
                else:
                    _LOGGER.warning(
                        "Previous ip NOT in possibilities -> we are before the update -> ignore the current one"
                    )
                    for test_ip in possibilities:
                        if test_ip != current_ip:
                            filtered_results.append(test_ip)
            else:
                _LOGGER.error(
                    "None value in curr or prev. Could not do advanced ip detection logic"
                )

            if len(filtered_results) == 1:
                _LOGGER.info("Could determine definite ip after previous value filter")
                return filtered_results[0]

            # Fallback return the first one from the list
            _LOGGER.error("Possibilites Fallback")
            return possibilities[0]

        _LOGGER.error("Local Platform could not detect configured ipv6 address")
        return ""

    def get_sensor_type(
        self,
    ) -> Literal["ipv6_address_local", "ipv6_address_dns_lookup"]:
        return "ipv6_address_local"


class IonosInterface(GetIpInterface):
    def __init__(self, url: str) -> None:
        self._url = url
        super().__init__()

    async def get_ipv6_address(
        self, previous_ip: str | None, current_ip: str | None
    ) -> str:
        _ = previous_ip
        _ = current_ip

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
        self._previous_native_value: Optional[str] = None

    @property
    def extra_state_attributes(self):
        return {
            "previous_native_value": self._previous_native_value,
        }

    @property
    def name(self) -> str:
        return self._name

    @property
    def native_value(self):
        return self._native_value

    async def async_update(self):
        _LOGGER.info(
            f"Attempting update {self._attr_unique_id}: prev = {self._previous_native_value}, curr = {self._native_value}"
        )

        previous_override = None
        if (
            self._previous_native_value != ""
            and self._previous_native_value is not None
        ):
            previous_override = self._previous_native_value

        current_override = None
        if self._native_value != "" and self._native_value is not None:
            current_override = self._native_value

        ip = await self._sensor.get_ipv6_address(previous_override, current_override)

        if ip != "":
            if (
                self._previous_native_value != ""
                and self._previous_native_value is not None
            ):
                try:
                    prev_address = IPv6Address(self._previous_native_value)
                    current_address = IPv6Address(self._native_value)
                    new_address = IPv6Address(ip)
                    prev_address_short = str(prev_address.compressed)
                    current_address_short = str(current_address.compressed)
                    new_address_short = str(new_address.compressed)

                    if new_address_short != current_address_short:
                        self._previous_native_value = current_address_short
                        self._native_value = new_address_short
                        _LOGGER.info(
                            f"Sensor detected a change - rotation: {prev_address_short} <- {current_address_short} <- {new_address_short}"
                        )

                except:
                    _LOGGER.info(
                        f"Error when updating addresses: {self._previous_native_value} - {self._native_value} - {ip}"
                    )
            else:
                _LOGGER.info(f"Empty previous_native_value - initializing to current")
                current_address = IPv6Address(self._native_value)
                current_address_short = str(current_address.compressed)
                self._previous_native_value = current_address_short
                self._native_value = current_address_short  # might need to be migrated to be stored shortened - but it is expected to be a real ipv6 address, if we made it into this branch

        # Perform update if necessary
        if self._updater is not None:
            await self._updater.update_ipv6_address_entry()

    def set_updater(self, updater: DNSUpdater):
        self._updater = updater

    async def async_added_to_hass(self) -> None:
        """Restore native_value on reload"""
        await super().async_added_to_hass()

        last_state: State | None = await self.async_get_last_state()
        if last_state is None:
            return

        # Restore native_value
        if last_state.state not in (None, "unknown", "unavailable"):
            self._native_value = last_state.state

        # Restore attribute
        prev_state_val = last_state.attributes.get("previous_native_value")
        if prev_state_val not in (None, "unknown", "unavailable"):
            self._previous_native_value = prev_state_val

        _LOGGER.info(
            "Restored IP sensor %s: value=%s prev_value=%s",
            self._attr_unique_id,
            self._native_value,
            self._previous_native_value,
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
    _attempt_update: bool
    _time_to_live: int

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
        dns_api_timeout: int,
        time_to_live: int,
    ):
        self = cls(log_http_errors, dns_api_timeout)

        self._domain = domain
        self._zone_domain = zone_domain
        self._dns_sensor = dns_sensor
        self._local_sensor = local_sensor
        self._encryption = encryption
        self._prefix = prefix
        self._time_to_live = time_to_live

        self._auth_header_key = "X-API-Key"
        self._auth_header = f"{self._prefix}.{self._encryption}"

        self._zone_id = None
        self._record_id = None
        self._attempt_update = (
            self._zone_domain != "" and self._encryption != "" and self._prefix != ""
        )
        if self._attempt_update:
            await self.initialize_ids()
        else:
            _LOGGER.warning(
                f"Some of the Update-required properties are not set. Therefore dns updater integration only provides the sensors in read mode."
            )

        return self

    async def update_ipv6_address_entry(self) -> bool:
        _LOGGER.info(f"Checking for necessary update of ipv6 address")

        if not self._attempt_update:
            return False
        if self._zone_id is None or self._record_id is None:
            _LOGGER.error(
                f"Tried to update, but either _zone_id or _record_id are none... As the settings for write-mode are set, something must have failed during initialize_ids (most likely wrong credentials)"
            )
            await self.initialize_ids()
            return False

        local_address = IPv6Address(self._local_sensor.native_value)
        dns_address = IPv6Address(self._dns_sensor.native_value)
        local_address_short = str(local_address.compressed)
        dns_address_short = str(dns_address.compressed)

        if local_address_short != dns_address_short:
            # differs, should be updated
            _LOGGER.info(
                f"Attempting update of DNS entry on IONOS API from {dns_address_short} -> {local_address_short}"
            )
            status, _ = await self.request(
                f"https://api.hosting.ionos.com/dns/v1/zones/{self._zone_id}/records/{self._record_id}",
                "PUT",
                {
                    self._auth_header_key: self._auth_header,
                    "Content-Type": "application/json",
                },
                f'{{"disabled": false, "content": "{local_address_short}", "ttl": {self._time_to_live}, "prio": 0}}',
            )
            if status:
                _LOGGER.info(
                    f"Used the IONOS DNS API to set the AAAA entry for {self._domain} to {local_address_short}"
                )

                # update the sensor value
                self._dns_sensor._previous_native_value = self._dns_sensor._native_value
                self._dns_sensor._native_value = local_address_short

            return status
        _LOGGER.info(f"Adresses are both {dns_address_short} no update necessary")
        return False
