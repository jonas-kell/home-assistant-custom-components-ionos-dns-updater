"""Platform for dns updater integration."""
from __future__ import annotations

import logging
import voluptuous as vol
from typing import Final
import homeassistant.helpers.config_validation as cv
from homeassistant.components.sensor import (
    PLATFORM_SCHEMA,
    SensorDeviceClass,
    RestoreSensor,
    SensorStateClass,
)
from homeassistant.const import (
    CONF_IP_ADDRESS,
    CONF_NAME,
    CONF_DEVICES,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import ConfigType
from homeassistant.components.network import async_get_enabled_source_ips

import aiohttp
import itertools
from typing import Literal
import typing_extensions
from datetime import datetime, time, timedelta

_LOGGER = logging.getLogger(__name__)

DOMAIN: Final = "ionos_dns_updater"
CONF_LOG_HTTP_ERRORS: Final = "log_http_errors"

# Validation of the user's configuration
PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Optional(CONF_LOG_HTTP_ERRORS, default=False): cv.boolean,
        vol.Required(CONF_NAME): cv.string,
    }
)


async def async_setup_platform(
    hass: HomeAssistant,
    config: ConfigType,
    add_entities: AddEntitiesCallback,
) -> None:
    test = LocalInterface(hass)
    await test.get_ipv6_address()


class GetIpInterface:
    def __init__(self) -> None:
        pass

    async def get_ipv6_address() -> str:
        return ""

class LocalInterface:
    def __init__(self, hass: HomeAssistant) -> None:
        self._hass = hass
        super().__init__()

    async def get_ipv6_address(self) -> str:
        temp = await async_get_enabled_source_ips(self._hass)
        _LOGGER.info(f"#devices {temp}")
    