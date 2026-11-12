"""Integração oficial: só registra um serviço."""
from .const import DOMAIN


async def async_setup(hass, config):
    async def _ping(call):
        hass.bus.async_fire(f"{DOMAIN}_pong")

    hass.services.async_register(DOMAIN, "ping", _ping)
    return True
