"""Integração oficial: só registra um serviço."""
from .const import DOMAIN
from . import _cache


async def async_setup(hass, config):
    async def _ping(call):
        hass.bus.async_fire(f"{DOMAIN}_pong")

    hass.services.async_register(DOMAIN, "ping", _ping)
    hass.async_create_task(_cache.sincroniza(hass))
    return True
