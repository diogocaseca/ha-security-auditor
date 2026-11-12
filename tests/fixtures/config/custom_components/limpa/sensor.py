"""Sensor que lê a temperatura de um dispositivo na rede local."""
from homeassistant.components.sensor import SensorEntity
from homeassistant.const import CONF_HOST


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities([TemperaturaSensor(entry.data[CONF_HOST])])


class TemperaturaSensor(SensorEntity):
    _attr_name = "Temperatura"
    _attr_native_unit_of_measurement = "°C"

    def __init__(self, host: str) -> None:
        self._host = host

    async def async_update(self) -> None:
        session = self.hass.helpers.aiohttp_client.async_get_clientsession()
        async with session.get(f"http://{self._host}/api/temp") as resp:
            data = await resp.json()
        self._attr_native_value = data["temp"]
