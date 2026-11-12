import logging

from auditor.masking import MASK, Masker, MaskingFilter


def test_known_secrets_from_secrets_yaml(tmp_path, masker: Masker):
    (tmp_path / "secrets.yaml").write_text(
        "wifi_password: SuperSenha123\nmqtt:\n  user: x\napi_key: !env_var CHAVE\npin: 1883012\n",
        encoding="utf-8",
    )
    assert masker.load_secrets_yaml(tmp_path / "secrets.yaml") == 2  # SuperSenha123 e 1883012; "x" é curto demais
    assert masker.mask("conectando com SuperSenha123 pin 1883012") == f"conectando com {MASK} pin {MASK}"


def test_missing_or_invalid_secrets_yaml(tmp_path, masker: Masker):
    assert masker.load_secrets_yaml(tmp_path / "nao_existe.yaml") == 0
    (tmp_path / "ruim.yaml").write_text("a: [", encoding="utf-8")
    assert masker.load_secrets_yaml(tmp_path / "ruim.yaml") == 0


def test_patterns(masker: Masker):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    text = masker.mask(
        f"token {jwt} gh=ghp_abcdefghijklmnopqrstuvwxyz0123456789 aws=AKIAABCDEFGHIJKLMNOP "
        "url=https://admin:hunter2pass@example.com/x"
    )
    assert jwt not in text
    assert "ghp_" not in text
    assert "AKIA" not in text
    assert "hunter2pass" not in text and "https://admin:" in text


def test_assignments(masker: Masker):
    assert masker.mask('password = "s3nh4F0rte!"') == f'password = "{MASK}"'
    assert masker.mask("api_key: 9f8e7d6c5b4a") == f"api_key: {MASK}"
    # Referências e variáveis não são segredos: ficam como estão.
    assert masker.mask("password: !secret wifi") == "password: !secret wifi"
    assert masker.mask("token = entry.data") == "token = entry.data"
    assert masker.mask("token = config_token") == "token = config_token"
    # Código não pode ser confundido com valor de segredo.
    code = 'tokens = open(hass.config.path(".storage", "auth")).read()'
    assert masker.mask(code) == code
    assert masker.mask("api_key = entry.data[CONF_API_KEY]") == "api_key = entry.data[CONF_API_KEY]"


def test_private_key_block(masker: Masker):
    text = "x\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\ny"
    assert masker.mask(text) == f"x\n{MASK}\ny"


def test_logging_filter_masks_message_args_and_traceback(masker: Masker, caplog):
    masker.add_known("segredo-muito-secreto")
    logger = logging.getLogger("teste.mascara")
    logger.addFilter(MaskingFilter(masker))
    with caplog.at_level(logging.INFO, logger="teste.mascara"):
        logger.info("valor %s", "segredo-muito-secreto")
        try:
            raise RuntimeError("falhou com segredo-muito-secreto")
        except RuntimeError:
            logger.exception("erro")
    assert "segredo-muito-secreto" not in caplog.text
    assert caplog.text.count(MASK) >= 2
