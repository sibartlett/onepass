const WS = require("ws");

class OnePassClient {

  constructor(options) {
    this.options = options;
  }

  ws() {
    const ws = new WS(this.options.url, {
      origin: this.options.origin
    });

    ws.number = 0;

    ws.command = (type, payload) => {
      const cmd = {
        action: type,
        number: ws.number++,
        version: "4",
        bundleId: this.options.bundleId,
        payload
      };

      ws.send(JSON.stringify(cmd), { binary: true, mask: true });
    };

    return ws;
  }

  password(url, func) {
    return new Promise((resolve, reject) => {

      let timeout = undefined;

      const success = pass => {
        clearTimeout(timeout);
        func && func(undefined, pass);
        resolve(pass);
      };

      const fail = error => {
        clearTimeout(timeout);
        func && func(error);
        reject(error);
      };

      timeout = setTimeout(() => fail("Timeout"), this.options.timeout * 1000);

      const ws = this.ws();

      ws.on("open", () => {
        ws.command("hello", { version: "4.2.4.90" });
      });

      ws.on("message", function message(data) {
        const d = JSON.parse(data);

        switch (d.action) {

        case "welcome": {
          ws.command("showPopup", {
            url: url,
            options: {"source": "toolbar-button"}
          });
          break;
        }

        case "fillItem": {
          const field = d.payload.item.secureContents.fields.find(f => f.name === "password");
          if (field) {
            success(field.value);
          } else {
            fail("No password");
          }
          break;
        }

        }
      });
    });

  }

}

module.exports = options => {
  options = Object.assign({
    bundleId: "com.github.sibartlett.onepass",
    origin: "chrome-extension://aomjjhallfgjeglblehebfpbcfeobpgk",
    timeout: 30,
    url: "ws://127.0.0.1:6263/4"
  }, options);

  return new OnePassClient(options);
};
