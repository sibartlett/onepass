const crypto = require("crypto");
const EventEmitter = require("events");
const WS = require("ws");


class OnePassAuthentication {

  constructor(client) {
    this.authenticated = false;

    this.alg = "aead-cbchmac-256";
    this.method = "auth-sma-hmac256";
    this.extId = null;
    this.secret = null;

    this.setup(client);
  }

  generateCredentials() {
    return {
      extId: crypto.randomBytes(16).toString("hex"),
      secret: crypto.randomBytes(16).toString("hex")
    };
  }

  credentials(credentials) {
    if (credentials) {
      this.extId = credentials.extId;
      this.secret = credentials.secret;
    }
    return {
      extId: this.extId,
      secret: this.secret
    };
  }

  authenticate(client) {
    this.cc = Buffer.from(Math.floor(Math.random() * 1000000000).toString());
    client.send("authBegin", {
      "extId": this.extId,
      "method": this.method,
      "alg": this.alg,
      "cc": this.toBase64(this.cc)
    });
  }

  getSessionData(cc, cs) {
    const buffers = Buffer.concat([cs, cc]);

    const hash = crypto.createHash("sha256").update(buffers).digest();
    const m3 = crypto.createHmac("sha256", this.secret).update(hash).digest();
    const m4 = crypto.createHmac("sha256", this.secret).update(m3).digest();
    const encK = crypto.createHmac("sha256", this.secret).update(Buffer.concat([m3, m4, Buffer.from("encryption")])).digest();
    const hmacKey = crypto.createHmac("sha256", this.secret).update(Buffer.concat([m4, m3, Buffer.from("hmac")])).digest();

    return {
      encK,
      hmacKey,
      m3,
      m4
    };
  }

  setup(client) {
    client.on("authNew", data => {
      client.emit("authCode", data.code);

      client.send("authRegister", {
        "method": this.method,
        "secret": this.toBase64(this.secret)
      });
    });

    client.on("authRegistered", () => {
      // Need a slight delay, otherwise 1Password crashes
      setTimeout(() => this.authenticate(client), 500);
    });

    client.on("authBegin", () => {
      this.authenticate(client);
    });

    client.on("authFail", data => {
      if (data.reason === "bad-mac") {
        client.send("authRegister", {
          "method": this.method,
          "secret": this.toBase64(this.secret)
        });
      }
    });

    client.on("authContinue", data => {
      const cs = Buffer.from(data.cs, "base64");

      this.session = this.getSessionData(this.cc, cs);

      const verify = data.M3 === this.toBase64(this.session.m3);
      if (!verify) {
        client.send("authFail", {
          "reason": "bad-mac"
        });
        return;
      }

      client.send("authVerify", {
        "method": this.method,
        "M4": this.toBase64(this.session.m4)
      });
    });

    client.on("welcome", data => {
      if (data.alg) {
        this.authenticated = true;
      }
    });
  }

  capabilities() {
    return [this.method, this.alg];
  }

  toBase64(s) {
    if (typeof s === "string") {
      s = Buffer.from(s);
    }
    return s.toString("base64").replace(/\//g, "_").replace(/\+/g, "|").replace(/\-/g, "+").replace(/\|/g, "-").replace(/\=/g, "");
  }

  hmac(iv, data) {
    if (typeof iv !== "string") {
      iv = this.toBase64(iv);
      data = this.toBase64(data);
    }
    const buffers = Buffer.concat([Buffer.from(iv), Buffer.from(data)]);
    return this.toBase64(crypto.createHmac("sha256", this.session.hmacKey).update(buffers).digest());
  }

  encrypt(payload) {
    if (!this.authenticated) {
      if (this.extId) {
        payload.extId = this.extId;
      }
      return payload;
    }

    const p = JSON.stringify(payload);
    const iv = crypto.randomBytes(16);
    const encK = this.session.encK;
    const cipher = crypto.createCipheriv("aes-256-cbc", encK, iv);
    const data = Buffer.concat([cipher.update(p), cipher.final()]);

    return {
      alg: this.method,
      iv: this.toBase64(iv),
      data: this.toBase64(data),
      hmac: this.hmac(iv, data)
    };
  }

  decrypt(payload) {
    const encrypted = payload.alg && payload.iv && payload.data && payload.hmac;

    if (!this.authenticated || !encrypted) {
      return payload;
    }

    const hmac = this.hmac(payload.iv, payload.data);
    if (payload.hmac !== hmac) {
      throw "Bad data";
    }

    const iv = Buffer.from(payload.iv, "base64");
    const data = Buffer.from(payload.data, "base64");
    const encK = this.session.encK;
    const decipher = crypto.createDecipheriv("aes-256-cbc", encK, iv);
    let unencrypted = decipher.update(data);
    unencrypted += decipher.final("latin1");
    return JSON.parse(unencrypted);
  }
}

class OnePassClient extends EventEmitter {

  constructor(options) {
    super(options);
    this.options = options;
    this.auth = new OnePassAuthentication(this);
  }

  reset() {
    if (this.ws) {
      this.ws.terminate();
    }
    this.ws = null;
    this.auth.authenticated = false;
  }

  send(type, payload) {
    if (!this.ws) {
      return;
    }

    const cmd = {
      action: type,
      payload: this.auth.encrypt(payload)
    };

    this.ws.send(JSON.stringify(cmd), { binary: true, mask: true });
  }

  connect() {
    return new Promise((resolve, reject) => {
      if (this.ws) {
        return resolve();
      }

      this.reset();

      const listeners = {};
      listeners.success = () => {
        this.removeListener("authFail", listeners.fail);
        resolve();
      };
      listeners.fail = () => {
        this.removeListener("authFail", listeners.success);
        reject();
      };

      this.once("welcome", listeners.success);
      this.once("authFail", listeners.fail);

      this.ws = new WS(this.options.url, {
        origin: this.options.origin
      });

      this.ws.on("message", data => {
        this.emit("message", data);
        const d = JSON.parse(data);
        this.emit(d.action, this.auth.decrypt(d.payload));
      });

      this.ws.on("open", () => {
        this.send("hello", {
          version: "4.6.2.90",
          capabilities: this.auth.capabilities()
        });
      });
    });
  }

  password(url, func) {
    return this.connect().then(() => {
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

        this.once("fillItem", data => {
          const field = data.item.secureContents.fields.find(f => f.name === "password");
          if (field) {
            success(field.value);
          } else {
            fail("No password");
          }
        });

        this.send("showPopup", {
          url: url,
          options: {"source": "toolbar-button"}
        });
      });
    });
  }

}

module.exports = options => {
  options = Object.assign({
    origin: "chrome-extension://aomjjhallfgjeglblehebfpbcfeobpgk",
    timeout: 30,
    url: "ws://127.0.0.1:6263/4"
  }, options);

  return new OnePassClient(options);
};

module.exports.OnePassClient = OnePassClient;
