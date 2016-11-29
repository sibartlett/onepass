# onepass

Node.js library for communicating with 1Password and retrieving passwords.

```js
const onepass = require('onepass')();

// Configure creds if you have them
onepass.auth.credentials(creds);

// Otherwise generate new creds
creds = onepass.auth.generateCredentials();
onepass.auth.credentials(creds);

// Promise API
onepass.password('http://example.com')
       .then(password => ...)
       .catch(err => ...);

// Node callback API
onepass.password('http://example.com', (err, pass) => {
  ...
})
```

### Configuring 1Password5 to work with onepass

If you're using 1Password 5+, or you run into this screen:

![Cannot Fill Item in Web Browser](https://raw.githubusercontent.com/ravenac95/readme-images/master/sudolikeaboss/cannot-fill-item-error-popup.png)

This causes a problem for `onepass` as it isn't a "trusted browser" per se.
In order to fix this issue, you need to do the following:

1. Open up 1Password's preferences
2. Find the `Advanced` settings tab.
3. Uncheck `Verify browser code signature`.

![Uncheck "Verify browser code signature"](https://cloud.githubusercontent.com/assets/889219/6270365/a69a0726-b816-11e4-9b96-558ddeb00378.png)

### Acknowledgements

A big thank you [Reuven V. Gonzales](https://github.com/ravenac95) and his work on [sudolikeaboss](https://github.com/ravenac95/sudolikeaboss). `onepass` is largely based on `sudolikeaboss`.

Another big thank you to [AgileBits](https://agilebits.com/) for bringing us [1Password](https://1password.com/).
