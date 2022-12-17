# Time-based one-time password

[Time-based one-time password](https://en.wikipedia.org/wiki/Time-based_one-time_password) (TOTP) is a computer algorithm that generates a [one-time password](https://en.wikipedia.org/wiki/One-time_password) (OTP) that uses the current time as a source of uniqueness. As an extension of the [HMAC-based one-time password algorithm](https://en.wikipedia.org/wiki/HMAC-based_one-time_password_algorithm) (HOTP), it has been adopted as [Internet Engineering Task Force](https://en.wikipedia.org/wiki/Internet_Engineering_Task_Force) (IETF) standard [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238).

TOTP is the cornerstone of [Initiative for Open Authentication](https://en.wikipedia.org/wiki/Initiative_for_Open_Authentication) (OATH), and is used in a number of [two-factor authentication](https://en.wikipedia.org/wiki/Two-factor_authentication) (2FA) systems.

### Secret Key

The server generates a private key that is used with [HMAC](https://en.wikipedia.org/wiki/HMAC)-[SHA1](https://en.wikipedia.org/wiki/SHA-1) to encrypt the epoch timer, then the generated cryptographic HMAC hash is used to calculate the password of typically 6 or 8 digits.
The private key is encoded in [Base32](https://es.wikipedia.org/wiki/Base32) to deliver it in a human-readable form to the user.

### QR code

[QR codes](https://en.wikipedia.org/wiki/QR_code) are used to encode a secret key as a [URI](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier) so that it can be easily added to any [authenticator](https://en.wikipedia.org/wiki/Authenticator) application.

Secret keys may be encoded in QR codes as a URI with the following format:

> `otpauth://TYPE/LABEL?PARAMETERS`

Example with all optional parameters supplied:

> `otpauth://totp/NodeJS:example@email.com?secret=XXXXX&issuer=NodeJS&algorithm=SHA1&digits=6&period=30`

Use [OTP Authenticator Migration URL Parser](https://github.com/taharactrl/otpauth-migration-parser) to parse the exported QR code data from the [Google Authenticator](https://es.wikipedia.org/wiki/Google_Authenticator) application.

Reference: [Google Authenticator - Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

## Installation

```bash
npm install https://github.com/flipeador/node.js-otp-2fa
```

## Example

```js
const { setInterval } = require('node:timers');
const { generateSecret, generateTOTP, otpauthURL } = require('@flipeador/node.js-otp-2fa');

const secret = generateSecret(24);

setInterval(() => {
    const totp = generateTOTP(secret);
    totp.remaining = `Expires in ${totp.period-totp.time%totp.period}s`;
    totp.url = otpauthURL({
        label: 'example@email.com',
        issuer: 'Node',
        ...totp
    });
    console.log(totp);
}, 1000);
```

```bash
{
  secret: 'N23Y253JQO7VDN7VBTP64N33',
  buffer: <Buffer 6e b7 8d 77 69 83 bf 51 b7 f5 0c df ee 37 7b>,
  algorithm: 'sha1',
  digits: 6,
  period: 30,
  time: 1668889958,
  password: '586899',
  remaining: 'Expires in 22s',
  url: 'otpauth://totp/Node%3Aexample%40email.com?secret=N23Y253JQO7VDN7VBTP64N33&issuer=Node&algorithm=sha1&digits=6&period=30'
}
```

## License

This project is licensed under the **GNU General Public License v3.0**. See the [license file](LICENSE) for details.
