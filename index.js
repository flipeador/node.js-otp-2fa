'use strict';

const crypto = require('node:crypto');
const { Buffer } = require('node:buffer');
const { URL, URLSearchParams } = require('node:url');

// function padStart(str, len)
// {
//     return '0'.repeat(Math.max(0, len-str.length)) + str;
// }

function padotp(otp, digits)
{
    return `${otp}`.padStart(digits, '0').slice(-digits);
    // return leftpad(`${otp}`, digits).slice(-digits);
}

function base32Decode(base32)
{
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '', hex = '';
    for (const char of base32.replace(/[=]+$/u, ''))
    {
        const index = chars.indexOf(char.toUpperCase());
        if (index === -1)
            throw new Error(`Invalid character: ${char}`);
        bits += index.toString(2).padStart(5, '0');
    }
    for (let i = 0; i + 8 <= bits.length; i += 8)
        hex += parseInt(bits.slice(i,i+8),2).toString(16).padStart(2, '0');
    return hex;
}

function parseOptions(options, extra)
{
    if (typeof(options) !== 'object')
        options = {secret: options};
    options.secret ??= generateSecret();
    options.buffer = Buffer.isBuffer(options.key) ? options.key
        : Buffer.from(options.key||base32Decode(options.secret), 'hex');
    options.algorithm ??= 'sha1';
    options.digits = Math.min(10, Math.max(1, options.digits ?? 6));
    for (const key in extra)
        options[key] ??= extra[key];
    return options;
}

/**
 * Generate a HMAC-based one-time password (HOTP).
 */
function hotp(algorithm, secret, counter)
{
    const hmac = crypto.createHmac(algorithm, secret).update(counter).digest('hex');
    // Extract the last 4 bits of the hash string as decimal.
    const offset = parseInt(hmac.slice(-1), 16);
    // Return the last 31 bits of the hash string starting at `offset`.
    const otp = hmac.slice(2*offset, 2*offset+8); // last 32 bits
    return parseInt(otp, 16) & 0x7fffffff; // remove the first bit
}

/**
 * Generate a Time-based one-time password (TOTP).
 */
function totp(algorithm, secret, time, length)
{
    const Ct = Math.floor(time/length).toString(16);
    const token = Buffer.from(Ct.padStart(16, '0'), 'hex');
    return hotp(algorithm, secret, token);
}

/**
 * Generate a HMAC-based one-time password (HOTP).
 * @param {Object|String} options Options or `secret`.
 * @param {String} options.secret Base32 secret key.
 * @param {String} options.counter Counter value.
 * @param {String} options.algorithm Hash algorithm. Defaults to `SHA1`.
 */
function generateHOTP(options)
{
    options = parseOptions(options, { counter: 0 });
    const otp = hotp(options.algorithm, options.buffer, `${options.counter}`);
    return {...options, password: padotp(otp, options.digits)};
}

/**
 * Generate a Time-based one-time password (TOTP).
 * @param {Object|String} options Options or `secret`.
 * @param {String} options.secret Base32 secret key.
 * @param {Number} options.period Update interval, in seconds. Defaults to 30.
 * @param {Number} options.digits Password length (6-10). Defaults to 6.
 * @param {String} options.algorithm Hash algorithm. Defaults to `SHA1`.
 */
function generateTOTP(options)
{
    options = parseOptions(options, {
        period: 30,
        time: Math.floor(Date.now() / 1000)
    });
    const otp = totp(options.algorithm, options.buffer, options.time, options.period);
    return {...options, password: padotp(otp, options.digits)};
}

/**
 * Generate a random secret key.
 * @param {Number} length Secret length. Defaults to 24.
 */
function generateSecret(length=24)
{
    const chars = '2A3B4C5D6E7F2G3H4I5J6K7L2M3N4O5P6Q7R2S3T4U5V6W7X2Y3Z';
    let secret = '';
    while (length--)
        secret += chars[crypto.randomInt(chars.length)];
    return secret;
}

/**
 * Generate an otpauth URL.
 * @param {Object} options Options.
 * @param {String} options.type Either `hotp` or `totp`.
 * @param {String} options.label Used to identify the account with which the secret key is associated.
 * @param {String} options.secret Shared base32 secret key.
 * @param {String} options.issuer The provider or service with which the secret key is associated.
 * @param {String} options.algorithm Hash algorithm: `sha1`, `sha256` or `sha512`.
 * @param {Number} options.digits The number of digits for the OTP: `6` or `8`.
 * @param {Number} options.period A period that a TOTP code will be valid for, in seconds.
 * @param {Number} options.counter The initial counter value, required for HOTP.
 */
function otpauthURL(options)
{
    if (options.issuer !== undefined && !options.label.includes(':'))
        options.label = `${options.issuer}:${options.label}`;
    options.label = new URLSearchParams(options.label).toString().slice(0, -1);
    const url = new URL(`otpauth://${options.type??'totp'}/${options.label}`);
    for (const key of ['secret', 'issuer', 'algorithm', 'digits', 'period', 'counter'])
        if (options[key] !== undefined) url.searchParams.append(key, options[key]);
    return url.toString();
}

module.exports = {
    base32Decode,
    hotp,
    totp,
    generateHOTP,
    generateTOTP,
    generateSecret,
    otpauthURL
};
