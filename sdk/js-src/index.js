/**
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */

/** @module delegated-account-recovery */
/**
 * @file index.js
 * @copyright Copyright (c) 2016-present, Facebook, Inc.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */

'use strict';
const crypto = require('crypto'),
    url = require('url'),
    https = require('https');

/** well known path for published configuration */
const CONFIG_PATH = '/.well-known/delegated-account-recovery/configuration';

/** well known path for receiving token status callbacks */
const STATUS_PATH = '/.well-known/delegated-account-recovery/token-status';

const originRegex = /^https:\/\/([a-z0-9-]{1,63}\.)+([a-z]{2,63})(:[\d]+)?$/;

/**
 * Class representing a RecoveryToken.
 */
class RecoveryToken {
    static get NO_OPTIONS() { return 0x00; }
    static get STATUS_REQUESTED_FLAG() { return 0x01; }
    static get LOW_FRICTION_REQUESTED_FLAG() { return 0x02; }
    static get VERSION() { return 0x00; }
    static get TYPE_RECOVERY_TOKEN() { return 0x00; }
    static get TYPE_COUNTERSIGNED_TOKEN() { return 0x01; }

    /**
     * Create a RecoveryToken
     *
     * If passing a privateKey, the signature param will be ignored and the token will be signed with that key.
     * If privateKey is null, signature should be a buffer and will be set as the token signature. This is
     * useful when creating a token from a serialized format.  The signature is not validated in this case and
     * must be properly checked with isSignatureValid() if this is being used to implement a recovery provider.
     *
     * @param {string} privateKey - the base64 encoded EC PRIVATE KEY on a single line with no PEM wrapping
     * @param {Buffer} id - 16 byte Buffer representing the token id
     * @param {number} options - either RecoveryToken.NO_OPTIONS, or a combination of
     *                           RecoveryToken.STATUS_REQUESTED_FLAG and RecoveryToken.LOW_FRICTION_REQUESTED_FLAG
     * @param {string} issuer - RFC6454 ASCII encoded origin of the token issuer
     * @param {string} audience - RFC6454 ASCII encoded origin of the token audience
     * @param {string} issuedTime - ISO8601 ASCII string representing token creation time
     * @param {Buffer} data - data to keep in token, encrypted before passing to this method, may be empty
     * @param {Buffer} binding - token binding data from the audience, may be empty
     * @param {Buffer} [signature] - signature field from a token, if creating from a serialized form
     * @throws {Error} if any inputs are malformed
     */
    constructor(privateKey, id, options, issuer, audience, issuedTime, data, binding, signature = null) {
        if (issuer.search(originRegex)) { throw new Error('malformed issuer'); }
        if (audience.search(originRegex)) { throw new Error('malformed audience'); }
        if (options && typeof options !== 'number') { throw new Error('malformed options'); }
        if (!(id instanceof Buffer) || id.length !== 16) { throw new Error('malformed id'); }
        if (data && !(data instanceof Buffer)) { throw new Error('malformed data'); }
        if (binding && !(binding instanceof Buffer)) { throw new Error('malformed binding'); }

        this.version = RecoveryToken.VERSION;
        this.type = RecoveryToken.TYPE_RECOVERY_TOKEN;
        this.id = id || crypto.randomBytes(16);
        this.options = options || 0;
        this.issuer = issuer;
        this.audience = audience;
        this.data = data || Buffer.alloc(0);
        this.binding = binding || Buffer.alloc(0);
        this.issuedTime = issuedTime || new Date().toISOString();

        const issuerBuf = new Buffer(this.issuer, 'ascii');
        const audienceBuf = new Buffer(this.audience, 'ascii');
        const issuedTimeBuf = new Buffer(this.issuedTime, 'ascii');

        let tokenLength =
        1 + // uint8 version
        1 + // uint8 type
        16 + // uint64 token_id
        1 + // uint8 options
        2 + // uint16 issuer_length
        issuer.length + // issuer[issuer_length]
        2 + // uint16 audience_length
        audience.length + // audience[audience_length]
        2 + // uint16 issued_time_length
        this.issuedTime.length + // issued_time[isued_time_length]
        2 + // uint16 data_length
        data.length + // data[data_length]
        2 + // uint16 binding_length
        binding.length; //binding[binding_length]

        let raw = new Buffer(tokenLength);
        let offset = 0;
        raw.writeUInt8(this.version, offset);
        raw.writeUInt8(this.type, offset += 1);
        new Buffer(id).copy(raw, offset += 1);
        raw.writeUInt8(options, offset += 16);
        raw.writeUInt16BE(issuerBuf.length, offset += 1);
        issuerBuf.copy(raw, offset += 2);
        raw.writeUInt16BE(audienceBuf.length, offset += issuerBuf.length);
        audienceBuf.copy(raw, offset += 2);
        raw.writeUInt16BE(issuedTimeBuf.length, offset += audienceBuf.length);
        issuedTimeBuf.copy(raw, offset += 2);
        raw.writeUInt16BE(data.length, offset += issuedTimeBuf.length);
        data.copy(raw, offset += 2);
        raw.writeUInt16BE(binding.length, offset += data.length);
        binding.copy(raw, offset += 2);
        offset += binding.length;
        this.raw = raw;
        if (privateKey === null) {
            this.signature = signature;
        } else {
            const sign = crypto.createSign('sha256');
            sign.update(raw);
            this.signature = sign.sign(ecPrivateKeyToPEM(privateKey));
        }
        this.encoded = Buffer.concat([this.raw, this.signature]).toString('base64');
    }

    /**
     * Deserializes an encoded token and returns an object with the fields.
     * @param {Buffer|string} serialized - binary Buffer or Base64 encoded string
     * @returns {Object} token fields
     */
    static deserialize(serialized) {
        let fields = {};
        if(serialized instanceof String) {
            serialized = new Buffer(serialized, 'base64');
        }
        let offset = 0;
        fields.version = serialized.readUInt8(offset);
        offset += 1;
        fields.type = serialized.readUInt8(offset);
        offset += 1;
        fields.id = serialized.slice(offset, offset + 16);
        offset += 16;
        fields.options = serialized.readUInt8(offset);
        offset += 1;
        let issuerLength = serialized.readUInt16BE(offset);
        offset += 2;
        fields.issuer = serialized.slice(offset, offset + issuerLength).toString('ascii');
        offset += issuerLength;
        let audienceLength = serialized.readUInt16BE(offset);
        offset += 2;
        fields.audience = serialized.slice(offset, offset + audienceLength).toString('ascii');
        offset += audienceLength;
        let issuedTimeLength = serialized.readUInt16BE(offset);
        offset += 2;
        fields.issuedTime = serialized.slice(offset, offset + issuedTimeLength).toString('ascii');
        offset += issuedTimeLength;
        let dataLength = serialized.readUInt16BE(offset);
        offset += 2;
        fields.data = serialized.slice(offset, offset + dataLength);
        offset += dataLength;
        let bindingLength = serialized.readUInt16BE(offset);
        offset += 2;
        fields.binding = serialized.slice(offset, offset + bindingLength);
        offset += bindingLength;
        fields.raw = serialized.slice(0, offset);
        fields.signatureIndex = offset;
        fields.signature = serialized.slice(offset, serialized.length);
        fields.encoded = serialized.toString('base64');
        return fields;
    }

    /**
     * Construct a RecoveryToken from a serialized string or Buffer.  Does not check signature!
     * @param {string|Buffer} serialized - binary Buffer or Base64 encoded serialized string
     * @returns {RecoveryToken}
     * @throws {Error} if any input fields are invalid
     */
    static fromSerialized(serialized) {
        let fields = RecoveryToken.deserialize(serialized);
        if (fields.version !== RecoveryToken.VERSION) { throw new Error('incorrect version'); }
        if (fields.type !== RecoveryToken.TYPE_RECOVERY_TOKEN) { throw new Error('incorrect type'); }
        return new RecoveryToken(
            null,
            fields.id,
            fields.options,
            fields.issuer,
            fields.audience,
            fields.issuedTime,
            fields.data,
            fields.binding,
            fields.signature
        );
    }

    /**
     * Check if the signature on a token is valid.
     * @param {string|Buffer} serialized - binary token as Buffer or Base64 encoded string
     * @param {string[]} keys - array of base64 encoded EC Public Keys, no newlines or PEM wrapping
     * @param {number} [signatureOffset] - start offset of signature (if already known from parsing)
     * @return {boolean}
     */
    static isSignatureValid(serialized, keys, signatureOffset = null) {
        if (serialized instanceof String) {
            serialized = new Buffer(serialized, 'base64');
        }

        if (signatureOffset === null) {
            signatureOffset = RecoveryToken.deserialize(serialized).signatureOffset;
        }

        const raw = serialized.slice(0, signatureOffset);
        const sig = serialized.slice(signatureOffset);

        for (let i = 0; i < keys.length; i++) {
            let verify = crypto.createVerify('sha256');
            verify.update(raw);
            let pem = publicKeyToPEM(keys[i]);
            if (verify.verify(pem, sig)) {
                return true;
            }
        }
        return false;
    }
}

/**
 * Class representing a RecoveryToken.
 */
class CountersignedToken extends RecoveryToken {
    constructor(id, options, issuer, audience, issuedTime, data, binding, signature) {
        super(null, id, options, issuer, audience, issuedTime, data, binding, signature);
        this.type = RecoveryToken.TYPE_COUNTERSIGNED_TOKEN;
    }

    /**
     * Construct a CountersignedToken from a serialized form. This function requires passing in public keys
     * to check the signature of the token and will throw an Error if the signature is invalid.
     * @param {string|Buffer} serialized - binary Buffer or Base64 encoded string serialization of the token
     * @param {string} issuer - expected issuer, Error thrown if mismatch with serialized token
     * @param {string} audience - expected audience, Error thrown if mismatch with serialized token
     * @param {number} allowedClockSkew - how many seconds forward or back the issued time can be vs. now, or Error
     * @param {Buffer} binding - Buffer of token binding data, can be empty
     * @param {string[]} publicKeys - array of base64 encoded EC public keys to check signature.
     * @returns {CountersignedToken}
     * @throws {Error} if token is invalid, doesn't match expected values or signature validation fails
     */
    static fromSerialized(serialized, issuer, audience, allowedClockSkew, binding, publicKeys) {
        let fields = RecoveryToken.deserialize(serialized);
        if (fields.version !== RecoveryToken.VERSION) { throw new Error('incorrect version'); }
        if (fields.type !== RecoveryToken.TYPE_COUNTERSIGNED_TOKEN) { throw new Error('incorrect type'); }
        if (fields.issuer !== issuer) { throw new Error('incorrect issuer'); }
        if (fields.audience !== audience) { throw new Error('incorrect audience'); }
        if (!fields.binding.equals(binding)) { throw new Error('incorrect token binding'); }

        let issuedTime = new Date(fields.issuedTime);
        if (Math.abs(issuedTime.value - new Date().value) > (allowedClockSkew * 1000)) {
            throw new Error('token issued outside allowed clock skew');
        }

        const token = new CountersignedToken(
            fields.id,
            fields.options,
            fields.issuer,
            fields.audience,
            fields.issuedTime,
            fields.data,
            fields.binding,
            fields.signature
        );

        if (!RecoveryToken.isSignatureValid(serialized, publicKeys, fields.signatureIndex)) {
            throw new Error('invalid countersigned token signature');
        }

        return token;
    }
}

/**
 * Helper function to return the hex value of the sha256 digest of the supplied buffer.
 * @param {Buffer} buffer - buffer to hash
 * @returns {srring} hex encoded digest
 */
function sha256(buffer) {
    return new Buffer(crypto.createHash('sha256').update(buffer).digest()).toString('hex');
}

/**
 * Fetch the delegated account recovery configuration for a given origin, if present
 * @param {string} origin - https:// ASCII encoded origin to fetch from
 * @param {Object} options - set extras, as per options object used by Node https module
 * @returns {Promise} resolves to a configuration object or rejects if fetch or parse fails
 */
function fetchConfiguration(origin, options) {
    options = options || {};
    return new Promise((resolve, reject) => {
        try {
            let u = url.parse(origin + CONFIG_PATH);
            options.hostname = u.hostname;
            options.path = u.path;
            if (u.port) {
                options.port = u.port;
            }
            https.get(options, (res) => {
                let body = '';
                res.setEncoding('utf8');
                res.on('data', (d) => {
                    body += d;
                });
                res.on('end', () => {
                    try {
                        let json = JSON.parse(body);
                        json.issuer = json.issuer.toLowerCase();
                        if (json.issuer.search(originRegex) != 0) {
                            reject('Malformed origin for issuer in config: ' + json.issuer);
                        }
                        resolve(json);
                    } catch (e) {
                        reject('Couldn\'t parse configuration from ' + origin);
                    }
                });
            }).on('error', (e) => {
                reject('Couldn\'t fetch configuration from ' + origin + ', error: ' + e);
            });
        } catch (e) {
            reject('Couldn\'t fetch configuration from ' + origin + ', error: ' + e);
        }
    });
}

/**
 * Extracts just the issuer string from a serialized token.
 * @param {string} tokenBase64 - the base64 encoded token
 * @returns {string} the issuer origin
 */
function extractIssuer(tokenBase64) {
    let offset = 19;
    let buffer = new Buffer(tokenBase64, 'base64');
    let issuerLength = buffer.readUInt16BE(offset);
    offset += 2;
    return buffer.slice(offset, offset + issuerLength).toString('ascii');
}

/**
 * @typedef middlewareOptions
 * @type {object}
 * @property {string[]} publicKeys - array of base64 encoded public keys used to sign tokens by this service
 * @property {string} save-token-return - path of save-token-return endpoint
 * @property {string} recover-account-return - path of recover-account-return endpoint
 * @property {string} privacy-policy - privacy policy path
 * @property {string} icon-152px: icon path
 * @property {number} config-max-age: cache-control header max-age value for configuration (default 3600)}
 */

/**
 * @param {middlewareOptions} options
 */
function middleware(options) {
    let opts = options || {};
    let kps = options['publicKeys'];
    let tokensignPubkeysSecp256r1 = [];

    for (let i = 0; i < kps.length; i++) {
        tokensignPubkeysSecp256r1.push(kps[i]);
    }

    return (req, res, next) => {
        if (req.path === CONFIG_PATH) {
            let maxAge = options['config-max-age'] === null ? 3600 // one hour
                : options['config-max-age'];
            res.set('Cache-Control', `public, max-age=${maxAge}`);
            res.set('Access-Control-Allow-Origin', '*');
            res.json({
                'issuer': 'https://' + opts['issuer'],
                'tokensign-pubkeys-secp256r1': tokensignPubkeysSecp256r1,
                'recover-account-return': `https://${req.headers.host + opts['recover-account-return']}`,
                'save-token-return': `https://${req.headers.host + opts['save-token-return']}`,
                'privacy-policy': `https://${req.headers.host + opts['privacy-policy']}`,
                'icon-152px': `https://${req.headers.host + opts['icon-152px']}`,
            });
        } else {
            next();
        }
    };
}

module.exports = {
    RecoveryToken: RecoveryToken,
    CountersignedToken: CountersignedToken,
    middleware: middleware,
    fetchConfiguration: fetchConfiguration,
    sha256: sha256,
    extractIssuer: extractIssuer,
    CONFIG_PATH: CONFIG_PATH,
    STATUS_PATH: STATUS_PATH,
};

/*
 * Internal helper functions
 */

function toPEM(inKey, typeStr) {
    let pem = `-----BEGIN ${typeStr}-----\n`;
    for (let i = 0; i < inKey.length; i++) {
        pem += inKey[i];
        if (((i + 1) % 64) == 0) {
            pem += '\n';
        }
    }
    pem += `\n-----END ${typeStr}-----\n`;
    return pem;
}

function ecPrivateKeyToPEM(inKey) {
    return toPEM(inKey, 'EC PRIVATE KEY');
}

function publicKeyToPEM(inKey) {
    return toPEM(inKey, 'PUBLIC KEY');
}
