// Copyright 2016-present, Facebook, Inc.
// All rights reserved.
//
// This source code is licensed under the license found in the
// LICENSE-examples file in the root directory of this source tree.
'use strict';
const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const mustacheExpress = require('express-mustache');
const delegatedRecoverySDK = require('delegated-account-recovery');
const RecoveryToken = delegatedRecoverySDK.RecoveryToken;
const CountersignedToken = delegatedRecoverySDK.CountersignedToken;
const path = require('./path.js');

////
// Heroku-specific config management.  Update for your own deployment strategy.
////
const recoveryPrivKey = process.env.RECOVERY_PRIVATE_KEY;
const recoveryPubKey = process.env.RECOVERY_PUBLIC_KEY;
const issuerOrigin = process.env.ISSUER_ORIGIN;

if (recoveryPrivKey === undefined || recoveryPubKey === undefined || issuerOrigin === undefined) {
    console.error('Necessary environment variables are not defined.');
    process.exit(1);
}
const recoveryProvider = 'https://www.facebook.com';

let cachedRecoveryProviderConfig = null;

function recoveryProviderConfig() {
    return new Promise((resolve, reject) => {
        if (cachedRecoveryProviderConfig === null) {
            delegatedRecoverySDK.fetchConfiguration(recoveryProvider).then(
                (config) => {
                    cachedRecoveryProviderConfig = config;
                    resolve(config);
                }, (e) => {
                reject(e);
            });
        } else {
            resolve(cachedRecoveryProviderConfig);
        }
    });
}

// app-specific record keeping
const tokenRecords = [];
const recordStatus = {
    provisional: 'provisional',
    confirmed: 'confirmed',
    invalid: 'invalid',
};

function createNewToken(username, config) {
    const id = crypto.randomBytes(16);
    const token = new RecoveryToken(
        recoveryPrivKey,
        id,
        RecoveryToken.STATUS_REQUESTED_FLAG,
        issuerOrigin,
        config.issuer,
        new Date().toISOString(),
        Buffer.alloc(0),
        Buffer.alloc(0));

    tokenRecords.push({
        status: recordStatus.provisional,
        username: username,
        id: id.toString('hex'),
        issuer: config.issuer,
        hash: delegatedRecoverySDK.sha256(new Buffer(token.encoded, 'base64')),
    });
    
    return token;
}

const app = express();
app.set('port', (process.env.PORT || 5000));
app.use(express.static(__dirname + '/static'));

// Register '.mustache' extension with The Mustache Express
app.engine('mustache', mustacheExpress.create());
app.set('view engine', 'mustache');
app.set('views', __dirname + '/static/templates');

app.use(bodyParser.urlencoded({
    extended: false,
}));

////
// Set up delegated recovery middleware
////

app.use(delegatedRecoverySDK.middleware({
    "issuer": issuerOrigin,
    "save-token-return": path.web.saveTokenReturn,
    "recover-account-return": path.web.recoverAccountReturn,
    "privacy-policy": path.web.privacyPolicy,
    "publicKeys": [recoveryPubKey],
    "icon-152px": path.web.icon,
    "config-max-age": 6000,
}));

////
// filters
////
app.all('*', (req, res, next) => {
    // this app should only be accessed over https and not framed
    res.set('Strict-Transport-Security', 'max-age=3600000; includeSubDomains');
    res.set('X-Frame-Options', 'DENY');
    if (req.path !== delegatedRecoverySDK.CONFIG_PATH) {
        res.set('Cache-Control', 'no-store, must-revalidate');
    }

    // X-Forwarded-Proto is the Heroku-specific way to tell if original
    // request used https
    const forwardedProto = req.get('X-Forwarded-Proto');
    if (req.hostname !== 'localhost' && forwardedProto !== null && forwardedProto !== 'https') {
        // sensitive data endpoints used by APIs should not automatically redirect
        if (req.path  === delegatedRecoverySDK.CONFIG_PATH ||
            req.path === path.web.recoverAccountReturn) {
            res.send(401, 'Not available at this scheme.  Use https.\n');
        } else {
            res.redirect('https://' + req.hostname + req.path + '?' + req.query);
        }
    } else {
        next();
    }
});

////
// Routes
////

app.get(path.web.default, (req, res) => {
    res.render(path.template.default, {
        "action": path.web.saveToken,
        "recoverAction": path.web.recoverIdentifyAccount,
    });
});

app.get(path.web.saveToken, (req, res) => {
    const username = req.query.username;
    if (username === null) {
        res.redirect(path.template.default);
    } else {
        const tokenRecord = tokenRecords.find((record) => {
            return (record.username === username && record.status === recordStatus.confirmed);
        });

        if (tokenRecord === undefined) {
            recoveryProviderConfig().then((config) => {
                const token = createNewToken(username, config);
                res.render(path.template.saveToken, {
                    "encoded-token": token.encoded,
                    "username": username,
                    "state": token.id.toString('hex'),
                    "save-token": config['save-token'],
                });
            }, (e) => {
                res.send(500, e.message);
            });
        } else {
            res.render(path.template.invalidateToken, {
                "action": path.web.invalidateToken,
                "renew-action": path.web.renewToken,
                "id": tokenRecord.id,
                "username": username,
            });
        }
    }
});

app.get(path.web.saveTokenReturn, (req, res) => {
    const state = req.query.state;
    const ids = state.split(',', 2);
    const tokenRecord = tokenRecords.find((record) => record.id === ids[0]);
    
    let obsoletedRecord = null;
    
    if (ids.length > 1) {
        obsoletedRecord = tokenRecords.find((record) => {
            return (record.id === ids[1] && record.status === recordStatus.confirmed);
        });
    }

    if (tokenRecord === undefined) {
        res.render(path.template.unknownToken, {
            "action": path.web.default,
        });
    } else if (req.query.status === 'save-success') {
        tokenRecord.status = recordStatus.confirmed;
        if (obsoletedRecord !== null) {
            obsoletedRecord.status = recordStatus.invalid;
        }
        res.render(path.template.saveTokenSuccess, {
            "username": tokenRecord.username,
        });
    } else {
        tokenRecords.splice(tokenRecords.findIndex((record) => record.id === ids[0]), 1);
        res.render(path.template.saveTokenFailure, {
            "username": tokenRecord.username,
            "homeAction": path.web.saveToken,
        });
    }
});

app.get(path.web.invalidateToken, (req, res) => {
    const id = req.query.id;
    const username = req.query.username;
    const tokenRecord = tokenRecords.find((record) => record.id === id);
    if (tokenRecord !== undefined) {
        tokenRecord.status = recordStatus.invalid;
    }
    res.redirect(path.web.saveToken + '?username=' + username);
});

app.get(path.web.recoverIdentifyAccount, (req, res) => {
    recoveryProviderConfig().then((config) => {
        const username = req.query.username;

        if (username === null || username === '') {
            res.render(path.template.identifyAccount, {
                "action": path.web.recoverIdentifyAccount,
                "facebookRecover": config['recover-account'] + '?issuer=' + issuerOrigin,
            });
        } else {
            const record = tokenRecords.find((record) => {
                return record.username === username && record.status === recordStatus.confirmed;
            });

            if (record !== undefined) {
                res.render(path.template.recoverAccount, {
                    "id": record.id,
                    "username": username,
                    "action": config['recover-account'],
                });
            } else {
                res.render(path.template.noSavedToken, {
                    "username": username,
                });
            }
        }
    }, (e) => {
        res.send(500, e);
    });
});

app.get(path.web.renewToken, (req, res) => {
    const obsoleteId = req.query.id;
    const username = req.query.username;
    
    recoveryProviderConfig().then((config) => {
        const token = createNewToken(username, config);
        res.render(path.template.renewToken, {
            "encoded-token": token.encoded,
            "username": username,
            "renew-action": config['save-token'],
            "state": token.id.toString('hex') + "," + obsoleteId,
            "obsoletes": obsoleteId,
        });
    }, (e) => {
        res.send(500, e.message);
    });
});

const replayCache = [];

app.post(path.web.recoverAccountReturn, (req, res) => {
    let errorFlag = false;

    const errorFunction = (message) => {
        errorFlag = true;
        res.render(path.template.recoverAccountFailure, {
            "exception": message,
        });
    };

    const token = req.body.token;
    if (token === null || token === '') {
        errorFunction('No token.');
    }

    if (replayCache.find((item) => item === token) !== undefined) {
        errorFunction('Countersigned token replay detected!');
    } else {
        replayCache.push(token);
    }

    const issuer = delegatedRecoverySDK.extractIssuer(token);

    // if multiple issuers were supported, would fetch config here, but
    // this sample app only uses Facebook with a statically cached config
    recoveryProviderConfig().then((config) => {
        if (issuer !== config.issuer) {
            errorFunction('Countersigned token issuer invalid: ' + issuer);
        }
        let countersignedToken = null;
        try {
            countersignedToken = CountersignedToken.fromSerialized(
                new Buffer(token, 'base64'),
                issuer,
                issuerOrigin,
                60 /*sec*/ * 60 /*min*/ , // 1 hour clock skew
                Buffer.alloc(0),
                config['countersign-pubkeys-secp256r1']
            );
        } catch (e) {
            errorFunction(e);
        }

        if (countersignedToken !== null) {
            const innerHash = delegatedRecoverySDK.sha256(countersignedToken.data);
            const expectedUsername = req.body.state;
            const record = tokenRecords.find((record) => record.hash === innerHash);

            if (record === undefined) {
                errorFunction('No record of this token. Perhaps you restarted this app since it was issued?');
            } else if (record.status !== recordStatus.confirmed) {
                errorFunction('The recovery token from this app wasn\'t marked as valid.');
            } else if (expectedUsername !== undefined && expectedUsername !== '' && expectedUsername !== record.username) {
                errorFunction('The recovery token from this app was not for ' + expectedUsername);
            }

            if (!errorFlag) {
                res.render(path.template.recoverAccountSuccess, {
                    "username": record.username,
                });
            }
        }
    }, (e) => {
        errorFunction(e);
    });
});

app.post(delegatedRecoverySDK.STATUS_PATH, (req, res) => {
    const id = req.body.id;
    const tokenRecord = tokenRecords.find((record) => record.id === id);
    if (tokenRecord !== undefined) {
        switch (req.body.status) {
        case 'save-success':
            tokenRecord.status = recordStatus.confirmed;
            break;
        case 'save-failure':
            tokenRecords.splice(tokenRecords.findIndex((record) => record.id === id), 1);
            break;
        case 'token-repudiated':
            tokenRecord.status = recordStatus.invalid;
            break;
        }
    }
    res.status(200).send();
});

app.listen(app.get('port'), () => {
    console.log('Node app is running on port', app.get('port'));
});