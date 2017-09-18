// Copyright 2016-present, Facebook, Inc.
// All rights reserved.
//
// This source code is licensed under the license found in the
// LICENSE-examples file in the root directory of this source tree.
'use strict;';

const web = {
    default: '/',
    saveToken: '/home/',
    saveTokenReturn: '/save-token-return/',
    recoverAccountReturn: '/recover-account-return/',
    icon: '/icon.png',
    privacyPolicy: '/privacy.html',
    recoverIdentifyAccount: '/identify-account/',
    invalidateToken: '/invalidate/',
    renewToken: '/renew/',
};

const template = {
    default: 'index.mustache',
    saveToken: 'save.mustache',
    invalidateToken: 'invalidate.mustache',
    saveTokenSuccess:  'save_token_success.mustache',
    saveTokenFailure: 'save_token_failure.mustache',
    recoverAccountSuccess: 'recover_account_success.mustache',
    recoverAccountFailure: 'recover_account_failure.mustache',
    identifyAccount: 'identify_account.mustache',
    recoverAccount: 'recover_account.mustache',
    noSavedToken: 'no_token.mustache',
    unknownToken: 'save_token_unknown.mustache',
    renewToken: 'renew.mustache',
};

module.exports = {
    web: web,
    template: template,
};
