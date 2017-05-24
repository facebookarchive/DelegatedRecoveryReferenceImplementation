// Copyright 2016-present, Facebook, Inc.
// All rights reserved.
//
// This source code is licensed under the license found in the
// LICENSE-examples file in the root directory of this source tree.
package com.fbsamples.delegatedrecovery.sparkapp;

/**
 * Web and template paths for the example application.
 */
public class Path {

  public static class Web {
    public static final String DEFAULT = "/";
    public static final String SAVE_TOKEN = "/home/";
    public static final String SAVE_TOKEN_RETURN = "/save-token-return/";
    public static final String RECOVER_ACCOUNT_RETURN = "/recover-account-return/";
    public static final String ICON = "/icon.png";
    public static final String PRIVACY_POLICY = "/privacy.html";
    public static final String RECOVER_IDENTIFY_ACCOUNT = "/identify-account/";
    public static final String INVALIDATE_TOKEN = "/invalidate/";
    public static final String RENEW_TOKEN = "/renew/";
  }

  public static class Template {
    public static final String DEFAULT = "/index.mustache";
    public static final String SAVE_TOKEN = "/save.mustache";
    public static final String INVALIDATE_TOKEN = "/invalidate.mustache";
    public static final String SAVE_TOKEN_SUCCESS = "/save_token_success.mustache";
    public static final String SAVE_TOKEN_FAILURE = "/save_token_failure.mustache";
    public static final String RECOVER_ACCOUNT_SUCCESS = "/recover_account_success.mustache";
    public static final String RECOVER_ACCOUNT_FAILURE = "/recover_account_failure.mustache";
    public static final String IDENTIFY_ACCOUNT = "/identify_account.mustache";
    public static final String RECOVER_ACCOUNT = "/recover_account.mustache";
    public static final String NO_SAVED_TOKEN = "/no_token.mustache";
    public static final String UNKNOWN_TOKEN = "/save_token_unknown.mustache";
    public static final String RENEW_TOKEN = "/renew.mustache";
  }
}
