/*
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant 
 * of patent rights can be found in the PATENTS file in the same directory.
 */
package com.facebook.delegatedrecovery;

import javax.json.JsonObject;
import java.net.URL;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

/**
 * Represents the configuration of a RecoveryProvider in the delegated account
 * recovery protocol
 */
public class RecoveryProviderConfiguration extends DelegatedRecoveryConfiguration {

  private final ECPublicKey[] pubKeys;
  private int tokenMaxSize;

  /**
   * @return instantiated EC public keys
   */
  public ECPublicKey[] getPubKeys() {
    return pubKeys == null ? null : pubKeys.clone();
  }

  /**
   * @return max token size, in bytes, a recovery provider is willing to accept
   */
  public int getTokenMaxSize() {
    return tokenMaxSize;
  }

  /**
   * @return save-token URL
   */
  public URL getSaveToken() {
    return saveToken;
  }

  /**
   * @return recover-account URL
   */
  public URL getRecoverAccount() {
    return recoverAccount;
  }

  /**
   * @return save-token-async-api-iframe URL
   */
  public URL getSaveTokenAsyncApiIframe() {
    return saveTokenAsyncApiIframe;
  }

  private URL saveToken;
  private URL recoverAccount;
  private URL saveTokenAsyncApiIframe;

  /**
   * Constructor from raw JSON as published
   * 
   * @param json The JSON blob to pull the data out of
   * @throws Exception If the JSON fails to parse of if URL's in the json are invalid.
   */
  public RecoveryProviderConfiguration(final JsonObject json) throws Exception {
    super(json);
    String stString = json.getString("save-token");
    this.saveToken = new URL(stString);
    String raString = json.getString("recover-account");
    this.recoverAccount = new URL(raString);
    String saveTokenAsyncApiIframe = json.getString("save-token-async-api-iframe");
    this.saveTokenAsyncApiIframe = new URL(saveTokenAsyncApiIframe);
    pubKeys = keysFromJsonArray(json.getJsonArray("countersign-pubkeys-secp256r1"));
  }

  public String toString() {
    StringBuilder out = new StringBuilder(300);
    out.append("RecoveryProviderConfiguration: ")
       .append("\n  issuer: ").append(getIssuer())
       .append("\n  privacy-policy: ").append(getPrivacyPolicy())
       .append("\n  icon-152px: ").append(getIcon152px())
       .append("\n  save-token: ").append(getSaveToken())
       .append("\n  recover-account: ").append(getRecoverAccount())
       .append("\n  save-token-async-api-iframe: ").append(getSaveTokenAsyncApiIframe())
       .append("\n  countersign-pubkeys-secp256r1: [\n");
    for (final ECPublicKey key : pubKeys) {
      out.append("    ")
         .append(Base64.getEncoder().encodeToString(key.getEncoded()))
         .append("\n");
    }
    out.append("]\n");
    return out.toString();
  }

}
