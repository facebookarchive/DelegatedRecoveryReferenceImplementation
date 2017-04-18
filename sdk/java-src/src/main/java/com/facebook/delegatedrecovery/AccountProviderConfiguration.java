/*
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant 
 * of patent rights can be found in the PATENTS file in the same directory.
 */
package com.facebook.delegatedrecovery;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonBuilderFactory;
import javax.json.JsonObject;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

/**
 * Represents the configuration published by an AccountProvider.
 */
public class AccountProviderConfiguration extends DelegatedRecoveryConfiguration {

  private final URL saveTokenReturn;
  private final URL recoverAccountReturn;
  private final ECPublicKey[] pubKeys;

  /**
   * Constructor for publication.
   * 
   * @param issuer The RFC-6454 origin of the recovery service
   * @param saveTokenReturn The URL to call to save the token
   * @param recoverAccountReturn The URL to call to recover the account
   * @param privacyPolicy A URL to the privacy policy
   * @param tokensignPubkeysSecp256r1 The token signing keys
   * @param icon152px a URL to a icon
   * @throws MalformedURLException if the URL fo the privacy policy, icon, saveTokenReturn, or recoverAccountReturn is malformed
   */
  public AccountProviderConfiguration(
          final String issuer,
          final String saveTokenReturn,
          final String recoverAccountReturn,
          final String privacyPolicy,
          final String[] tokensignPubkeysSecp256r1,
          final String icon152px) throws MalformedURLException {
    super(issuer, privacyPolicy, icon152px);
    this.saveTokenReturn = new URL(saveTokenReturn);
    this.recoverAccountReturn = new URL(recoverAccountReturn);

    JsonBuilderFactory factory = Json.createBuilderFactory(null);
    JsonArrayBuilder keyArray = factory.createArrayBuilder();
    for (String key : tokensignPubkeysSecp256r1) {
      keyArray.add(key);
    }
    this.pubKeys = keysFromJsonArray(keyArray.build());
  }

  /**
   * Constructor from JSON, as when retrieved remotely from a 3rd party
   * 
   * @param json JSON blob to parse the data from
   * @throws MalformedURLException If any of the URL's in the json are malformed
   * @throws InvalidOriginException If the issue is invalid.
   */
  public AccountProviderConfiguration(final JsonObject json) throws MalformedURLException, InvalidOriginException {
    super(json);
    String strString = json.getString("save-token-return");
    this.saveTokenReturn = new URL(strString);
    String rarString = json.getString("recover-account-return");
    this.recoverAccountReturn = new URL(rarString);
    pubKeys = keysFromJsonArray(json.getJsonArray("tokensign-pubkeys-secp256r1"));
  }

  /**
   * @return instantiated public keys for ECDSA on secp256r1 curve
   */
  public ECPublicKey[] getPubKeys() {
    return pubKeys == null ? null : pubKeys.clone();
  }

  /**
   * @return URL for save-token-return
   */
  public URL getSaveTokenReturn() {
    return saveTokenReturn;
  }

  /**
   * @return URL for recover-account-return
   */
  public URL getRecoverAccountReturn() {
    return recoverAccountReturn;
  }

  public String toString() {
    final JsonBuilderFactory factory = Json.createBuilderFactory(null);
    final JsonArrayBuilder keyArray = factory.createArrayBuilder();

    for (final ECPublicKey key : pubKeys) {
      keyArray.add(Base64.getEncoder().encodeToString(key.getEncoded()));
    }

    final JsonObject config = factory.createObjectBuilder().add("issuer", getIssuer())
        .add("save-token-return", getSaveTokenReturn().toString())
        .add("recover-account-return", getRecoverAccountReturn().toString())
        .add("icon-152px", getIcon152px().toString()).add("privacy-policy", getPrivacyPolicy().toString())
        .add("tokensign-pubkeys-secp256r1", keyArray.build()).build();

    return config.toString();
  }
}
