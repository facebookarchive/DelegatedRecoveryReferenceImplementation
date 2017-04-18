/*
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant 
 * of patent rights can be found in the PATENTS file in the same directory.
 */
package com.facebook.delegatedrecovery;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import javax.json.JsonArray;
import javax.json.JsonObject;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

/**
 * Abstract superclass for RecoveryProvider and AccountProvider configurations.
 */
public abstract class DelegatedRecoveryConfiguration {

  /**
   * Enum determining whether an instantiated configuration is for a recovery or
   * account provider. A given JSON configuration published at the well-known
   * endpoint may contain the keys representing information for use in both
   * roles, but must be instantiated separately, in a typed fashion, for use in
   * code
   */
  public enum ConfigType {
    ACCOUNT_PROVIDER, RECOVERY_PROVIDER
  }

  /**
   * The well=known URL path at which a delegated recovery configuration is
   * published
   */
  public static final String CONFIG_PATH = "/.well-known/delegated-account-recovery/configuration";

  /**
   * The well=known URL path at which a the token status endpoint must listen
   */
  public static final String TOKEN_STATUS_PATH = "/.well-known/delegated-account-recovery/token-status";

  /**
   * Time in seconds until a fetched configuration is considered stale, by
   * default. Override by calling setMaxAge() with the value of the
   * Cache-Control header or your own preferred default.
   */
  public static final int DEFAULT_EXPIRY = 60 * 60;

  // public keys are of fixed length when encoded, so this ASN.1 prefix is
  // always the same. sometimes it is easier
  // to just add/remove it directly to move between encoded and unencoded public
  // points
  private final static byte[] PEM_ASN1_PREFIX = new byte[] { 48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8,
          42, -122, 72, -50, 61, 3, 1, 7, 3, 66, 0 };

  private final String issuer;
  private final URL privacyPolicy;
  private URL icon152px;
  private Date expires = new Date(new Date().getTime() + (DEFAULT_EXPIRY * 1000));

  /**
   * @return RFC 6454 Origin string representing issuer
   */
  public String getIssuer() {
    return issuer;
  }

  /**
   * @return Privacy policy URL
   */
  public URL getPrivacyPolicy() {
    return privacyPolicy;
  }

  /**
   * @return URL of 152x152 pixel PING icon file
   */
  public URL getIcon152px() {
    return icon152px;
  }

  /**
   * If a configuration is served with a Cache-Control HTTP header, the max-age
   * value can be set at construction time to determine expiration.
   * 
   * @param maxAge new max age value
   */
  public void setMaxAge(final int maxAge) {
    this.expires = new Date(new Date().getTime() + (maxAge * 1000));
  }

  /**
   * Test if the configuration is expired and should be re-fetched based on its
   * max age
   * 
   * @return if configuration is expired
   */
  public boolean isExpired() {
    return new Date().after(expires);
  }

  /**
   * Superclass shared constructor logic
   * 
   * @param issuer The issuer
   * @param privacyPolicy the privacy policy URL
   * @param icon152px a URL to an icon
   * @throws MalformedURLException if the url for the privacy policy or icon is malformed
   */
  protected DelegatedRecoveryConfiguration(final String issuer, final String privacyPolicy, final String icon152px)
      throws MalformedURLException {
    this.issuer = issuer;
    this.privacyPolicy = new URL(privacyPolicy);
    this.icon152px = new URL(icon152px);
  }

  /**
   * Superclass shared constructor logic
   * 
   * @param json The json to parse the data out of
   * @throws MalformedURLException if the privacy policy url is malformed
   * @throws InvalidOriginException if the issuer is invalid
   */
  protected DelegatedRecoveryConfiguration(final JsonObject json) throws MalformedURLException, InvalidOriginException {
    final String issuer = json.getString("issuer");
    DelegatedRecoveryUtils.validateOrigin(issuer);
    this.issuer = issuer;
    final String privacyPolicy = json.getString("privacy-policy");
    this.privacyPolicy = new URL(privacyPolicy);
    try {
      String icon152px = json.getString("icon-152px");
      this.icon152px = new URL(icon152px);
    } catch (Exception e) {
      this.icon152px = null;
    }
  }


  
  /**
   * Turn the JSON public key array from a configuration into a set of usable
   * public keys for ECDSA on secp256r1
   * 
   * @param array The JSON public key array
   * @return array of public keys decoded from the JSON array of base64 encoded
   *         strings
   */
  protected static ECPublicKey[] keysFromJsonArray(final JsonArray array) {
    try {
      final ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
      final KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
      final ECNamedCurveSpec params = new ECNamedCurveSpec("prime256v1", spec.getCurve(), spec.getG(), spec.getN());
      final ArrayList<ECPublicKey> pubKeys = new ArrayList<ECPublicKey>(array.size());

      for (int i = 0; i < array.size(); i++) {
        final String b64 = array.getString(i);
        final byte[] pubKeyAsn1 = Base64.getDecoder().decode(b64);
        final byte[] pubKey = new byte[pubKeyAsn1.length - PEM_ASN1_PREFIX.length]; // trim
                                                                              // PEM
                                                                              // ASN.1
                                                                              // prefix
        System.arraycopy(pubKeyAsn1, PEM_ASN1_PREFIX.length, pubKey, 0, pubKey.length);
        final ECPoint point = ECPointUtil.decodePoint(params.getCurve(), pubKey);
        final ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
        try {
          final ECPublicKey pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
          pubKeys.add(pk);
        } catch (InvalidKeySpecException e) {
          System.err.println("InvalidKeySpecException while processing " + b64);
        }
      }
      return pubKeys.toArray(new ECPublicKey[pubKeys.size()]);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      System.err.println("Unable to initialize ECDSA key factor for prime256v1.  Cannot continue.");
      System.exit(1);
      return null; // unreachable but Eclipse complier wants me to return
                   // something. :P
    }
  }
}
