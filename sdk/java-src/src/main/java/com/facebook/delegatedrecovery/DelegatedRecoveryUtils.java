/*
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant 
 * of patent rights can be found in the PATENTS file in the same directory.
 */
package com.facebook.delegatedrecovery;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.TimeZone;
import java.util.regex.Pattern;

/**
 * Various utility functions for working with the Delegated Account Recovery
 * protocol
 */
public class DelegatedRecoveryUtils {

  private static final X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
  private static final char[] hexDigits =
          { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

  private static final Pattern ORIGIN_REGEX = Pattern
          .compile("^https://(?:[a-z0-9-]{1,63}\\.)+(?:[a-z]{2,63})(:[\\d]+)?$");

  private static final SecureRandom secureRandom = new SecureRandom();

  protected static final ECDomainParameters P256_DOMAIN_PARAMS = new ECDomainParameters(curve.getCurve(), curve.getG(),
      curve.getN(), curve.getH());

  private static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
  private static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
  private static final String BEGIN_EC_PRIVATE_KEY = "-----BEGIN EC PRIVATE KEY-----";
  private static final String END_EC_PRIVATE_KEY = "-----END EC PRIVATE KEY-----";

  /**
   * Converts a base64 encoded string of an ASN.1 encoded public key into the
   * PEM format with appropriate headers and line breaks so it can be read by
   * OpenSSL or a compatible parser
   * 
   * @param key A base64 encoded ASN.1 encoded public key
   * @return PEM string
   */
  public static String publicKeyToPEM(final ECPublicKey key) {
    final StringBuilder out = new StringBuilder(300);
    out.append(BEGIN_PUBLIC_KEY).append("\n")
       .append(Base64.getMimeEncoder(64, System.getProperty("line.separator").getBytes(StandardCharsets.UTF_8)).encodeToString(key.getEncoded()))
       .append("\n")
       .append(END_PUBLIC_KEY).append("\n")
       .append("\n");
    return out.toString();
  }

  /**
   * Loads a private key on the P-256 curve from a PEM file of the type created
   * by openssl ecparam -name prime256v1 -genkey -noout -out filename
   * 
   * @param filename The filename of the pem file
   * @return an EC key pair
   * @throws Exception If the file fails to read or parse.
   */
  public static KeyPair keyPairFromPEMFile(final String filename) throws Exception {
    final Reader reader = new InputStreamReader(new FileInputStream(filename), StandardCharsets.UTF_8);
    final PEMParser pemParser = new PEMParser(reader);
    final KeyPair kp = new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) pemParser.readObject());
    pemParser.close();
    return kp;
  }

  /**
   * As keyPairFromPEMFile but with a string instead of a file
   * 
   * @param key The key from a PEM file as a string
   * @return an EC key pair
   * @throws Exception If the string failes to parse.
   */
  public static KeyPair keyPairFromPEMString(final String key) throws Exception {
    final StringBuilder pem = new StringBuilder(300);
    pem.append(BEGIN_EC_PRIVATE_KEY + "\n");
    for (int i = 0; i < key.length(); i++) {
      pem.append(key.charAt(i));
      if ((i + 1) % 64 == 0) {
        pem.append("\n");
      }
    }
    pem.append("\n" + END_EC_PRIVATE_KEY + "\n");

    final StringReader reader = new StringReader(pem.toString());
    final PEMParser pemParser = new PEMParser(reader);
    final KeyPair kp = new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) pemParser.readObject());
    pemParser.close();
    return kp;
  }

  /**
   * Simple utility method to return a hex-encoded string of the SHA256 digest
   * of a byte[]
   * 
   * @param bytes The bytes to encode
   * @return The hex encoded bytes in a String
   */
  public static String sha256(final byte[] bytes) {
    // hash of the token to re-identify it later
    final SHA256Digest digest = new SHA256Digest();
    final byte[] hash = new byte[digest.getByteLength()];
    digest.update(bytes, 0, bytes.length);
    digest.doFinal(hash, 0);
    return DelegatedRecoveryUtils.encodeHex(hash);
  }

  /**
   * Makes an HTTPS request to fetch and parse the JSON delegated account
   * recovery protocol configuration from the well-known location.
   * 
   * @param origin The origin to fetch from, this will have the delegated recovery config path appended to it
   * @param type The type of config
   * @return configuration. Cast to AccountProviderConfiguation or
   *         RecoveryProviderConfiguration based on the type parameter
   * @throws Exception If something fails while fetching the config.
   */
  public static DelegatedRecoveryConfiguration fetchConfiguration(
        final String origin,
        final DelegatedRecoveryConfiguration.ConfigType type) throws Exception {
    DelegatedRecoveryUtils.validateOrigin(origin);

    final URL url = new URL(origin + DelegatedRecoveryConfiguration.CONFIG_PATH);
    try (final InputStream is = url.openStream(); final JsonReader rdr = Json.createReader(is)) {
      final JsonObject obj = rdr.readObject();
      DelegatedRecoveryConfiguration config;
      if (type == DelegatedRecoveryConfiguration.ConfigType.ACCOUNT_PROVIDER) {
        config = new AccountProviderConfiguration(obj);
      } else {
        config = new RecoveryProviderConfiguration(obj);
      }
      // TODO set max-age from Cache-Control header
      return config;
    }
  }

  /**
   * convenience method to encode a byte[] as a hex string
   * 
   * @param rawBytes The bytes to encode
   * @return a Hex string representing rawBytes
   */
  public static String encodeHex(final byte[] rawBytes) {
    final char[] hexChars = new char[rawBytes.length * 2];
    for (int i = 0; i < rawBytes.length; i++) {
      hexChars[i * 2] = DelegatedRecoveryUtils.hexDigits[(0xF0 & rawBytes[i]) >>> 4];
      hexChars[i * 2 + 1] = DelegatedRecoveryUtils.hexDigits[0x0F & rawBytes[i]];
    }
    return new String(hexChars);
  }

  /**
   * Validate that a string conforms to an RFC6454 ASCII Origin with the https
   * scheme.
   * @param origin The issuer or audience origin
   * @throws InvalidOriginException if the origin is invalid
   */
  public static void validateOrigin(final String origin) throws InvalidOriginException {
    if (!(DelegatedRecoveryUtils.ORIGIN_REGEX.matcher(origin).matches())) {
      throw new InvalidOriginException(
          origin + " is not a valid RFC 6454 ASCII Origin with https:// scheme and no path component.");
    }
  }

  /**
   * Get the current time formatted to ISO8601
   * 
   * @return date string
   */
  public static String nowISO8601() {
    final TimeZone tz = TimeZone.getTimeZone("UTC");
    final DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
    df.setTimeZone(tz);
    return df.format(new Date());
  }

  /**
   * Get a Date from an ISO8601 string
   * 
   * @param isoDateString The ISO8601 string
   * @return Date object
   * @throws ParseException if unable to parse date from string
   */
  public static Date fromISO8601(final String isoDateString) throws ParseException {
    final DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
    return df.parse(isoDateString);
  }

  /**
   * Generate a new token id, byte[16] using a SecureRandom source
   * 
   * @return byte[16]
   */
  public static byte[] newTokenID() {
    final byte[] id = new byte[16];
    DelegatedRecoveryUtils.secureRandom.nextBytes(id);
    return id;
  }
}
