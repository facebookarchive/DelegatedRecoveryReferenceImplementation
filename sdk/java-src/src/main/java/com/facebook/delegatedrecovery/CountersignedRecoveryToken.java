/*
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant 
 * of patent rights can be found in the PATENTS file in the same directory.
 */
package com.facebook.delegatedrecovery;

import org.bouncycastle.crypto.digests.SHA256Digest;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

/**
 * Represents a countersigned recovery token.
 */
public class CountersignedRecoveryToken extends RecoveryToken {

  /**
   * Extract the issuer from an encoded token so that the configuration can be
   * fetched.
   * 
   * @param encoded The encoded token
   * @return RFC6454 origin string
   */
  public static String extractIssuer(final String encoded) {
    try {
      final byte[] tmp = Base64.getDecoder().decode(encoded);
      int offset = 19;
      final int issuerLength = tmp[offset] << 8 & 0xFF00 | tmp[offset + 1] & 0xFF;
      offset += 2;
      return new String(Arrays.copyOfRange(tmp, offset, offset + issuerLength), "US-ASCII");
    } catch (final UnsupportedEncodingException e) {
      e.printStackTrace();
      System.err.println("US-ASCII encoding was unsupported. Cannot continue.");
      System.exit(1);
      return null; // unreachable
    }
  }

  /**
   * Construct a CountersignedRecovery token from an encoded string. This will
   * automatically verify the signature, issuer, audience and allowed age of the
   * token. InvalidTokenException is thrown if any of these checks fail. The
   * caller is responsible for checking against a replay cache, if desired.
   * 
   * @param encoded Base64 encoded string of the binary countersigned token
   * @param issuer The RFC-6454 origin of the recovery service
   * @param audience RFC-6454 origin of the your service
   * @param keys The countersigning keys to verify the token
   * @param allowedClockSkewSec How much clock skew to allow in seconds
   * @param binding token binding string to verify against, usually null
   * @throws InvalidTokenException If any of the checks fail.
   * @throws InvalidOriginException If the issuer is invalid
   * @throws SignatureException If the keys are invalid.
   * @throws InvalidKeyException If the keys are invalid.
   */
  public CountersignedRecoveryToken(
          final String encoded,
          final String issuer,
          final String audience,
          final ECPublicKey[] keys,
          final int allowedClockSkewSec,
          final byte[] binding) throws InvalidTokenException, InvalidOriginException, InvalidKeyException, SignatureException {
    super(encoded);
    if (!this.issuer.equals(issuer)) {
      throw new InvalidTokenException("issuer doesn't match expected");
    }
    if (!this.audience.equals(audience)) {
      throw new InvalidTokenException("audience doesn't match expected");
    }
    if(binding != null && !Arrays.equals(this.binding, binding)) {
      throw new InvalidTokenException("binding doesn't match expected");
    }

    if(!this.isSignatureValid(keys)) {
      throw new InvalidTokenException("token signature didn't verify");
    }
    
    try {
      final long issuedTime = DelegatedRecoveryUtils.fromISO8601(this.issuedTime).getTime();
      final long now = new Date().getTime();
      final long skew = Math.abs(issuedTime - now);

      if (skew > (allowedClockSkewSec * 1000 /* seconds */)) {
        throw new InvalidTokenException("Issued time for token outside valid clock skew window.");
      }
    } catch (ParseException pe) {
      throw new InvalidTokenException("unparsable issuedTime", pe);
    }

  }

  /**
   * Utility method to quickly get a hex-encoded SHA256 digest of the data field
   * of the countersigned token, which contains the original token.
   * 
   * @return hex encoded string of SHA256 digest
   */
  public String getInnerTokenHash() {
    final SHA256Digest digest = new SHA256Digest();
    final byte[] hash = new byte[digest.getByteLength()];
    digest.update(data, 0, data.length);
    digest.doFinal(hash, 0);
    return DelegatedRecoveryUtils.encodeHex(hash);
  }

  protected void typedSanityCheck() {
    if (type != RecoveryToken.TYPE_COUNTERSIGNED_TOKEN) {
      throw new IllegalArgumentException("illegal token type");
    }
  }
}
