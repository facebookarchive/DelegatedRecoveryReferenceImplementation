/*
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */
package com.facebook.delegatedrecovery;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;

/**
 * Represents the recovery token, and serves as a base class for the
 * countersigned recovery token, in the delegated account recovery protocol.
 */
public class RecoveryToken {

  /**
   * No options for token options field
   */
  public static final byte NO_OPTIONS = 0x00;

  /**
   * Status callbacks requested token options flag.
   */
  public static final byte STATUS_REQUESTED_FLAG = 0x01;

  /**
   * Low-friction token recovery requested options flag.
   */
  public static final byte LOW_FRICTION_REQUESTED_FLAG = 0x02;

  /**
   * Mandatory version field value.
   */
  public static final byte VERSION = 0x00;

  /**
   * Token type field for recovery token.
   */
  public static final byte TYPE_RECOVERY_TOKEN = 0x00;

  /**
   * Token type field for countersigned recovery token.
   */
  public static final byte TYPE_COUNTERSIGNED_TOKEN = 0x01;

  protected byte type;
  protected byte version;
  protected byte[] id;
  protected byte options;
  protected String issuer;
  protected String audience;
  protected String issuedTime;
  protected byte[] data;
  protected byte[] binding;
  protected byte[] signature;
  protected byte[] decoded;
  protected String encoded;

  /**
   * Construct a RecoveryToken.
   *
   * @param privateKey The key to sign this token with.
   * @param id A unique id for the key.
   * @param options A set of bit flags setting options on the token
   * @param issuer The RFC-6454 origin of the recovery service
   * @param audience The RFC-6454 origin of your service
   * @param data Additional data to store in the token, can be null. This data will not be encrypted by this method.
   * @param binding token binding string to verify against, usually null
   * @throws InvalidOriginException If the issuer or audience is invalid
   * @throws IOException If signature fails DER encoding
   */
  public RecoveryToken(
          final ECPrivateKey privateKey,
          final byte[] id,
          final byte options,
          final String issuer,
          final String audience,
          final byte[] data,
          final byte[] binding) throws InvalidOriginException, IOException {
    if (id == null || id.length != 16) {
      throw new InvalidParameterException("token id must be byte[16]");
    }
    DelegatedRecoveryUtils.validateOrigin(issuer);
    DelegatedRecoveryUtils.validateOrigin(audience);

    this.version = VERSION;
    this.type = TYPE_RECOVERY_TOKEN;
    this.id = id.clone();
    this.options = options;
    this.issuer = issuer;
    this.audience = audience;
    this.data = data.clone();
    this.binding = binding.clone();

    this.issuedTime = DelegatedRecoveryUtils.nowISO8601();

    final int tokenLength =
        1 + // uint8 version
        1 + // uint8 type
        16 + // byte[16] token_id
        1 + // uint8 options
        2 + // uint16 issuer_length
        issuer.length() + // issuer[issuer_length]
        2 + // uint16 audience_length
        audience.length() + // audience[audience_length]
        2 + // uint16 issued_time_length
        issuedTime.length() + // issued_time[isued_time_length]
        2 + // uint16 data_length
        data.length + // data[data_length]
        2 + // uint16 binding_length
        binding.length; // binding[binding_length]

    final byte[] rawToken = new byte[tokenLength];

    final ByteBuffer tokenBuffer = ByteBuffer.wrap(rawToken);
    tokenBuffer
            .put(RecoveryToken.VERSION)
            .put(RecoveryToken.TYPE_RECOVERY_TOKEN)
            .put(id)
            .put(options)
            .putChar((char) issuer.length())
            .put(issuer.getBytes(StandardCharsets.US_ASCII))
            .putChar((char) audience.length())
            .put(audience.getBytes(StandardCharsets.US_ASCII))
            .putChar((char) issuedTime.length())
            .put(issuedTime.getBytes(StandardCharsets.US_ASCII))
            .putChar((char) data.length)
            .put(data)
            .putChar((char) binding.length)
            .put(binding);

    final byte[] rawArray = rawToken;

    this.signature = getSignature(rawToken, privateKey);

    this.decoded = new byte[rawArray.length + signature.length];
    System.arraycopy(rawArray, 0, decoded, 0, rawArray.length);
    System.arraycopy(signature, 0, decoded, rawArray.length, signature.length);

    this.encoded = Base64.getEncoder().encodeToString(decoded);
  }

  /**
   * Check the signature on a token.
   *
   * @param keys they keys to validate
   * @return whether signature is valid
   * @throws InvalidKeyException If the keys are invalid
   * @throws SignatureException If the keys are invalid
   */
  public boolean isSignatureValid(final ECPublicKey[] keys) throws InvalidKeyException, SignatureException {
    try {
      final Signature verifier = Signature.getInstance("SHA256withECDSA");
      for (final ECPublicKey key : keys) {
        verifier.initVerify(key);
        verifier.update(Arrays.copyOfRange(decoded, 0, decoded.length - signature.length));
        if (verifier.verify(signature)) {
          return true;
        }
      }
      return false;
    } catch (final NoSuchAlgorithmException e) {
        throw new Error(e.getMessage());
    }
  }

  /**
   * Construct a token from an encoded string. This constructor does not
   * validate the token signature.
   *
   * @param encoded Base64 encoded binary token
   * @throws InvalidOriginException If the issuer or audience in the token are invalid
   */
  public RecoveryToken(final String encoded) throws InvalidOriginException {
    try {
      this.encoded = encoded;
      decoded = Base64.getDecoder().decode(encoded);

      int offset = 0;
      version = decoded[offset];
      offset += 1;
      type = decoded[offset];
      offset += 1;
      id = Arrays.copyOfRange(decoded, offset, offset + 16);
      offset += 16;
      options = decoded[offset];
      offset += 1;
      final int issuerLength = decoded[offset] << 8 & 0xFF00 | decoded[offset + 1] & 0xFF;
      offset += 2;
      issuer = new String(Arrays.copyOfRange(decoded, offset, offset + issuerLength), "US-ASCII");
      offset += issuerLength;
      final int audienceLength = decoded[offset] << 8 & 0xFF00 | decoded[offset + 1] & 0xFF;
      offset += 2;
      audience = new String(Arrays.copyOfRange(decoded, offset, offset + audienceLength), "US-ASCII");
      offset += audienceLength;
      final int issuedTimeLength = decoded[offset] << 8 & 0xFF00 | decoded[offset + 1] & 0xFF;
      offset += 2;
      issuedTime = new String(Arrays.copyOfRange(decoded, offset, offset + issuedTimeLength), "US-ASCII");
      offset += issuedTimeLength;
      final int dataLength = decoded[offset] << 8 & 0xFF00 | decoded[offset + 1] & 0xFF;
      offset += 2;
      data = Arrays.copyOfRange(decoded, offset, offset + dataLength);
      offset += dataLength;
      final int bindingLength = decoded[offset] << 8 & 0xFF00 | decoded[offset + 1] & 0xFF;
      offset += 2;
      binding = Arrays.copyOfRange(decoded, offset, offset + bindingLength);
      offset += bindingLength;
      signature = Arrays.copyOfRange(decoded, offset, decoded.length);

      commonSanityCheck();
      typedSanityCheck();
    } catch (final UnsupportedEncodingException e) {
        throw new Error(e.getMessage());
    }
  }

  protected void commonSanityCheck() throws InvalidOriginException {
    if (version != VERSION) {
      throw new IllegalArgumentException("illegal version");
    }
    DelegatedRecoveryUtils.validateOrigin(issuer);
    DelegatedRecoveryUtils.validateOrigin(audience);
  }

  protected void typedSanityCheck() {
    if (type != RecoveryToken.TYPE_COUNTERSIGNED_TOKEN) {
      throw new IllegalArgumentException("illegal token type");
    }
  }

  private byte[] getSignature(final byte[] rawArray, final ECPrivateKey privateKey) throws IOException {
    if (this.signature != null) {
      throw new IllegalStateException("This token already has a signature.");
    }
    final BigInteger privatePoint = privateKey.getS();

    final SHA256Digest digest = new SHA256Digest();
    final byte[] hash = new byte[digest.getByteLength()];
    digest.update(rawArray, 0, rawArray.length);
    digest.doFinal(hash, 0);

    final ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
    signer.init(true, new ECPrivateKeyParameters(privatePoint, DelegatedRecoveryUtils.P256_DOMAIN_PARAMS));
    final BigInteger[] signature = signer.generateSignature(hash);
    final ByteArrayOutputStream s = new ByteArrayOutputStream();
    final DERSequenceGenerator seq = new DERSequenceGenerator(s);
    seq.addObject(new ASN1Integer(signature[0]));
    seq.addObject(new ASN1Integer(signature[1]));
    seq.close();

    return s.toByteArray();
  }

  public byte getType() {
    return type;
  }

  public byte getVersion() {
    return version;
  }

  public byte[] getId() {
    return id == null ? null : id.clone();
  }

  public byte getOptions() {
    return options;
  }

  public String getIssuer() {
    return issuer;
  }

  public String getAudience() {
    return audience;
  }

  /**
   * ISO8601 time string
   * @return the issued time
   */
  public String getIssuedTime() {
    if (this.signature == null) {
      throw new IllegalStateException("This token has not been signed.  Call getSigned(privateKey) first.");
    }
    return issuedTime;
  }

  public byte[] getData() {
    return data == null ? null : data.clone();
  }

  public byte[] getBinding() {
    return binding == null ? null : binding.clone();
  }

  public byte[] getSignature() {
    return signature == null ? null : signature.clone();
  }

  public String getEncoded() throws IllegalStateException {
    return encoded;
  }
}
