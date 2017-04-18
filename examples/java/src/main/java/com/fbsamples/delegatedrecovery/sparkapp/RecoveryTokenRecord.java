// Copyright 2016-present, Facebook, Inc.
// All rights reserved.
//
// This source code is licensed under the license found in the
// LICENSE-examples file in the root directory of this source tree.
package com.fbsamples.delegatedrecovery.sparkapp;

/**
 * Simple representation of a recovery token that is saved at a Recovery
 * Provider. Remembering the id, hash, issuer and username avoids the necessity
 * to re-validate the inner token or manage long-term encryption keys at the
 * Account Provider
 */
public class RecoveryTokenRecord {

  public enum Status {
    PROVISIONAL, CONFIRMED, INVALID
  };

  private Status status;
  private String username;
  private String id;
  private String hash;
  private String issuer;

  public RecoveryTokenRecord(String username, String id, String issuer, String hash, Status status) {
    this.username = username;
    this.issuer = issuer;
    this.id = id;
    this.hash = hash;
    this.status = status;
  }

  public String getId() {
    return id;
  }

  public String getIssuer() {
    return issuer;
  }

  public Status getStatus() {
    return status;
  }

  public String getUsername() {
    return username;
  }

  public String getHash() {
    return hash;
  }

  public void setStatus(Status status) {
    this.status = status;
  }
}
