/*
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant 
 * of patent rights can be found in the PATENTS file in the same directory.
 */
package com.facebook.delegatedrecovery;

/**
 * Thrown if there are problems validating a token.
 */
public class InvalidTokenException extends Exception {

  private static final long serialVersionUID = -8933032394580579696L;

  public InvalidTokenException(final String message) {
    super(message);
  }

  public InvalidTokenException(final Throwable cause) {
    super(cause);
  }

  public InvalidTokenException(final String message, final Throwable cause) {
    super(message, cause);
  }

}
