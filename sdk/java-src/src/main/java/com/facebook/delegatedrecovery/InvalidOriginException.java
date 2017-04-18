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
 * Thrown if what should be an RFC6454 Origin is not. (check for disallowed
 * trailing slashes)
 */
public class InvalidOriginException extends Exception {

  private static final long serialVersionUID = -8278122378279640808L;

  public InvalidOriginException(String message) {
    super(message);
  }

}
