// Copyright 2016-present, Facebook, Inc.
// All rights reserved.
//
// This source code is licensed under the license found in the
// LICENSE-examples file in the root directory of this source tree.
package com.fbsamples.delegatedrecovery.sparkapp;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Fake DAO pattern object to manage RecoveryTokenRecord objects. This just uses
 * a static ArrayList as a backing store and state is lost when the app is
 * restarted.
 */
public class RecoveryTokenRecordDao {

  static ArrayList<RecoveryTokenRecord> records = new ArrayList<RecoveryTokenRecord>();

  public static List<RecoveryTokenRecord> getSavedTokensForUser(String username) {
    return records.stream().filter(record -> record.getUsername().equals(username)).collect(Collectors.toList());
  }

  public static List<RecoveryTokenRecord> getSavedTokensForUser(String username, RecoveryTokenRecord.Status status) {
    return records.stream().filter(record -> record.getUsername().equals(username) && record.getStatus() == status)
        .collect(Collectors.toList());
  }

  public static RecoveryTokenRecord getTokenRecordById(String id) {
    return records.stream().filter(record -> record.getId().equals(id)).findFirst().orElse(null);
  }

  public static RecoveryTokenRecord getTokenRecordByHash(String hash) {
    return records.stream().filter(record -> record.getHash().equals(hash)).findFirst().orElse(null);
  }

  public static void addRecord(RecoveryTokenRecord record) {
    records.add(record);
  }

  public static void deleteRecordById(String id) {
    records.removeIf(record -> record.getId().equals(id));
  }

}
