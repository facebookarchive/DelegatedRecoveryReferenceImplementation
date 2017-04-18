// Copyright 2016-present, Facebook, Inc.
// All rights reserved.
//
// This source code is licensed under the license found in the
// LICENSE-examples file in the root directory of this source tree.
package com.fbsamples.delegatedrecovery.sparkapp;

import com.facebook.delegatedrecovery.DelegatedRecoveryUtils;
import com.facebook.delegatedrecovery.RecoveryToken;
import spark.Request;
import spark.Response;
import spark.Route;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Controller logic for the actions around saving a recovery token
 */
public class SaveTokenController {

  private static ECPrivateKey privateKey;

  /*
   * Initialize the private key for token signing
   */
  static {
    try {
      String keystring = new ProcessBuilder().environment().get("RECOVERY_PRIVATE_KEY");
      KeyPair keypair = DelegatedRecoveryUtils.keyPairFromPEMString(keystring);
      privateKey = (ECPrivateKey) keypair.getPrivate();
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(0);
    }
  }

  /**
   * Landing page when returning from saving a token at Facebook, updates the
   * local records of token status in the RecoveryTokenRecordDao
   */
  public static Route serveSaveTokenReturn = (Request req, Response res) -> {
    Map<String, Object> model = new HashMap<String, Object>();
    String id = req.queryParams("state");
    RecoveryTokenRecord record = RecoveryTokenRecordDao.getTokenRecordById(id);

    if (record == null) {
      model.put("action", Path.Web.DEFAULT);
      return Main.render(model, Path.Template.UNKNOWN_TOKEN);
    }

    if (req.queryParams("status").equals("save-success")) {
      record.setStatus(RecoveryTokenRecord.Status.CONFIRMED);
      model.put("username", record.getUsername());
      return Main.render(model, Path.Template.SAVE_TOKEN_SUCCESS);
    } else {
      RecoveryTokenRecordDao.deleteRecordById(id);
      model.put("username", record.getUsername());
      model.put("homeAction", Path.Web.SAVE_TOKEN);
      return Main.render(model, Path.Template.SAVE_TOKEN_FAILURE);
    }
  };

  /**
   * Landing page of the app. Create and prompt to save a token at Facebook if
   * none found in the RecoveryTokenRecordDao for this username, or give option
   * to invalidate locally the token if one exists.
   */
  public static Route serveSaveToken = (Request req, Response res) -> {
    String username = req.queryParams("username");
    if (username == null || username.equals("")) {
      res.redirect(Path.Web.DEFAULT);
      return "";
    }

    // does this username already have a recovery token saved?
    List<RecoveryTokenRecord> savedTokens = RecoveryTokenRecordDao.getSavedTokensForUser(username,
        RecoveryTokenRecord.Status.CONFIRMED);

    Map<String, Object> model = new HashMap<String, Object>();

    if (savedTokens.isEmpty()) { // user has no saved tokens yet
      byte[] id = DelegatedRecoveryUtils.newTokenID();
      String stringID = DelegatedRecoveryUtils.encodeHex(id);

      RecoveryToken token = new RecoveryToken(privateKey, // signing key
          id, // token id
          RecoveryToken.STATUS_REQUESTED_FLAG, // get lifecycle callbacks
          Main.getAccountProviderConfig().getIssuer(), // our origin
          Main.getRecoveryProviderConfig().getIssuer(), // origin from
                                                        // Facebook's config
          new byte[0], // no data
          new byte[0]); // no binding

      String encoded = token.getEncoded();

      model.put("encoded-token", encoded);
      model.put("username", username);
      model.put("state", stringID);
      model.put("save-token", Main.getRecoveryProviderConfig().getSaveToken());

      // keep a record of tokens we've created for this username
      // (note, in this sample app this record does not survive service restart)
      RecoveryTokenRecordDao.addRecord(
          new RecoveryTokenRecord(
              username,
              stringID,
              token.getAudience(),
              DelegatedRecoveryUtils.sha256(Base64.getDecoder().decode(encoded)),
              RecoveryTokenRecord.Status.PROVISIONAL));

      return Main.render(model, Path.Template.SAVE_TOKEN);
    } else {
      model.put("action", Path.Web.INVALIDATE_TOKEN);
      model.put("id", savedTokens.get(0).getId());
      model.put("username", username);
      return Main.render(model, Path.Template.INVALIDATE_TOKEN);
    }
  };

  /**
   * Locally mark a token as no longer valid.
   */
  public static Route serveInvalidateToken = (Request req, Response res) -> {
    String id = req.queryParams("id");
    String username = req.queryParams("username");
    RecoveryTokenRecord record = RecoveryTokenRecordDao.getTokenRecordById(id);
    if (record != null) {
      record.setStatus(RecoveryTokenRecord.Status.INVALID);
    }
    res.redirect(Path.Web.SAVE_TOKEN + "?username=" + username);
    return "";
  };
}
