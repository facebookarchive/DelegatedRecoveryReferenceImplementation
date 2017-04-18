// Copyright 2016-present, Facebook, Inc.
// All rights reserved.
//
// This source code is licensed under the license found in the
// LICENSE-examples file in the root directory of this source tree.
package com.fbsamples.delegatedrecovery.sparkapp;

import com.facebook.delegatedrecovery.CountersignedRecoveryToken;
import com.facebook.delegatedrecovery.DelegatedRecoveryConfiguration;
import com.facebook.delegatedrecovery.DelegatedRecoveryUtils;
import com.facebook.delegatedrecovery.RecoveryProviderConfiguration;
import spark.Request;
import spark.Response;
import spark.Route;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/**
 * Controller logic for the actions around recovering an account
 */
public class RecoverAccountController {

  // toy implementation of a replay cache for this sample app, data is lost on
  // app reload
  private static HashSet<String> replayCache = new HashSet<String>();

  /**
   * Identify the account to recover
   */
  public static Route serveIdentifyAccount = (Request req, Response res) -> {
    String username = req.queryParams("username");
    Map<String, Object> model = new HashMap<String, Object>();

    if (username == null || username.equals("")) {
      model.put("action", Path.Web.RECOVER_IDENTIFY_ACCOUNT);
      model.put("facebookRecover", Main.getRecoveryProviderConfig().getRecoverAccount().toString() + "?issuer="
          + Main.getAccountProviderConfig().getIssuer());
      return Main.render(model, Path.Template.IDENTIFY_ACCOUNT);
    } else {
      List<RecoveryTokenRecord> records = RecoveryTokenRecordDao.getSavedTokensForUser(username,
          RecoveryTokenRecord.Status.CONFIRMED);
      if (records.size() > 0) {
        RecoveryTokenRecord record = records.get(0);
        model.put("id", record.getId());
        model.put("username", username);
        model.put("action", Main.getRecoveryProviderConfig().getRecoverAccount());
        return Main.render(model, Path.Template.RECOVER_ACCOUNT);
      } else {
        model.put("username", username);
        return Main.render(model, Path.Template.NO_SAVED_TOKEN);
      }
    }
  };

  /**
   * Handle an incoming countersigned recovery token and give access to account
   * if correct
   */
  public static Route serveRecoverAccountReturn = (Request req, Response res) -> {
    try {
      String encoded = req.queryParams("token");
      if (encoded == null || encoded.equals("")) {
        throw new Exception("No recovery token.");
      }

      // check relay cache if we've seen this countersigned token before
      synchronized (replayCache) {
        if (replayCache.contains(encoded)) {
          throw new Exception("countersigned token replay detected!");
        } else {
          replayCache.add(encoded);
        }
      }

      String issuer = CountersignedRecoveryToken.extractIssuer(encoded);
      RecoveryProviderConfiguration recoveryProviderConfig = Main.getRecoveryProviderConfig();

      // if the token incoming isn't from Facebook, which we have cached, fetch
      // the correct configuration
      if (!issuer.equals(recoveryProviderConfig.getIssuer())) {
        recoveryProviderConfig = (RecoveryProviderConfiguration) DelegatedRecoveryUtils.fetchConfiguration(issuer,
            DelegatedRecoveryConfiguration.ConfigType.RECOVERY_PROVIDER);
      }

      // constructing a countersigned token automatically validates the outer
      // token
      CountersignedRecoveryToken countersignedToken = new CountersignedRecoveryToken(encoded, issuer,
          Main.getAccountProviderConfig().getIssuer(), // our service's issuer
                                                       // is audience for
                                                       // countersigned token
          recoveryProviderConfig.getPubKeys(), 60 * 60,// validity period in
                                                       // seconds (one hour)
          null                                         // no token binding expected
      );

      RecoveryTokenRecord record = RecoveryTokenRecordDao.getTokenRecordByHash(countersignedToken.getInnerTokenHash());
      String expectedUsername = req.queryParams("state");

      if (record == null) {
        throw new Exception("No record of this token. Perhaps you restarted this app since it was issued?");
      } else if (record.getStatus() != RecoveryTokenRecord.Status.CONFIRMED) {
        throw new Exception("The recovery token from this app wasn't market as valid.");
      } else if (expectedUsername != null && !expectedUsername.equals("")
          && !expectedUsername.equals(record.getUsername())) {
        throw new Exception("The recovery token from this app was not for " + expectedUsername);
      } else {
        Map<String, Object> model = new HashMap<String, Object>();
        model.put("username", record.getUsername());
        return Main.render(model, Path.Template.RECOVER_ACCOUNT_SUCCESS);
      }
    } catch (Exception e) {
      Map<String, Object> model = new HashMap<String, Object>();
      model.put("exception", e.getMessage());
      StringWriter sw = new StringWriter();
      e.printStackTrace(new PrintWriter(sw));
      model.put("stackTrace", sw.toString());
      return Main.render(model, Path.Template.RECOVER_ACCOUNT_FAILURE);
    }
  };

}
