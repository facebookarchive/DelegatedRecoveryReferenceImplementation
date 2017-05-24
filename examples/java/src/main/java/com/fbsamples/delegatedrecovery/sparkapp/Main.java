// Copyright 2016-present, Facebook, Inc.
// All rights reserved.
//
// This source code is licensed under the license found in the
// LICENSE-examples file in the root directory of this source tree.
package com.fbsamples.delegatedrecovery.sparkapp;

import com.facebook.delegatedrecovery.AccountProviderConfiguration;
import com.facebook.delegatedrecovery.DelegatedRecoveryConfiguration;
import com.facebook.delegatedrecovery.DelegatedRecoveryUtils;
import com.facebook.delegatedrecovery.RecoveryProviderConfiguration;
import spark.ModelAndView;
import spark.template.mustache.MustacheTemplateEngine;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static spark.Spark.*;
import static spark.debug.DebugScreen.enableDebugScreen;

/**
 * Main class for serving the example Spark application. See
 * https://sparkjava.com/ for framework documentation.
 */
public class Main {

  private static String RECOVERY_PROVIDER = "https://www.facebook.com";
  private static String ISSUER_ORIGIN;

  private static AccountProviderConfiguration accountProviderConfig;
  private static RecoveryProviderConfiguration recoveryProviderConfig;

  /**
   * @return statically cached account provider config
   */
  public static AccountProviderConfiguration getAccountProviderConfig() {
    return accountProviderConfig;
  }

  /**
   * @return statically cached recovery provider config for
   *         https://www.facebook.com
   */
  public static RecoveryProviderConfiguration getRecoveryProviderConfig() {
    return recoveryProviderConfig;
  }

  // static initialization of configuration data
  static {
    try {
      // load some config values from the environment (Heroku-specific)
      ISSUER_ORIGIN = new ProcessBuilder().environment().get("ISSUER_ORIGIN");
      String publicKey = new ProcessBuilder().environment().get("RECOVERY_PUBLIC_KEY");

      // build our configuration object statically
      accountProviderConfig =
              new AccountProviderConfiguration(
                  ISSUER_ORIGIN, // our issuer
                  ISSUER_ORIGIN + Path.Web.SAVE_TOKEN_RETURN,
                  ISSUER_ORIGIN + Path.Web.RECOVER_ACCOUNT_RETURN,
                  ISSUER_ORIGIN + Path.Web.PRIVACY_POLICY,
                  new String[] { publicKey },
                  ISSUER_ORIGIN + Path.Web.ICON);

      // pre-fetch and save the Facebook recovery provider configuration
      // a real application should examine and respect the Cache-Control:
      // max-age values for this data
      recoveryProviderConfig =
              (RecoveryProviderConfiguration) DelegatedRecoveryUtils.fetchConfiguration(
                      RECOVERY_PROVIDER,
                      DelegatedRecoveryConfiguration.ConfigType.RECOVERY_PROVIDER);

    } catch (Exception e) {
      e.printStackTrace();
      System.exit(0);
    }
  }

  public static void main(String[] args) {

    ////
    // Spark setup
    ////
    port(getHerokuAssignedPort());
    staticFiles.location("/static");
    enableDebugScreen();

    ////
    // Filters
    ////

    // this app should only be accessed over https and not framed
    before((req, res) -> {
      res.header("Strict-Transport-Security", "max-age=3600000; includeSubDomains");
      res.header("X-Frame-Options", "DENY");
      if(!req.pathInfo().equals(DelegatedRecoveryConfiguration.CONFIG_PATH)) {
        res.header("Cache-Control", "no-store, must-revalidate");
      }
    });

    // redirect http to https if not locally debugging
    before((req, res) -> {
      String path = Optional.ofNullable(req.pathInfo()).orElse("");
      // X-Forwarded-Proto is the Heroku way to tell if original request used https
      if (!Optional.ofNullable(req.headers("X-Forwarded-Proto")).orElse("https").equals("https")) {
        if (path.equals(DelegatedRecoveryConfiguration.CONFIG_PATH) || path.equals(Path.Web.RECOVER_ACCOUNT_RETURN)) {
          halt(401, "Not available at this scheme.  Use https.");
        } else {
          res.redirect("https://" + req.host() + path
              + Optional.ofNullable(req.queryString()).map(queryString -> "?" + queryString).orElse(""), 301); // moved
        } // permanently
      }
    });

    ////
    // Routes
    ////

    // account provider configuration
    get(DelegatedRecoveryConfiguration.CONFIG_PATH, "application/json", (req, res) -> {
      res.header("Cache-Control", "max-age=60");
      return accountProviderConfig.toString();
    });

    // "login" page at /
    get(Path.Web.DEFAULT, (req, res) -> {
      Map<String, Object> model = new HashMap<String, Object>();
      model.put("action", Path.Web.SAVE_TOKEN);
      model.put("recoverAction", Path.Web.RECOVER_IDENTIFY_ACCOUNT);
      return render(model, Path.Template.DEFAULT);
    });

    // save token actions
    get(Path.Web.SAVE_TOKEN, SaveTokenController.serveSaveToken);
    get(Path.Web.SAVE_TOKEN_RETURN, SaveTokenController.serveSaveTokenReturn);
    get(Path.Web.INVALIDATE_TOKEN, SaveTokenController.serveInvalidateToken);
    get(Path.Web.RENEW_TOKEN, SaveTokenController.serveRenewToken);

    // recover account actions
    get(Path.Web.RECOVER_IDENTIFY_ACCOUNT, RecoverAccountController.serveIdentifyAccount);
    post(Path.Web.RECOVER_ACCOUNT_RETURN, RecoverAccountController.serveRecoverAccountReturn);

    // token status callback
    post(DelegatedRecoveryConfiguration.TOKEN_STATUS_PATH, (req, res) -> {
      String id = req.queryParams("id");
      String status = req.queryParams("status");

      RecoveryTokenRecord record = RecoveryTokenRecordDao.getTokenRecordById(req.queryParams("id"));

      if (record != null && status != null) {
        if (status.equals("save-success")) {
          record.setStatus(RecoveryTokenRecord.Status.CONFIRMED);
        } else if (status.equals("save-failure") || status.equals("deleted")) {
          RecoveryTokenRecordDao.deleteRecordById(id);
        } else if (status.equals("token-repudiated")) {
          record.setStatus(RecoveryTokenRecord.Status.INVALID);
        }
      }
      res.status(200);
      return "";
    });

  }

  static int getHerokuAssignedPort() {
    ProcessBuilder processBuilder = new ProcessBuilder();
    if (processBuilder.environment().get("PORT") != null) {
      return Integer.parseInt(processBuilder.environment().get("PORT"));
    }
    return 4567; // return default port if heroku-port isn't set (i.e. on
                 // localhost)
  }

  /**
   * Avoid constantly re-typing new MoustacheTemplateEngine(), new
   * ModelAndView()
   *
   * @param model
   * @param templatePath
   * @return
   */
  public static String render(Map<String, Object> model, String templatePath) {
    return new MustacheTemplateEngine().render(new ModelAndView(model, templatePath));
  }
}
