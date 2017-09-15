# Delegated Account Recovery Example Application for Node.js
  
The "examples/nodejs" directory of [https://github.com/facebook/DelegatedRecoveryReferenceImplementation](https://github.com/facebook/DelegatedRecoveryReferenceImplementation) provides an example web application and library for using the Delegated Account
Recovery protocol documented at [https://github.com/facebook/DelegatedRecoveryReferenceImplementation](https://github.com/facebook/DelegatedRecoveryReferenceImplementation)


## Usage
This is a `Node.js` application built with the `Express` framework. It is
packaged for deployment on `Heroku`, but should be easily adaptable to any `Node.js` environment.

`index.js` contains the example application. This application is,
apart from some cryptographic keys, stateless, and only demonstrates the protocol flows
without creating actual user accounts.  

This code is for example purposes only, to demonstrate the concepts of Delegated Account Recovery.  Because the application does not persist any state, you will not be able to recover "accounts" across resets of the runtime, including when Herkou puts the application to sleep and restores it.  
  
## Dependencies

The example application is written in
[ES2015](https://babeljs.io/docs/learn-es2015/) for
[Node JS](https://nodejs.org/en/) >= 6.10.0

It uses the `delegated-account-recovery` module to implement core features of Delegated Account Recovery.
  
The example application is built with the [Express](https://expressjs.com/)
framework. The application is built to run on the [Heroku](https://www.heroku.com/)
cloud application platform, but has only a few lines of Herkou-specific code,
to manage configuration of application secrets and handle Heroku's idiosyncracies
in how https is routed. The application should be easily adapted to any Node.js hosting
environment. Refer to the documentation for your specific environment to configure https
and secure storage for application secrets.

The example application requires the following additional `NPM` modules:

* [delegated-account-recovery](https://www.npmjs.com/package/delegated-account-recovery)
* [express](https://www.npmjs.com/package/express)
* [express-mustache](https://www.npmjs.com/package/express-mustache)
* [body-parser](https://www.npmjs.com/package/body-parser)

Following the step-by-step tutorial included in the example application will require

* a bash command line environment with git, openssl, and curl available
* a [Heroku](https://www.heroku.com/) account
* the [Heroku toolbelt](https://devcenter.heroku.com/articles/getting-started-with-nodejs#set-up) installed for working with Node.js applications

## Installation
Begin by forking the repository.  In the top right corner of [the repository home page on GitHub](https://github.com/facebook/DelegatedRecoveryReferenceImplementation), click **Fork** ![Fork](https://help.github.com/assets/images/help/repository/fork_button.jpg)

Now, in your bash command line, get a copy of the forked repository.
```bash
$ git clone https://github.com/{your-github-username}/DelegatedRecoveryReferenceImplementation
```
  
Change to the root directory of your cloned repository
```bash
$ cd DelegatedRecoveryReferenceImplementation
```
  
Edit the `examples/nodejs/app.json` and `examples/nodejs/package.json` files and make sure the "repository" properties point to your fork of the application.

**These steps must be run from the root directory of your repository clone.**  
  
1. First, commit your updates to app.json and package.json 
1. Next, create a heroku app. The results of this command will tell you your app name.
1. Push the subtree containing the example app to the `heroku` git remote created by step 2.
  
```bash
$ git commit -am "update app.json and package.json"
$ heroku create
```

Because we only want to push the example app, not the entire reference implementation repository, use the following command to deploy:
```
$ git subtree push --prefix examples/nodejs heroku master
```

Note, if you use `git commit --amend` as part of your develompent process, in order to re-deploy an amended commit to the subtree you will need to use the following command line:
```
$ git push heroku `git subtree split --prefix examples/nodejs`:master --force
```

Ensure that at least one instance of the app is running:
```bash
$ heroku ps:scale web=1
```

Next, you need to set some config variables for the application. You must
have a recent build of openssl to complete this step. 

First, you need to create the assymetric key pair for signing recovery tokens.
```bash
$ openssl ecparam -name prime256v1 -genkey -noout -out prime256v1-key.pem
$ openssl ec -in prime256v1-key.pem -pubout -out prime256v1-pub.pem
```

Make sure you don't check the secret keys into your source control.
(it's fine to check in the public key if you want)
```bash
$ echo "*.pem" >> .gitignore
```
  
And now we'll strip the PEM files down to unadorned, single-line base64
and set them as config variables.
```bash
$ heroku config:set RECOVERY_PRIVATE_KEY=`perl -p -e 's/\R//g; s/-----[\w\s]+-----//' prime256v1-key.pem`
$ heroku config:set RECOVERY_PUBLIC_KEY=`perl -p -e 's/\R//g; s/-----[\w\s]+-----//' prime256v1-pub.pem`
```

Now, set the value your application needs to report as its `issuer` in the Delegated Account Recovery configuration: (note that not trailing slash is allowed)
```bash
$ heroku config:set ISSUER_ORIGIN="https://{your-app-name}.herokuapp.com"
```
  
You can see your current configuration using:
```bash
$ heroku config
```

Check that your configuration is working in the application:
```bash
$ curl https://{your-app-name}.herokuapp.com/.well-known/delegated-account-recovery/configuration
```

You should get a JSON file that lists your public key as the first entry in the
array that is the value of the key `tokensign-pubkeys-secp256r1`

You can try the application itself by running:
  
```bash
$ heroku open
```

During the closed beta, you will only be able to use the sample applications when logging in to Facebook with a whitehat test account.  [Create and manage test accounts here](https://www.facebook.com/whitehat/accounts).
