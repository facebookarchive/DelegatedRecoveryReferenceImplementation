# Delegated Account Recovery Example Application for Java
The "examples/java"  directory of
[https://github.com/facebook/DelegatedRecoveryReferenceImplementation](https://github.com/facebook/DelegatedRecoveryReferenceImplementation) provides an example web application and library for using the Delegated Account
Recovery protocol documented at [https://github.com/facebook/DelegatedRecoveryReferenceImplementation](https://github.com/facebook/DelegatedRecoveryReferenceImplementation)

**This is an alpha implementation and subject to change.**

## Sample app
The `com.fbsamples.delegatedrecovery.sparkapp` package contains a sample
app that demonstrates the basic features of using delegated account recovery
with Facebook.  It is intended to demonstrate concepts and is for evaluation purposes only.

## Dependencies
Java version 1.8 is required.

The sample app is built using the [Spark Framework](https://sparkjava.com/).

The application is built to deploy on [Heroku](https://heroku.com/).

The overall project is build using [Maven](https://maven.apache.org/) and its
dependencies are listed in the `pom.xml` file.

## Installation
Begin by forking the repository.  In the top right corner of [the repository home page on GitHub](https://github.com/facebook/DelegatedRecoveryReferenceImplementation), click **Fork** ![Fork](https://help.github.com/assets/images/help/repository/fork_button.jpg)

Now, in your bash command line, get a copy of the forked repository.
```bash
$ git clone https://github.com/{your-github-username}/DelegatedRecoveryReferenceImplementation
```
  
Change to the sample application directory of your cloned repository
```bash
$ cd DelegatedRecoveryReferenceImplementation/examples/java
```

To deploy, pick a name for your app on Heroku.  Using the command line Heroku toolbelt,
create the app.
```bash
$ heroku create my-app-name
```
  
Then create a file called 'heroku.properties' that defines your app name
```bash
$ echo "heroku.appName=my-app-name" >> heroku.properties
$ echo "heroku.properties" >> .gitignore
```
  
Next, you need to set some config variables for the application. 
You must have a recent build of openssl to complete this step. 

First set the issuer origin:
  
```bash
$ heroku config:set ISSUER_ORIGIN=https://{my-app-name}.herokuapp.com --app my-app-name
```
  
Create the assymetric key pair for signing recovery tokens.
```bash
$ openssl ecparam -name prime256v1 -genkey -noout -out prime256v1-key.pem
$ openssl ec -in prime256v1-key.pem -pubout -out prime256v1-pub.pem
```

Make sure you don't check the secret keys into your source control.  It is
important to keep a backup of every private key and symmetric key ever
used in order to verify and ecrypt tokens being returned to your app as part
a recovery, but it's always a bad idea to keep secrets in source control.
(it's fine to check in the public key if you want)
```bash
$ echo "*.pem" >> .gitignore
```
  
 And now we'll strip the PEM files down to unadorned, single-line base64
for use as config variables.
```bash
$ heroku config:set RECOVERY_PRIVATE_KEY=`perl -p -e 's/\R//g; s/-----[\w\s]+-----//' prime256v1-key.pem` --app my-app-name
$ heroku config:set RECOVERY_PUBLIC_KEY=`perl -p -e 's/\R//g; s/-----[\w\s]+-----//' prime256v1-pub.pem` --app my-app-name
```

You can see your current configuration using:
```bash
$ heroku config --app my-app-name
```

And deploy with Maven
```bash
$ mvn heroku:deploy
```
  
Check that your application deployed successfully with these configuration variables from the command line:
```bash
$ curl https://{your-app-name}.herokuapp.com/.well-known/delegated-account-recovery/configuration
```

You should get a JSON file that lists your public key as the first entry in the
array that is the value of the key `tokensign-pubkeys-secp256r1`

You can try the application itself by running:
  
```bash
$ heroku open --app my-app-name
```

During the closed beta, you will only be able to use the sample applications when logging in to Facebook with a whitehat test account.  [Create and manage test accounts here](https://www.facebook.com/whitehat/accounts).
