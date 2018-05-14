/* global
  AccountsTemplates
*/
"use strict";

const Future = Npm.require('fibers/future');
const ldap   = Npm.require('ldap');

Meteor.methods({
  ATCreateUserServer: function(options) {
    if (AccountsTemplates.options.forbidClientAccountCreation) {
      throw new Meteor.Error(403, AccountsTemplates.texts.errors.accountsCreationDisabled);
    }

    // createUser() does more checking.
    check(options, Object);
    var allFieldIds = AccountsTemplates.getFieldIds();

    // Picks-up whitelisted fields for profile
    var profile = options.profile;
    profile = _.pick(profile, allFieldIds);
    profile = _.omit(profile, "username", "email", "password");

    console.log("profile", profile);

    // Validates fields" value
    var signupInfo = _.clone(profile);
    if (options.username) {
      signupInfo.username = options.username;

      if (AccountsTemplates.options.lowercaseUsername) {
        signupInfo.username = signupInfo.username.trim().replace(/\s+/gm, ' ');
        options.profile.name = signupInfo.username;
        signupInfo.username = signupInfo.username.toLowerCase().replace(/\s+/gm, '');
        options.username = signupInfo.username;
      }
    }

    if (options.email) {
      signupInfo.email = options.email;

      if (AccountsTemplates.options.lowercaseUsername) {
        signupInfo.email = signupInfo.email.toLowerCase().replace(/\s+/gm, '');
        options.email = signupInfo.email;
      }
    }

    if (options.password) {
      signupInfo.password = options.password;
    }

    var validationErrors = {};
    var someError = false;

    // Validates fields values
    _.each(AccountsTemplates.getFields(), function(field) {
      var fieldId = field._id;
      var value = signupInfo[fieldId];

      if (fieldId === "password") {
        // Can"t Pick-up password here
        // NOTE: at this stage the password is already encripted,
        //       so there is no way to validate it!!!
        check(value, Object);
        return;
      }


      var validationErr = field.validate(value, "strict");
      if (validationErr) {
        validationErrors[fieldId] = validationErr;
        someError = true;
      }
    });

    if (AccountsTemplates.options.showReCaptcha) {
      var secretKey = null;

      if (AccountsTemplates.options.reCaptcha && AccountsTemplates.options.reCaptcha.secretKey) {
        secretKey = AccountsTemplates.options.reCaptcha.secretKey;
      } else {
        secretKey = Meteor.settings.reCaptcha.secretKey;
      }

      var apiResponse = HTTP.post("https://www.google.com/recaptcha/api/siteverify", {
        params: {
          secret: secretKey,
          response: options.profile.reCaptchaResponse,
          remoteip: this.connection.clientAddress,
        }
      }).data;

      if (!apiResponse.success) {
        throw new Meteor.Error(403, AccountsTemplates.texts.errors.captchaVerification,
          apiResponse['error-codes'] ? apiResponse['error-codes'].join(", ") : "Unknown Error.");
      }
    }

    if (someError) {
      throw new Meteor.Error(403, AccountsTemplates.texts.errors.validationErrors, validationErrors);
    }

    // Possibly removes the profile field
    if (_.isEmpty(options.profile)) {
      delete options.profile;
    }

    if (_.isEmpty(options.password)) {
      delete options.password;
    }

    // Create user. result contains id and token.
    var userId = Accounts.createUser(options);
    // safety belt. createUser is supposed to throw on error. send 500 error
    // instead of sending a verification email with empty userid.
    if (! userId) {
      throw new Error("createUser failed to insert new user");
    }

    // Call postSignUpHook, if any...
    var postSignUpHook = AccountsTemplates.options.postSignUpHook;
    if (postSignUpHook) {
      postSignUpHook(userId, options);
    }

    // Send a email address verification email in case the context permits it
    // and the specific configuration flag was set to true
    if (options.email && AccountsTemplates.options.sendVerificationEmail) {
      Accounts.sendVerificationEmail(userId, options.email);
    }

    return userId;
  },

  ATAuthenticateLdapUserServer: function (options) {

    check(options, Object);

    if (!options.username) return;

    const user     = options.username;
    const password = options.password;
    let userId;



    const userData = logarLdap(user, password);


    if (!userData) return;


    const localUser = Accounts.findUserByUsername(user);

    if (!localUser) {
      // createUser() does more checking.

      // Validates fields" value
      var newUser = {
        username: user,
        email   : userData.mail,
        profile : {
          fullname : userData.sn
        }
      };


      var signupInfo = {};
      if (newUser.username) {
        signupInfo.username = newUser.username;

        if (AccountsTemplates.options.lowercaseUsername) {
          signupInfo.username  = signupInfo.username.trim().replace(/\s+/gm, ' ');
          signupInfo.username  = signupInfo.username.toLowerCase().replace(/\s+/gm, '');
          newUser.username     = signupInfo.username;
        }
      }

      if (newUser.email) {
        signupInfo.email = newUser.email;

        if (AccountsTemplates.options.lowercaseUsername) {
          signupInfo.email = signupInfo.email.toLowerCase().replace(/\s+/gm, '');
          newUser.email    = signupInfo.email;
        }
      }

      // if (options.password) {
      //   signupInfo.password = options.password;
      // }

      var validationErrors = {};
      var someError        = false;

      // Validates fields values
      _.each(AccountsTemplates.getFields(), function (field) {
        var fieldId = field._id;
        var value   = signupInfo[fieldId];

        if (fieldId === "password") {
          // Can"t Pick-up password here
          // NOTE: at this stage the password is already encripted,
          //       so there is no way to validate it!!!
          // check(value, Object);
          return;
        }


        var validationErr = field.validate(value, "strict");
        if (validationErr) {
          validationErrors[fieldId] = validationErr;
          someError                 = true;
        }
      });

      if (AccountsTemplates.options.showReCaptcha) {
        var secretKey = null;

        if (AccountsTemplates.options.reCaptcha && AccountsTemplates.options.reCaptcha.secretKey) {
          secretKey = AccountsTemplates.options.reCaptcha.secretKey;
        } else {
          secretKey = Meteor.settings.reCaptcha.secretKey;
        }

        var apiResponse = HTTP.post("https://www.google.com/recaptcha/api/siteverify", {
          params: {
            secret  : secretKey,
            response: options.profile.reCaptchaResponse,
            remoteip: this.connection.clientAddress,
          }
        }).data;

        if (!apiResponse.success) {
          throw new Meteor.Error(403, AccountsTemplates.texts.errors.captchaVerification,
            apiResponse['error-codes'] ? apiResponse['error-codes'].join(", ") : "Unknown Error.");
        }
      }


      if (someError) {
        throw new Meteor.Error(403, AccountsTemplates.texts.errors.validationErrors, validationErrors);
      }

      // Create user. result contains id and token.
      userId = Accounts.createUser(newUser);

    } else userId = localUser._id;


    // safety belt. createUser is supposed to throw on error. send 500 error
    // instead of sending a verification email with empty userid.
    if (!userId) {
      throw new Error("createUser failed to insert new user");
    }

    this.setUserId(userId);

    // Call postSignUpHook, if any...
    var postSignUpHook = AccountsTemplates.options.postSignUpHook;
    if (postSignUpHook) {
      postSignUpHook(userId, options);
    }

    return userId;
  },

  // Resend a user's verification e-mail
  ATResendVerificationEmail: function (email) {
    check(email, String);

    var user = Meteor.users.findOne({ "emails.address": email });

    // Send the standard error back to the client if no user exist with this e-mail
    if (!user) {
      throw new Meteor.Error(403, "User not found");
    }

    try {
      Accounts.sendVerificationEmail(user._id);
    } catch (error) {
      // Handle error when email already verified
      // https://github.com/dwinston/send-verification-email-bug
      throw new Meteor.Error(403, "Already verified");
    }
  },

});

function logarLdap(user, password) {

  // console.log("passei aqui", process.env.LDAP_search_attributes);

  // const ldap = AccountsTemplates.ldap2();

  const baseDN           = process.env.LDAP_base_dn;
  const host             = process.env.LDAP_host;
  const port             = process.env.LDAP_port;
  const objectClass      = process.env.LDAP_object_class;
  const searchField      = process.env.LDAP_search_field;
  const searchFilter     = user;
  const searchScope      = process.env.LDAP_search_scope;
  // const searchAttributes = ['cn', 'sn', 'mail'];
  const searchAttributes = process.env.LDAP_search_attributes.split(',');
  const timeout          = process.env.LDAP_timeout;
  const connectTimeout   = process.env.LDAP_connect_timeout;
  const idleTimeout      = process.env.LDAP_idle_timeout;
  const tlsOptions       = process.env.LDAP_tls_options;
  const strictDN         = process.env.LDAP_strict_dn;

  //  const searchAttributes = ['*'];


  const client = ldap.createClient({
    url: `${host}:${port}`,
    timeout,
    tlsOptions,
    connectTimeout,
    idleTimeout,
    strictDN
  });

  client.bind(`uid=${user},${baseDN}`, password, (err => {
    console.log("deu merda", err);
    if (err) searchFuture.return(null);
    //todo tratamento de erro (Credentials are not valid)

  }));

  const opts = {
    filter    : `(&(objectclass=${objectClass})(${searchField}=${searchFilter}))`,
    scope     : searchScope,
    attributes: searchAttributes
  };


  // for (let i = 0; i < 800000; i++) {
  //
  // }


  var searchFuture = new Future();
  var result       = false;

  client.search(baseDN, opts, (err, res) => {
    let userData;
    // console.log('status d: ', new Date().getTime());
    console.log("deu merda 2", err);

    res.on('searchEntry', function (entry) {
      // console.log('entry: ' + JSON.stringify(entry.object));
      userData = entry.object;
    });
    res.on('searchReference', function (referral) {
      // console.log('referral: ' + referral.uris.join());
    });
    res.on('error', function (err) {
      console.error('error 2365: ' + err.message);
      // throw new Meteor.Error(403, err.message);
      // cb (err.message);
    });
    res.on('end', function (result) {
      // console.log('status: ' + result);
      // console.log('status 2: ' + result.status);
      // console.log('status CS: ', new Date().getTime());
      searchFuture.return(userData);
    });
  });

  result = searchFuture.wait();

  return result;


}
