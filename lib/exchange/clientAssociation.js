/**
 * Module dependencies.
 */
var jws = require('jws')
  , utils = require('../utils')
  , TokenError = require('../errors/tokenerror');


/**
 * Exchanges a software statement for a client credential.
 *
 * This exchange is used to obtain a client credential by presenting a software
 * statement.  In contrast to most other exchanges, this exchange functions as a
 * client registration (aka association) mechanism, rather than as an authorization
 * mechanism.
 *
 * In effect, the software statement acts as a "pre-canned" set of registration
 * parameters that is signed by an issuing organization.  This signature allows
 * additional administrative policies to be crafted in which software can be
 * automatically approved if the statement has been signed by a trusted
 * organization.  Apart the signature, a software statement offers no additional
 * functionality when compared to other dynamic registration protocols.
 *
 * It is important to note that a software statement is distributed with
 * applications, and is thus not a secret and not suitable for use as an
 * authentication mechanism.  It's use should be restricted to certain
 * authorization decisions, with the caveat that it should be treated as
 * self-asserted, since there is no way to prove a client is the software it
 * asserts to be.
 *
 * For purposes of authorizing a client registration, an initial access token
 * should be issued by the security domain into which the client needs to be
 * registered.  The issuing of such token is out of scope of this package and
 * protocol.
 *
 * References:
 *  - [OAuth Client Association](http://tools.ietf.org/html/draft-hunt-oauth-client-association-00)
 *  - [OAuth 2.0 Software Statement](http://tools.ietf.org/html/draft-hunt-oauth-software-statement-00)
 *
 * @param {Object} options
 * @param {Function} issue
 * @return {Function}
 * @api public
 */
module.exports = function(options, keying, issue) {
  if (typeof options == 'function') {
    issue = keying;
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  if (!keying) { throw new TypeError('clientAssociation exchange requires a keying callback'); }
  if (!issue) { throw new TypeError('clientAssociation exchange requires an issue callback'); }
  
  var userProperty = options.userProperty || 'user';
  
  return function client_assoc(req, res, next) {
    if (!req.body) { return next(new Error('OAuth2orize requires body parsing. Did you forget app.use(express.bodyParser())?')); }
    
    // The 'user' property of `req` holds the authenticated user.  In the case
    // of the token endpoint, the property will contain the OAuth 2.0 client.
    //
    // NOTE: Draft 00 of the specification states that the software statement
    //       should be contained in an "assertion" parameter, but shows an
    //       example where it is contained in a "software_statement" parameter.
    //       To be lenient, this implementation accepts both.
    //
    //       http://tools.ietf.org/html/draft-hunt-oauth-client-association-00#section-3.2.1
    var client = req[userProperty]
      , assertion = req.body.software_statement || req.body.assertion;
    
    if (!assertion) { return next(new TokenError('Missing required parameter: assertion', 'invalid_request')); }
    
    // NOTE: The JWT specification states that the "typ" header is optional and
    //       that claims are encoded as a JSON object.  The underlying `jws`
    //       package requires that the `json` option be set in order to parse
    //       claims from JWTs that don't set the "typ" header to "JWT".
    //
    //       http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-15#section-5.1
    var token = jws.decode(assertion, { json: true });
    //console.log(token);
    if (!token) {
      return next(new TokenError('Failed to decode software statement', 'invalid_statement', null, 400));
    }
    
    var header = token.header
      , payload = token.payload;
    
    // Validate the software statement.
    //
    // Note that the following requirements have been relaxed.
    //
    //   1. The "sub" claim is not required.  Since this corresponds to the
    //      "software_id" claim, it is redundant information.
    //   2. The "aud" claim is not required.  The specification defines a
    //      "generic" audience, which is effectively equal to not defining an
    //      audience.  Furthermore, since this is not an authentication
    //      assertion, the security properties of the "aud" claim are not
    //      critical.
    //   3. The "exp" claim is not required.  Since the software statement is
    //      packaged with a software distribution, it may exist in the wild for
    //      an indefinate amount of time.  Therefore, "exp" claims are likely to
    //      to be specified as far future dates, reducing the importance of any
    //      limited time window.
    //
    // Applications are free to tighten these checks, by performing them in
    // the `issue` callback, if application requirements mandate that stronger
    // requirements be guaranteed.
    //
    // http://tools.ietf.org/html/draft-hunt-oauth-software-statement-00#section-2.3
    
    if (!payload.software_id) { return next(new TokenError('Missing required claim: software_id', 'invalid_statement', null, 400)); }
    if (!payload.iss) { return next(new TokenError('Missing required claim: iss', 'invalid_statement', null, 400)); }
    
    function doKeyingStep() {
      
      function keyed(err, key) {
        if (err) { return next(err); }
        if (!key) { return next(new TokenError('Unable to verify software statement', 'unapproved_software', null, 403)); }
        
        var ok = jws.verify(assertion, key);
        if (!ok) { return next(new TokenError('Invalid signature on software statement', 'invalid_statement', null, 403)); }
        doIssueStep();
      }
      
      try {
        // NOTE: The JWT specification allows for the "iss" claim to be
        //       replicated in the header.
        //
        //       http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-15#section-5.3
        
        keying(payload.iss || header.iss, keyed);
      } catch (ex) {
        return next(ex);
      }
    }
    
    function doIssueStep() {
      
      function issued(err, clientID, clientToken, params) {
        if (err) { return next(err); }
        if (!clientID) { return next(new TokenError('Refused software statement', 'unapproved_software', null, 403)); }
        if (!clientToken) { return next(new TokenError('Refused software statement', 'unapproved_software', null, 403)); }
        
        // NOTE: This implementation defaults the token type to "Basic", as
        //       opposed to "Bearer", which is common with most other exchanges.
        //       Since the result of association is a unique client ID assigned
        //       to a single software installation, a password and refresh token
        //       are effectively equivalent.  Therefore there is little benefit
        //       in issuing both a bearer token and refresh token, and forcing
        //       the complication of credential rotation upon the client.
        //       Applications can override this default by supplying a value for
        //       `token_type`, along with any additional parameters, in params.
        var tok = {};
        tok.client_id = clientID;
        tok.client_token = clientToken;
        if (params) { utils.merge(tok, params); }
        tok.token_type = tok.token_type || 'Basic';
        
        var json = JSON.stringify(tok);
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Pragma', 'no-cache');
        res.end(json);
      }
    
      try {
        var arity = issue.length;
        if (arity == 4) {
          issue(client, payload, req.body, issued);
        } else {
          issue(client, payload, issued);
        }
      } catch (ex) {
        return next(ex);
      }
    }
    
    doKeyingStep();
  };
};
