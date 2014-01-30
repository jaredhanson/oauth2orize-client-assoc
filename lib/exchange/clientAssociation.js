/**
 * Module dependencies.
 */
var jws = require('jws')
  , utils = require('../utils')
  , TokenError = require('../errors/tokenerror');


/**
 * Exchanges a software statement for a client credential.
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
    var client = req[userProperty]
      , assertion = req.body.software_statement;
    
    var token = jws.decode(assertion, { json: true });
    //console.log(token);
    if (!token) {
      return next(new TokenError('Failed to decode software statement', 'invalid_statement', null, 400));
    }
    
    var header = token.header
      , payload = token.payload;
    
    function doKeyingStep() {
      
      function keyed(err, key) {
        if (err) { return next(err); }
        if (!key) { return next(new TokenError('Unable to verify software statement', 'unapproved_software', null, 403)); }
        
        var ok = jws.verify(assertion, key);
        if (!ok) { return next(new TokenError('Invalid signature on software statement', 'invalid_statement', null, 403)); }
        doIssueStep();
      }
      
      try {
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
        issue(client, payload, issued);
      } catch (ex) {
        console.log(ex.stack);
        return next(ex);
      }
    }
    
    doKeyingStep();
  };
};
