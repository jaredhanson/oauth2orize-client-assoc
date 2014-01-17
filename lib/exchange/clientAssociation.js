var jws = require('jws')
  , TokenError = require('../errors/tokenerror');


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
      , sw = req.body.software_statement;
    
    var token = jws.decode(sw, { json: true });
    console.log(token);
    // TODO: Check if token is null
    
    var header = token.header
      , payload = token.payload;
    
    function doKeyingStep() {
      console.log('DO KEY STEP');
      
      function keyed(err, key) {
        if (err) { return next(err); }
        if (!key) { return next(new TokenError('Refused software statement', 'unapproved_software', null, 403)); }
        
        var ok = jws.verify(sw, key);
        if (!ok) { return next(new TokenError('Invalid signature on software statement', 'invalid_statement', null, 403)); }
        doIssueStep();
      }
      
      try {
        keying(payload.iss || header.iss, keyed);
      } catch (ex) {
        console.log(ex);
        return next(ex);
      }
    }
    
    function doIssueStep() {
      console.log('DO ISSUE STEP');
      
      function issued(err, accessToken, refreshToken, params) {
        console.log('ISSUED');
      }
    
      console.log(issue)
    
      try {
        issue(client, sw, issued);
      } catch (ex) {
        console.log(ex.stack);
        return next(ex);
      }
    }
    
    doKeyingStep();
  };
};
