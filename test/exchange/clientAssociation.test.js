var chai = require('chai')
  , clientAssociation = require('../../lib/exchange/clientAssociation');


describe('exchange.clientAssociation', function() {
  
  it('should be named client_assoc', function() {
    expect(clientAssociation(function(){}).name).to.equal('client_assoc');
  });
  
  it('should throw if constructed without a issue callback', function() {
    expect(function() {
      clientAssociation();
    }).to.throw(TypeError, 'clientAssociation exchange requires an issue callback');
  });
  
  
  describe('issuing an access token to new association', function() {
    var response, err;

    function issue(client, code, redirectURI, done) {
      return done(new Error('something is wrong'));
    }

    before(function(done) {
      chai.connect.use(clientAssociation(issue))
        .req(function(req) {
          req.body = { code: 'abc123', redirect_uri: 'http://example.com/oa/callback' };
        })
        .end(function(res) {
          response = res;
          done();
        })
        .dispatch();
    });
    
    it('should respond with headers', function() {
      expect(response.getHeader('Content-Type')).to.equal('application/json');
      expect(response.getHeader('Cache-Control')).to.equal('no-store');
      expect(response.getHeader('Pragma')).to.equal('no-cache');
    });
    
    it('should respond with body', function() {
      expect(response.body).to.equal('{"access_token":"s3cr1t","token_type":"Bearer"}');
    });
  });
  
});
