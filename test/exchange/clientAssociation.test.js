var chai = require('chai')
  , fs = require('fs')
  , clientAssociation = require('../../lib/exchange/clientAssociation');


describe('exchange.clientAssociation', function() {
  
  it('should be named client_assoc', function() {
    expect(clientAssociation(function(){}, function(){}).name).to.equal('client_assoc');
  });
  
  it('should throw if constructed without a keying callback', function() {
    expect(function() {
      clientAssociation();
    }).to.throw(TypeError, 'clientAssociation exchange requires a keying callback');
  });
  
  it('should throw if constructed without an issue callback', function() {
    expect(function() {
      clientAssociation(function(){});
    }).to.throw(TypeError, 'clientAssociation exchange requires an issue callback');
  });
  
  
  describe('issuing an access token for statement containing issuer and software id with type in JWT header', function() {
    var response, err;

    function keying(issuer, done) {
      expect(issuer).to.equal('http://www.example.com/');
      
      return fs.readFile(__dirname + '/../keys/rsa/cert.pem', 'utf8', done);
    }

    function issue(client, statement, done) {
      expect(client).to.be.undefined;
      expect(statement.iss).to.equal('http://www.example.com/');
      expect(statement.software_id).to.equal('1234');
      
      return done(null, 'C123', 'shh-its-secret');
    }

    before(function(done) {
      chai.connect.use(clientAssociation(keying, issue))
        .req(function(req) {
          req.body = {};
          req.body.grant_type = 'urn:ietf:params:oauth:grant-type:client-assoc';
          // header = { alg: 'rs256' }
          // body = { iss: 'http://www.example.com/', software_id: '1234' }
          req.body.software_statement = 'eyJhbGciOiJyczI1NiJ9.eyJpc3MiOiJodHRwOi8vd3d3LmV4YW1wbGUuY29tLyIsInNvZnR3YXJlX2lkIjoiMTIzNCJ9.M-ZPqGU2J7XSkstGfyRc9Nbt9wamlohDQbIbfX5zVlGQjojPZWfFywPdjr64FQGzxC5bqwBXX8VyvKcXbuFlC-2AMJIu8nxpzV-_mJ6ewynGVQQ8NRCsa9pnqLBeXv22XQzF9XOn1uOAUfQsNafnQeuTkZraUyvhrJ9znNdWfwM';
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
      expect(response.body).to.equal('{"client_id":"C123","client_token":"shh-its-secret","token_type":"Basic"}');
    });
  });
  
});
