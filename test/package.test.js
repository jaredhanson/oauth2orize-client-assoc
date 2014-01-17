/* global describe, it, expect */

var clientAssoc = require('..');

describe('oauth2orize-client-assoc', function() {
  
  it('should export exchanges', function() {
    expect(clientAssoc.exchange).to.be.an('object');
    expect(clientAssoc.exchange.clientAssociation).to.be.a('function');
  });
  
});
