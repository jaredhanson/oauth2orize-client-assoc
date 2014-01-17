var chai = require('chai')
  , clientAssociation = require('../../lib/exchange/clientAssociation');


describe('exchange.clientAssociation', function() {
  
  it('should be named client_assoc', function() {
    expect(clientAssociation().name).to.equal('client_assoc');
  });
  
});
