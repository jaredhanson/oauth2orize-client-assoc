#!/usr/bin/env node

var jws = require('jws')
  , fs = require('fs');


var payload = {
  iss: 'http://www.example.com/',
  software_id: '1234'
};

var data = jws.sign({
  header: { alg: 'rs256' },
  payload: payload,
  privateKey: fs.readFileSync('../keys/rsa/private-key.pem')
});

console.log(data);
