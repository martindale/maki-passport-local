var assert = require('assert');

var PassportLocal = require('../');

describe('PassportLocal', function() {
  
  it('should expose a constructor', function() {
    assert(typeof PassportLocal, 'function');
  });
  
  it('should correctly instantiate without parameters', function() {
    var passport = new PassportLocal();
  });
  
  it('should correctly instantiate with parameters', function() {
    var passport = new PassportLocal({
      resource: 'Person'
    });
  });
  
});
