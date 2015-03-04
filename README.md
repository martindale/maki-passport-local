# maki-passport-local
local user logins for maki applications

## Quick Start

```javascript

var Maki = require('maki');
var maki = new Maki();

var Passport = require('maki-passport-local');
var passport = new Passport({ resource: 'Person' });

maki.define('Person', {
  attributes: {
    username: String
  }
});

maki.use( passport );
maki.start();

```
