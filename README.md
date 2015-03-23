maki-passport-local
===================
[![Build Status](https://img.shields.io/travis/martindale/maki-passport-local.svg?branch=master&style=flat-square)](https://travis-ci.org/martindale/maki-passport-local)
[![Coverage Status](https://img.shields.io/coveralls/martindale/maki-passport-local.svg?style=flat-square)](https://coveralls.io/r/martindale/maki-passport-local)

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
