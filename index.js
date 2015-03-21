var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var passportLocalMongoose = require('passport-local-mongoose');

// session handling
var redis = require('redis');
var connectRedis = require('connect-redis');
var session = require('express-session');
var cookieParser = require('cookie-parser');

var flash = require('connect-flash');
var async = require('async');

function PassportLocal( config ) {
  if (!config) var config = {};
  
  var self = this;
  self.config = config;
  
  if (!config.fields) config.fields = {};
  
  config.fields.username = config.fields.username || 'username';

  var resources = {};
  if (self.config.resource) {
    resources[ self.config.resource ] = {
      plugin: passportLocalMongoose
    }
  }
  
  self.extends = {
    resources: resources,
    services: {
      http: {
        middleware: function(req, res, next) {
          var stack = [];
          if (!req.session.hash) {
            stack.push(function(done) {
              req.session.hash = require('crypto').createHash('sha256').update( req.session.id ).digest('hex');
              req.session.save( done );
            });
          }
          async.series( stack , function(err, results) {
            // set a user context (from passport)
            res.locals.user = req.user;
            res.locals.session = req.session;
            return next();
          });
        },
        setup: function( maki ) {
          maki.passport = passport;
          
          // TODO: p2p datastore
          maki.redis = redis.createClient( maki.config.redis.port , maki.config.redis.host );
          var RedisStore = connectRedis( session );
          maki.app.use( cookieParser( maki.config.sessions.secret ) )
          
          maki.app.use( session({
            name: maki.config.service.namespace + '.id',
            store: new RedisStore({ client: maki.redis }),
            secret: maki.config.sessions.secret,
            cookie: {
              //secure: true,
              maxAge: 30 * 24 * 60 * 60 * 1000
            },
            rolling: true
          }));
  
          /* Configure the registration and login system */
          maki.app.use( maki.passport.initialize() );
          maki.app.use( maki.passport.session() );
          maki.app.use( flash() );
          maki.app.use(function(req, res, next) {
            res.format({
              html: function() {
                res.locals.messages = {
                  info: req.flash('info'),
                  warning: req.flash('warning'),
                  error: req.flash('error'),
                  success: req.flash('success'),
                };
                next();
              },
              default: function() {
                next();
              }
            });

          });
  
          maki.passport.use( new LocalStrategy( verifyUser ) );
          function verifyUser( username , password , done ) {
            var Resource = maki.resources[ self.config.resource ];
            Resource.query({ username: username }, function(err, users) {
              if (err) return done(err);
              var user = users[0];
              
              if (!user) return done( null , false , { message: 'Invalid login.' } );
  
              user.authenticate( password , function(err) {
                if (err) return done( null , false , { message: 'Invalid login.' } );
                return done( null , user );
              });
            });
          }
          
          var plugin = self;
          maki.resources[ self.config.resource ].pre('create', function( next , done ) {
            var self = this;

            if (self[ plugin.config.fields.username ] && self.password) {
              var user = JSON.parse( JSON.stringify( self ) );
              delete user.password;
              return maki.resources[ plugin.config.resource ].Model.register( user , self.password , done );
            }
            
            next();

          });
          
          maki.app.get('/sessions', function(req, res, next) {
            res.format({
              json: function() {
                var tmp = JSON.parse( JSON.stringify( req.session ) );
                tmp.id = tmp.hash;
                delete tmp.hash;
                return res.send([ tmp ]);
              },
              html: function() {
                res.render('login');
              }
            });
          });
          maki.app.post('/sessions', maki.passport.authenticate('local') , function(req, res, next) {
            res.format({
              json: function() {
                res.redirect(303, '/sessions/' + req.session.hash );
              },
              html: function() {
                req.flash('success', 'logged in');
                return res.redirect('/');
              }
            });
          });
          maki.app.get('/sessions/:sessionID', function(req, res, next) {
            if (req.session.hash != req.param('sessionID')) return next();
            
            // TODO: HTML version...
            var tmp = JSON.parse( JSON.stringify( req.session ) );
            tmp.id = tmp.hash;
            delete tmp.hash;
            return res.send( tmp );
          });
          maki.app.delete('/sessions/:sessionID', function(req, res, next) {
            
            req.logout();
            
            res.format({
              json: function() {
                res.status(204).end();
              },
              html: function() {
                req.flash('success', 'logged out');
                res.redirect('/');
              }
            });

          });
          
          maki.passport.serializeUser(function(user, done) {
            done( null , user._id );
          });
          maki.passport.deserializeUser(function(id, done) {
            maki.resources[ self.config.resource ].query({ _id: id }, function(err, users) {
              done( err , users[0] );
            });
          });
          
        }
      }
    }
  };
  
  return self;
}

module.exports = PassportLocal;
