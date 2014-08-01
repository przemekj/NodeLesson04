// LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL
require('newrelic');
var express = require('express')
  , expressValidator = require('express-validator');
var routes = require('./routes');
var user = require('./routes/user');
var http = require('http');
var path = require('path');
var mongoose = require('mongoose');
var nodemailer = require('nodemailer');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var bcrypt = require('bcrypt-nodejs');
var async = require('async');
var crypto = require('crypto');
var flash = require('express-flash');
var validator = require('validator');
var validate = require('mongoose-validator').validate;


passport.use(new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
  function(req, email, password, done) {
    User.findOne({ email: email.toLowerCase() }, function (err, user) {
      if (err) return done(err);
      if (!user) return done(null, false, { message: 'Incorrect username.' });
      user.comparePassword(password, function(err, isMatch) {
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect username.' });
        }
      });
    });
  }
));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


var userSchema = new mongoose.Schema({
  username: { type: String, required:true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, validate: validate('len', 3, 80) },
  vocabulary: { type: String, required: false, validate: validate({message: "String should be between 1 and 30000 characters"}, 'len', 1, 60000) },
  //password: { type: String, required: true},
  //vocabulary: { type: String, required: false},
  isRandom: { type: Boolean, required: false },
  isTitleModified: { type: Boolean, required: false },
  delay: { type: Number, required: false, max: 7000, min: 100 },
  firstLineColor: { type: String, required: false },
  secondLineColor: { type: String, required: false },
  backgroundColor: { type: String, required: false },
  firstLineTextSize: { type: Number, required: false, max: 10, min: 1 },
  secondLineTextSize: { type: Number, required: false, max: 10, min: 1 },
  signupDate: { type: Date, default: Date.now },
  lastLoginDate: { type: Date, required: false },
  ipAddress: { type: String, required: false },
  resetPasswordToken: String,
  resetPasswordExpires: Date
});

userSchema.pre('save', function(next) {
  var user = this;
  var SALT_FACTOR = 5;

  if (!user.isModified('password')) return next();

  bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
    if (err) return next(err);

    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) return next(err);
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if(err) return cb(err);
    cb(null, isMatch);
  });
};

var User = mongoose.model('User', userSchema);

mongoose.connect(process.env.MONGOHQ_URL);
// LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL LOCAL
 //mongoose.connect('localhost');
var app = express();

// all environments
app.set('port', process.env.PORT || 3000);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.use(express.favicon(path.join(__dirname, '/public/images/icons/favicon.ico')));
app.use(express.logger('dev'));
app.use(express.json());
app.use(express.urlencoded());
app.use(expressValidator());
app.use(express.methodOverride());
app.use(express.cookieParser());
app.use(express.session({ 
	secret: process.env.SECRET,  // LOCAL LOCAL LOCAL LOCAL
	cookie : {
    maxAge : 7*24*60*60*1000 // 7 * 24 * 60 * 60 * 1000;
      }
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());
app.use(app.router);
app.use(express.static(path.join(__dirname, 'public')));

if ('development' == app.get('env')) {
  app.use(express.errorHandler());
}

// app.get('/', routes.index);
// app.get('/users', user.list);

app.get('/', function(req, res){
  res.render('index', {
    user: req.user,
    start_page: 'start_page',
  });
});

app.get('/edit', function(req, res){
  if (!req.user) {
      req.flash('info', 'Sign in to continue');
      return res.redirect('/');
  }
  else {
  res.render('edit', {
    user: req.user,
  });
  }
});

app.get('/login', function(req, res) {
  if (req.user) {    
      return res.redirect('/');
  }
  else {
	  res.render('login', {
		user: req.user,
	  });
	}  
});

app.get('/signup', function(req, res) {
  if (req.user) {    
      return res.redirect('/');
  }
  else {

	  res.render('signup', {
		user: req.user,
	  });
  }
});

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
  req.flash('info', 'You have been logged out successfully');
});

app.get('/faq', function(req, res){
  res.render('faq', {
    user: req.user,
  });
});

app.get('/terms', function(req, res){
  res.render('terms', {
    user: req.user,
  });
});

app.get('/forgot', function(req, res) {
  if (req.user) {    
      return res.redirect('/');
  }
  else {

	  res.render('forgot', {
		user: req.user,
	  });
  }
});

///////// Dynamic routes

app.get('/:preview', function(req, res){

      User.findOne({ username: req.params.preview }, function(err, user) {
        if (!user) {
          req.flash('error', 'Bad request');
          return res.redirect('/');
        }
		
		res.render('preview', {
			vocabulary: user.vocabulary,
			//user: req.user,
			isRandom: user.isRandom,
			isTitleModified: user.isTitleModified,
			delay: user.delay,
			firstLineColor: user.firstLineColor,
			secondLineColor: user.secondLineColor,
			backgroundColor: user.backgroundColor,
			firstLineTextSize: user.firstLineTextSize,
			secondLineTextSize: user.secondLineTextSize
		});
      });
});

/////////

app.get('/reset/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired. You need to request resetting password again.');
      return res.redirect('/forgot');
    }
    res.render('reset', {
      user: req.user
    });
  });
});

app.post('/login', function(req, res, next) {
  passport.authenticate('local', function(err, user, info) {
    if (err) return next(err)
    if (!user) {
	  req.flash('error', 'Wrong username/password');
      return res.redirect('/login')
    }
    req.logIn(user, function(err) {
      if (err) {
		req.flash('error', 'Wrong username/password');
		return next(err);
	  } 	
      //req.flash('success', req.connection.remoteAddress);
	  
	  // Save last Login information
	  user.lastLoginDate = Date.now();

      user.save(function(err) {
       // req.logIn(user, function(err) {
       //   done(err, user);
       // });
	   req.flash('error', Date.now());
      });
	  req.flash('info', 'You are now logged in as ' + user.email);
	  return res.redirect('/edit');
    });
  })(req, res, next);
});

app.post('/', function(req, res, next) {
  passport.authenticate('local', function(err, user, info) {
    if (err) return next(err)
    if (!user) {
	  req.flash('error', 'Wrong username/password');
      return res.redirect('/login')
    }
    req.logIn(user, function(err) {
      if (err) {
		req.flash('error', 'Wrong username/password');
		return next(err);
	  }
	  // Save last Login information
	  user.lastLoginDate = Date.now();

      user.save(function(err) {
       // req.logIn(user, function(err) {
       //   done(err, user);
       // });
	   req.flash('error', Date.now());
      });	  
      req.flash('info', 'You are now logged in as ' + user.email);
	  return res.redirect('/edit');
    });
  })(req, res, next);
});

app.post('/signup', function(req, res) {
  
  function randomValueBase64 (len) {
    return crypto.randomBytes(Math.ceil(len * 3 / 4))
        .toString('base64')   // convert to base64 format
        .slice(0, len)        // return required number of characters
        .replace(/\+/g, '0')  // replace '+' with '0'
        .replace(/\//g, '0'); // replace '/' with '0'
  }
  
  var randomURL = randomValueBase64(6);
  //alert(randomURL);
  //req.flash('success', randomURL);
  
  var user = new User({
      username: randomURL.toLowerCase(),
      email: req.body.email.toLowerCase(),
      password: req.body.password,
	  vocabulary: 'Mentha piperita - Peppermint\r\nSalvia officinalis - Sage\r\nZingiber officinale - Ginger\r\n*Capsicum annuum - Cayenne (this line will be skipped as it begins with a star)\r\nEchinacea purpurea - Purple coneflower\r\n',
	  isRandom: true,
	  isTitleModified: true,
	  delay: 2500,
      firstLineColor: '#616161',
	  secondLineColor: '#9c9c9c',
	  backgroundColor: '#ffffff',
	  firstLineTextSize: 4,
	  secondLineTextSize: 2,
	  ipAddress: req.header('x-forwarded-for') || req.connection.remoteAddress,
	  isActiveUser: true
    });

  user.save(function(err) {
	if (err) {
          res.redirect("/signup");
		  return req.flash('error', 'This email address was already used for registration.');
        }
    req.logIn(user, function(err) {
	  // if (err) {
          // res.render("/");
		  // req.flash('error', 'Got error!');
        // }

	  if (!user) {	    
	    res.redirect('/signup');
		req.flash('error', 'Unknown error. Please refresh the page and try again.');
	  } else {  
	    res.redirect('/edit'); 
		req.flash('success', 'You have successfully registered with email: ' + user.email);
		console.log('*** New account: ' + user.email); 
	  }
    });
  });
});

app.post('/forgot', function(req, res) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ email: req.body.email.toLowerCase() }, function(err, user) {
        if (!user) {
          req.flash('error', 'No account with that email address exists.');
          return res.redirect('/forgot');
        }

        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      var smtpTransport = nodemailer.createTransport('SMTP', {
        service: 'Gmail',
        auth: {
          user: 'blinkerize@gmail.com',
          pass: process.env.EMAIL_PASS
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'passwordreset@demo.com',
        subject: 'Blinkerize.com Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
        done(err, 'done');
      });
    }
  ], function(err) {
    if (err) return next(err);
    res.redirect('/forgot');
  });
});

app.post('/reset/:token', function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error', 'Password reset token is invalid or has expired.');
          return res.redirect('back');
        }

        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        user.save(function(err) {
          req.logIn(user, function(err) {
            done(err, user);
          });
        });
      });
    },
    function(user, done) {
      var smtpTransport = nodemailer.createTransport('SMTP', {
        service: 'Gmail',
        auth: {
          user: 'blinkerize@gmail.com',
          pass: 'blink9!efez'
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'blinkerize@gmail.com',
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('success', 'Success! Your password has been changed.');
        done(err);
      });
    }
  ], function(err) {
    res.redirect('/');
  });
});

app.post('/edit', function(req, res) { 
	 var updateData = {
		 vocabulary: req.body.vocabulary
	   };
	   console.log('** ' + req.user.email + ' has updated his vocabulary'); 

	     
	   req.user.vocabulary = req.body.vocabulary; 

	    if (req.body.is_random_checkbox) {
		  req.user.isRandom = true;
		} 
		else {
		  req.user.isRandom = false;
		}
	    if (req.body.is_title_modified_checkbox) {
		  req.user.isTitleModified = true;
		} 
		else {
		req.user.isTitleModified = false;
		}
	  req.user.delay = req.body.delay_slider;
      req.user.firstLineColor = req.body.first_line_color;
	  req.user.secondLineColor = req.body.second_line_color;
	  req.user.backgroundColor = req.body.back_color;
	  req.user.firstLineTextSize = req.body.first_line_size;
	  req.user.secondLineTextSize = req.body.second_line_size;

	 
  req.user.save(function(err) { 

	  if (err) {
		req.flash('error', err.message);
		res.redirect('/edit');
		//throw err;
		//return next(err);
	  }
	  else {
	     res.redirect('/edit');
	     req.flash('success', 'Vocabulary and settings have been saved');
	  }
	  
  });

});


http.createServer(app).listen(app.get('port'), function(){
  console.log('Express server listening on port ' + app.get('port'));
});