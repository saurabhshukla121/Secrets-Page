// Cookies and sessions
require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require('mongoose-findorcreate')

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: 'secret key',
    resave: false,
    saveUninitialized: false,
  }));

  app.use(passport.initialize());
  app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/users");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: [String]
});

userSchema.plugin(passportLocalMongoose);  // hash salts password and adds user
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());  // Simplified Passport/Passport-Local Configuration

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });


passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/login/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/login/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) =>{
 res.render("home");
});

app.route("/login")
.get((req, res) =>{
    res.render("login");
   })
.post((req,res) =>{
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    
    req.login(user,function(err){
        if(err){
            console.log(err);
        } else{
          passport.authenticate("local")(req, res, function(){
              res.redirect("/secrets");
          });  
        }
    });
});   

app.route("/register")
.get((req, res) => {
    res.render("register");
   })
   
.post((req, res) => {
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");          // instead of render.which means they haven't logged out they can directly view the secrets page
            });
        }
    });
});   

app.get("/login/google",
   passport.authenticate('google', { scope: ['profile'] })
   );

app.get("/login/google/secrets",
  passport.authenticate('google', { failureRedirect: '/login', failureMessage: true }),
  (req, res) =>{
    res.redirect('/secrets');
  });
   
app.get("/login/facebook",
  passport.authenticate('facebook'));

app.get("/login/facebook/secrets",
  passport.authenticate('facebook', { failureRedirect: '/login', failureMessage: true }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/secrets", (req, res) =>{
    User.find({"secret": {$ne: null}}, (err,foundUsers) =>{
        if(err){
            console.log(err);
        }
        else{
            if(foundUsers){
                res.render("secrets",{allSecrets: foundUsers})
            }
        }
    })
   });

app.route("/submit")
.get((req,res) =>{
    if(req.isAuthenticated()){
        res.render("submit");
    } else{
        res.redirect("/login");
    }
})

.post((req,res) =>{
    const newSecret = req.body.secret;

    User.findById(req.user.id, (err,foundUser) =>{
        if(err){
            console.log(err);
        }
        else{
            if(foundUser){
                foundUser.secret.push(newSecret);
                foundUser.save(() =>{
                    res.redirect("/secrets");
                })
            }
            else res.redirect("/login");
        }
    })
})

app.get("/logout", (req, res) =>{
    req.logout();
    res.redirect("/");
   });   


app.listen(3000, function(){
 console.log("Server online at port 3000");
});
