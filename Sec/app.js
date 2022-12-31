
//const bcrypt = require('bcrypt');
//const saltRounds = 10;
/*
Passport local mongoose
*/
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');



const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});
 

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

//Code below Also used for making cookies
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const secret ="Thisisourlittlesecret.";
//This line only encrypts passwords however i commented it out because i decided to use hashing on users passwords 
//userScema.plugin(encrypt,{secret:secret,encryptedFields:['password']});


//mongoose.plugin.Schema(secret,plugin);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
passport.use(new GoogleStrategy({
  clientID: "1092251346773-mlu1qds67blcf6n4lhnnf3sm8r9291ou.apps.googleusercontent.com",
  clientSecret: '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',
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL:'https://www.googleapis.com/oauth2/v3/userinfo'
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile);

  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));





app.get("/",function(req,res){
   res.render("home.ejs");   
 
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
); 

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

    app.get("/login",function(req,res){
       res.render("login.ejs");
    })
    
    app.get("/register",function(req,res){
      res.render("register.ejs");
    })
    app.get("/secrets", function(req, res){
      User.find({"secret": {$ne: null}}, function(err, foundUsers){
        if (err){
          console.log(err);
        } else {
          if (foundUsers) {
            res.render("secrets", {usersWithSecrets: foundUsers});
          }
        }
      });
    });
    

    app.get("/submit", function(req, res){
      if (req.isAuthenticated()){
        res.render("submit");
      } else {
        res.redirect("/login");
      }
    });


    app.post("/submit", function(req, res){
      const submittedSecret = req.body.secret;
    
    //Once the user is authenticated and their session gets saved, their user details are saved to req.user.
      // console.log(req.user.id);
    
      User.findById(req.user.id, function(err, foundUser){
        if (err) {
          console.log(err);
        } else {
          if (foundUser) {
            foundUser.secret = submittedSecret;
            foundUser.save(function(){
              res.redirect("/secrets");
            });
          }
        }
      });
    });


//1092251346773-mlu1qds67blcf6n4lhnnf3sm8r9291ou.apps.googleusercontent.com
//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

app.get('/logout', function(req, res, next) { //Target the logout route

  //https://stackoverflow.com/questions/72336177/error-reqlogout-requires-a-callback-function

  req.logout(function(err) { //deauthenticate the user and end the user session

    if (err) { return next(err); }

    res.redirect('/'); //redirect the user to the root route (home page)

  });

});

  app.post('/register', function (req, res) {
/*

  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    // Store hash in your password DB.
    const newUser = new  User({
      email:req.body.username,
      //I commented out an example of using md5 to store passwords and hashing without salting 
      //password:md5(req.body.password)
      password:hash
    });
    
  newUser.save(function (err){
    if(!err){
    console.log("Succesfully registered");
    res.render("secrets.ejs");
    
    }
    else{
        console.log("error while registering new user ");
    }
    
      })

});

*/

User.register({username: req.body.username}, req.body.password, function(err, user){
  if (err) {
    console.log(err);
    res.redirect("/register");
  } else {
    passport.authenticate("local")(req, res, function(){
      res.redirect("/secrets");
    });
  }
});

  
});
    
app.post('/login',function(req,res){

/*
  const username = req.body.username;
const password = (req.body.password);

User.findOne({email:username},function(err,foundUSer){

    if(err){
      console.log(err);
    }
    else{
      if(foundUSer){
        bcrypt.compare(password,foundUSer.password,function(err,result){
if(result===true){
  res.render("secrets.ejs");
  
}
        });

       }
//passport passport-local passport-local-mongoose express-session
    }
  
      
  })
  */
 
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });


})

let port =process.env.PORT;
if(port==null||port==""){
  port=3000;
}
app.listen(port,function(req,res){
    console.log("Server Started Sucessfully")
});




/*if(!err){
    console.log(err);
   
    if(foundUSer){
        if(foundUSer.password===password){
            

            bcrypt.compare(req.body.password, foundUSer.password, function(err, result) {
              // result == true
              if(result===true){
res.render("secrets.ejs");
              }
              else{
                res.send("Invalid password")
              }

          });

          }
          else{
            res.send("Incorrect password or email ");
        } 
    }
    else{
        res.send("Incorrect password or email ");
    } 
*/