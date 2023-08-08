//jshint esversion:6
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

mongoose.connect("mongodb://127.0.0.1:27017/test", { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.set('debug', true);


const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (user, done) {
  done(null, user);
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
  function (accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ googleId: profile.id, username: profile.displayName }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/secrets");
  });

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", async function(req, res) {
  try {
    const foundUsers = await User.find({ "secret": { $ne: null } });

    if (foundUsers.length === 0) {
      console.log("No users with secrets found!");
      return res.status(404).send("No users with secrets found!");
    }

    res.render("secrets", { usersWithSecrets: foundUsers });
  } catch (err) {
    console.log("Error occurred while fetching secrets:", err);
    res.status(500).send("Error occurred while fetching secrets.");
  }
});



function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  } else {
    res.redirect("/login"); 
  }
}

app.get("/submit", ensureAuthenticated, function (req, res) {
  res.render("submit");
});


app.post("/submit", async function (req, res) {
  try {
    if (req.isAuthenticated()) {
      const newSecret = req.body.secret;
      const userID = req.user._id; 

      const foundUser = await User.findById(userID);

      if (!foundUser) {
        console.log("User not found!");
        return res.status(404).send("User not found!");
      }

      foundUser.secret = newSecret;
      await foundUser.save();

      res.redirect("/secrets");
    } else {
      res.redirect("/auth/google"); 
    }
  } catch (err) {
    console.log("Error occurred while saving the secret:", err);
    res.status(500).send("Error occurred while saving the secret.");
  }
});


app.get("/logout", function(req, res){
  req.logout(function(err) {
    if (err) {
      console.log(err);
      res.status(500).send("Error occurred during logout.");
    } else {
      res.redirect("/");
    }
  });
});

app.post("/register", function (req, res) {
  User.register({ username: req.body.username }, req.body.password, function (err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(3000, function () {
  console.log("Server started on port 3000.");
});
