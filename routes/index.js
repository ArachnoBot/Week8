require('dotenv').config()
const express = require('express');
const bcrypt = require("bcrypt")
const passport = require("passport")
const router = express.Router();
const mongoose = require("mongoose")

const jwt = require('jsonwebtoken')
const JwtStrategy = require('passport-jwt').Strategy, ExtractJwt = require('passport-jwt').ExtractJwt;
let opts = {}
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = process.env.SECRET;
passport.use(new JwtStrategy(opts, function(jwt_payload, done) {
  try {
    Users.findOne({email: jwt_payload.email})
    .then((user) => {
      if (user) {
          return done(null, user);
      } else {
          return done(null, false);
      }
    });
  }
  catch(err) {
    return done(err, false);
  }
}));

mongoose.connect("mongodb://127.0.0.1:27017/testdb")
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'))

const userSchema = mongoose.Schema({
  email: String,
  password: String
})

const Users = mongoose.model("Users", userSchema)


router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.post("/api/user/register/", async (req, res) => {
  try {
    const existingUsers = await Users.find()
    const found = existingUsers.find((user) => user.email == req.body.email);

    if (found) {
      return res.status(403).send({
        "email":"Email already in use."
      })
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    newUser = {
        id: Date.now().toString(),
        email: req.body.email,
        password: hashedPassword
    }
    Users.create(newUser)
    res.send(newUser)
  } catch {
      res.send("shit's fucked")
  }
})

router.post("/api/user/login", async (req, res) => {
  try {
    const existingUsers = await Users.find()
    const found = existingUsers.find((user) => user.email == req.body.email);
    const match = await bcrypt.compare(req.body.password, found.password)

    if (!found) {
      return res.send("user not found")
    } else if (match == false) {
      return res.send("wrong password")
    }

    const token = jwt.sign({email: req.body.email}, process.env.SECRET)
    res.send({
      "success": true,
      "token": token
    })

  } catch {
      res.send("shit's fucked")
  }
})

router.get("/api/private", passport.authenticate('jwt', {session: false}), (req, res) => {
  res.send({
    email:req.user.email
  })
})

module.exports = router;
