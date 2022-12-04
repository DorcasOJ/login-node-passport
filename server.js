const express = require("express");
const session = require("express-session");
const hbs = require("express-handlebars");
const mongoose = require("mongoose");
const passport = require("passport");
const bcrypt = require("bcrypt");
const localStrategy = require("passport-local").Strategy;
const dotenv = require("dotenv");
const path = require("path");

dotenv.config();
// { path: path.resolve(__dirname, './.env') }
const app = express();

mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("DB connected");
  })
  .catch((err) => console.log(err));

// const db = mongoose.connection;
// db.once("open", () => {});
// db.on("error", (err) => {
//   console.log("connectionerror");
// });

// model
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
});

const User = mongoose.model("User", userSchema);

// Middleware
app.engine("hbs", hbs.engine({ extname: "hbs" }));
app.set("view engine", "hbs");
app.use(express.static("./public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Passport.js
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(
  new localStrategy(function (username, passport, done) {
    User.findOne({ username: username }, function (err, user) {
      if (err) return done(err);
      if (!user) return done(null, false, { message: "Incorrect username" });

      bcrypt.compare(passport, user.password, function (err, res) {
        if (err) return done(err);
        if (res === false)
          return done(err, false, { message: "Incorrect password" });
        return done(null, user);
      });
    });
  })
);

async function hashPassword(password) {
  // const salt = await bcrypt.genSalt(10)
  return await bcrypt.hash(password, await bcrypt.genSalt(10));
}

async function comparePassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

function isLoggedOut(req, res, next) {
  if (!req.isAuthenticated()) return next();
  res.redirect("/");
}

// Routes
app.get("/", isLoggedIn, (req, res) => {
  res.render("index", { title: "Home" });
});

app.get("/about", (req, res) => {
  res.render("index", { title: "About" });
});

app.get("/signup", (req, res) => {
  res.render("register");
});

app.post("/signup", isLoggedIn, async (req, res) => {
  if (!req.body)
    return res.status(404).send({ message: "Content cannot be empty" });

    console.log(req.body)
  // const hashedPassword = await hashPassword(req.password);
  // new user
//   const newUser = new User({
//     username: req.username,
//     email: req.email,
//     password: await hashPassword(req.password),
//   });
//    try {
//         const savedUser = await newUser.save()
//         const {password, ...others} = savedUser
//         res.status(200).send(others)
//     } catch (err) {
//         res.status(500).send({ message: "An error occured while creating user" })
//     }
});

app.get("/login", isLoggedOut, (req, res) => {
  const response = {
    title: "Login",
    error: req.query.error,
  };
  res.render("login", response);
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login?error=true",
  })
);

app.get("/logout", function (req, res) {
  req.logout();
  res.redirect("/");
});

// Setting up admin user
app.get("/setup", async (req, res, next) => {
  const exists = await User.exists({ username: "admin" });
  if (exists) {
    res.redirect("/login");
    return;
  }

  bcrypt.genSalt(10, function (err, salt) {
    if (err) return next(err);
    bcrypt.hash(process.env.ADMIN_PASSWORD, salt, function (err, hash) {
      if (err) return next(err);
      const newAdmin = new User({
        username: "admin",
        password: hash,
      });
      newAdmin.save();
      res.redirect("/login");
    });
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`listening on port ${port}`);
});
