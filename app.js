// Load environment variables

require("dotenv").config();

// 2. Require modules 

const express = require("express");
const path = require("node:path");
const session = require("express-session");
const passport = require("passport");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const LocalStrategy = require("passport-local").Strategy;
const { body, validationResult } = require("express-validator");

// PostgreSQL connection/database setup

const pool = new Pool({
  host: process.env.PG_HOST,
  user: process.env.PG_USER,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: Number(process.env.PG_PORT),
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// Express app init

const app = express();

// Middleware: static files and views setup

app.use(express.static(__dirname + "/public"));
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
// This is a form-based app, so below is not needed:
// app.use(express.json());

// Session Middleware
// NOTE - hardcoding "secure: false" is fine for dev.
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    },
  }),
);

// Passport Middleware setup (after session)

app.use(passport.initialize());
app.use(passport.session());

// Passport LocalStrategy + serialize/deserialize

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username],
      );
      const user = rows[0];

      if (!user) return done(null, false, { message: "Incorrect username." });

      const match = await bcrypt.compare(password, user.password);
      if (!match) return done(null, false, { message: "Incorrect password." });

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }),
);

// -- Serialize / Deserialize

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    done(null, rows[0]);
  } catch (err) {
    done(err);
  }
});

// Routes (get, post)

// -- Sign-up Form
app.get("/sign-up", (req, res) => {
  res.render("sign-up-form", {
    title: "Sign Up",
    errors: [],
  });
});

// -- Sign-up form submission
app.post(
  "/sign-up",
  [
    body("username").notEmpty().withMessage("Username is required."),
    body("password")
      .isLength({ min: 3 })
      .withMessage("Password must be at least 3 characters long."),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).render("sign-up-form", {
        title: "Sign Up",
        errors: errors.array().map((err) => err.msg),
      });
    }

    const { username, password } = req.body;

    try {
      const { rows } = await pool.query(
        "SELECT 1 FROM users WHERE username = $1",
        [username],
      );

      if (rows.length > 0) {
        return res.status(409).render("sign-up-form", {
          title: "Sign Up",
          errors: ["Username already taken."],
        });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      await pool.query(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        [username, hashedPassword],
      );

      // Redirect only on success
      res.redirect("/");
    } catch (err) {
      next(err);
    }
  },
);

// -- Login Form
app.get("/", (req, res) => {
  res.render("index", {
    title: "Login",
    user: req.user,
    errors: [],
  });
});

// -- Log-in Form with Validation
app.post(
  "/log-in",
  [
    body("username").notEmpty().withMessage("Username is required."),
    body("password").notEmpty().withMessage("Password is required."),
  ],
  (req, res, next) => {
    const errors = validationResult(req);

    // Validation errors
    if (!errors.isEmpty()) {
      return res.status(400).render("index", {
        title: "Login",
        user: null,
        errors: errors.array().map((err) => err.msg),
      });
    }

    passport.authenticate("local", (err, user, info) => {
      if (err) return next(err);

      // Auth failure
      if (!user) {
        return res.status(401).render("index", {
          title: "Login",
          user: null,
          errors: [info.message || "Invalid credentials."],
        });
      }

      // Success
      req.logIn(user, (err) => {
        if (err) return next(err);
        return res.redirect("/");
      });
    })(req, res, next);
  },
);

// -- Log-out
app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/"); // Redirect to home after log-out
  });
});

// Error Handling

// -- 404 - Route not found (This should be placed before the general error handler)
app.use((req, res, next) => {
  res.status(404).render("404", {
    title: "404 Not Found",
    error: "Sorry, we couldn't find the page you were looking for.",
  });
});

// -- General error handler for 500 errors (or uncaught errors)
app.use((err, req, res, next) => {
  console.error(err);

  res.status(err.status || 500).render("500", {
    title: "Internal Server Error",
    error:
      process.env.NODE_ENV === "production"
        ? "Something went wrong."
        : err.message,
  });
});

// Start Server

app.listen(3000, (err) => {
  if (err) throw err;
  console.log("App listening on port 3000!");
});

