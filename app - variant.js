require("dotenv").config();
const bcrypt = require("bcryptjs");
const path = require("node:path");
const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const { body, validationResult } = require("express-validator");

// PostgreSQL connection
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

const app = express();

// Static files and views setup
app.use(express.static(__dirname + "/public"));
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Session Middleware
// The code below was not working as intended. Error message were not working on the first button click, only on the second button click, indicating latency/lag. Also, connect-pg-simple writes asynchronously, and redirects should be immediate.
// app.use(
//   session({
//     store: new pgSession({
//       pool, // PostgreSQL pool
//       tableName: "session",
//       createTableIfMissing: true, // Ensure session table is created
//     }),
//     secret: process.env.SESSION_SECRET,
//     resave: false,
//     saveUninitialized: false,
//     cookie: {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production", // false in development
//       sameSite: "strict",
//     },
//   }),
// );
//This code works b/c: memory writes are synchronous-ish, no network/DB latency, session is available immediately on redirect.
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false, sameSite: "strict" },
  }),
);

// Make flash message available to all views
app.use((req, res, next) => {
  res.locals.flash = req.session.flash || {}; // Store flash messages in local variables
  req.session.flash = null; // Clear the flash message after it's accessed
  next();
});

// Passport Middleware
app.use(passport.initialize());
app.use(passport.session());

// Routes

// Home Route - Login Form
app.get("/", (req, res) => {
  res.render("index", { title: "Login", user: req.user });
});

// Sign-up route (GET)
app.get("/sign-up", (req, res) => {
  res.render("sign-up-form", { title: "Sign Up" });
});

// Sign-up form submission (POST)
app.post(
  "/sign-up",
  [
    // Validation
    body("username").notEmpty().withMessage("Username is required."),
    body("password")
      .isLength({ min: 3 })
      .withMessage("Password must be at least 3 characters long."),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      req.session.flash = {
        error: errors
          .array()
          .map((err) => err.msg)
          .join(", "), // Join validation errors into one string
      };
      return res.redirect("/sign-up"); // Redirect back to the sign-up form with error messages
    }

    const { username, password } = req.body;

    try {
      // Check if username already exists
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username],
      );

      if (rows.length > 0) {
        req.session.flash = {
          error: "Username already taken!",
        };
        return res.redirect("/sign-up"); // Redirect with error message
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert new user into the database
      await pool.query(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        [username, hashedPassword],
      );

      // Redirect to login page after successful sign-up
      req.session.flash = {
        success: "Sign-up successful! Please log in.",
      };
      res.redirect("/"); // Redirect to login page (or any other page)
    } catch (err) {
      console.error(err);
      req.session.flash = {
        error: "Something went wrong. Please try again later.",
      };
      res.redirect("/sign-up");
    }
  },
);

// Passport LocalStrategy
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

// Serialize / Deserialize
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

// Log-in Route with Validation
app.post(
  "/log-in",
  [
    body("username").notEmpty().withMessage("Username is required."),
    body("password").notEmpty().withMessage("Password is required."),
  ],
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      req.session.flash = {
        error: errors
          .array()
          .map((err) => err.msg)
          .join(", "),
      };
      return res.redirect("/"); // Redirect to login page with error messages
    }

    passport.authenticate("local", (err, user, info) => {
      if (err) return next(err);
      if (!user) {
        req.session.flash = { error: info.message || "Invalid credentials." };
        return res.redirect("/"); // Redirect back to login page with error message
      }

      req.logIn(user, (err) => {
        if (err) return next(err);
        return res.redirect("/"); // Successful login, redirect
      });
    })(req, res, next);
  },
);

// Log-out
app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/"); // Redirect to home after log-out
  });
});

// Error Handling
// 404 - Route not found (This should be placed before the general error handler)
app.use((req, res, next) => {
  res.status(404).render("404", {
    title: "404 Not Found",
    error: "Sorry, we couldn't find the page you were looking for.",
  });
});

// General error handler for 500 errors (or uncaught errors)
app.use((err, req, res, next) => {
  console.error(err); // Log the error for debugging purposes
  res.status(err.status || 500).render("500", {
    title: "Internal Server Error",
    error:
      err.message ||
      "Something went wrong on the server. Please try again later.",
  });
});

// Start Server
app.listen(3000, (err) => {
  if (err) throw err;
  console.log("App listening on port 3000!");
});

// // General error handler for 500 errors (or uncaught errors)
// app.use((err, req, res, next) => {
//   console.error(err); // Log the error for debugging purposes
