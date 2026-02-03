require("dotenv").config();
const bcrypt = require("bcryptjs");

const path = require("node:path");
const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

const pool = new Pool({
  host: process.env.PG_HOST,
  user: process.env.PG_USER,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: Number(process.env.PG_PORT),

  max: 10, // max clients in pool
  idleTimeoutMillis: 30000, // close idle clients after 30 seconds
  connectionTimeoutMillis: 5000,
});

const app = express();
app.use(express.static(__dirname + "/public"));
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

// secret: "cats"... used to sign the session cookie, it prevents tampering. In real apps → use an env var, not "cats"
// resave: false... “Don’t re-save the session if nothing changed.” Why this is good: Avoids unnecessary writes to the session store.Especially important for DB-backed session stores.
// saveUninitialized: false... “Don’t create a session until we actually need one.” Why this matters: No session cookie for anonymous visitors;  Better for privacy; Required for some cookie consent laws
// How Passport uses this... Passport does not store users itself. Instead: Passport puts a user ID into req.session; express-session persists it. On future requests: session is loaded, passport reads it, and deserializeUser runs req.user is populated. Without this line: ❌ no sessions, ❌ no persistent login, ❌ Passport won’t work with req.user

// MENTAL MODEL : Cookie (session ID) → Session store → req.session → Passport → req.user
// NOTE - below is missing a session store: What’s missing (technically)... This line does not specify a session store, so Express Session falls back to its default store: MemoryStore. Why that means “no real session store”. MemoryStore: lives in server memory is wiped on server restart, and does not scale. It is explicitly not for production.
app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));

// WHAT ABOUT THE SESSION STORE??? Read this: https://www.npmjs.com/package/connect-pg-simple

// Still needed???
// Yes, app.use(passport.initialize()) is still generally required in Express applications to initialize Passport, particularly for setting up the authentication strategies and configuring the request object (req.user). 
app.use(passport.initialize());

app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

// A quick tip
// In express, you can set and access various local variables throughout your entire app (even in views) with the locals object. We can use this knowledge to write ourselves a custom middleware that will simplify how we access our current user in our views.

// Middleware functions are functions that take the req and res objects, manipulate them, and pass them on through the rest of the app.

app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});

// If you insert this code somewhere between where you instantiate the passport middleware and before you render your views, you will have access to the currentUser variable in all of your views, and you won’t have to manually pass it into all of the controllers in which you need it.


// If you fill out and submit the form now, everything should technically work, but you won’t actually SEE anything different on the page… let’s fix that.

// The passport middleware checks to see if there is a user logged in (by checking the cookies that come in with the req object) and if there is, it adds that user to the request object for us. So, all we need to do is check for req.user to change our view depending on whether or not a user is logged in.

// Edit your app.get("/") to send the user object to our view like so:
// app.get("/", (req, res) => res.render("index"));

app.get("/", (req, res) => {
  res.render("index", { user: req.user });
});


app.listen(3000, (error) => {
  if (error) {
    throw error;
  }
  console.log("app listening on port 3000!");
});

// SIGN UP FORM
app.get("/sign-up", (req, res) => res.render("sign-up-form"));

// Per lesson (https://www.theodinproject.com/lessons/node-path-nodejs-authentication-basics, next, create an app.post for the sign up form so that we can add users to our database (remember our notes about sanitization, and using plain text to store passwords…).Let’s reiterate: this is not a particularly safe way to create users in your database… BUT you should now be able to visit /sign-up, and submit the form. If all goes well it’ll redirect you to the index and you will be able to go see your newly created user inside your database. Open your database in psql and run your query to see your first user!

// REMINDER - this is not a particularly safe way to create users in your database… BUT you should now be able to visit /sign-up, and submit the form. If all goes well it’ll redirect you to the index and you will be able to go see your newly created user inside your database. 

// app.post("/sign-up", async (req, res, next) => {
//   try {
//     await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [
//       req.body.username,
//       req.body.password,
//     ]);
//     res.redirect("/");
//   } catch (err) {
//     return next(err);
//   }
// });

// CHANGED FOR BCRYPTJS
app.post("/sign-up", async (req, res, next) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10); // 10 is the length of the “salt” to use in the hashing function
    await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [
      req.body.username,
      hashedPassword,
    ]);
    res.redirect("/");
  } catch (error) {
    console.error(error);
    next(error);
  }
});

// Function one: setting up the LocalStrategy
// This function is what will be called when we use the "passport.authenticate()" function later. Basically, it takes a username and password, tries to find the user in our DB, and then makes sure that the user’s password matches the given password. If all of that works out (there’s a user in the DB, and the passwords match) then it authenticates our user and moves on! We will not be calling this function directly, so you won’t have to supply the "done" function. This function acts a bit like a middleware and will be called for us when we ask passport to do the authentication later.

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username],
      );
      const user = rows[0];

      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }

      // Inside your LocalStrategy function we need to replace the user.password !== password expression with the bcrypt.compare() function.

      //   if (user.password !== password) {
      //     return done(null, false, { message: "Incorrect password" });
      //   }

      // With the code below, you should now be able to log in using the new user you’ve created (the one with a hashed password). Unfortunately, users that were saved BEFORE you added bcrypt will no longer work, but that’s a small price to pay for security! (and a good reason to include bcrypt from the start on your next project)

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        // passwords do not match!
        return done(null, false, { message: "Incorrect password" });
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }),
);

// Functions two and three: sessions and serialization
// To make sure our user is logged in, and to allow them to stay logged in as they move around our app, passport internally calls a function from express-session that uses some data to create a cookie called connect.sid which is stored in the user’s browser. These next two functions define what bit of information passport is looking for when it creates and then decodes the cookie. The reason they require us to define these functions is so that we can make sure that whatever bit of data it’s looking for actually exists in our Database! passport.serializeUser takes a callback which contains the information we wish to store in the session data. passport.deserializeUser is called when retrieving a session, where it will extract the data we “serialized” in it then ultimately attach something to the .user property of the request object (req.user) for use in the rest of the request.

// For our purposes, the functions that are listed in the passport docs will work just fine:
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    const user = rows[0];

    done(null, user);
  } catch (err) {
    done(err);
  }
});

// When a session is created, passport.serializeUser will receive the user object found from a successful login and store its id property in the session data. Upon some other request, if it finds a matching session for that request, passport.deserializeUser will retrieve the id we stored in the session data. We then use that id to query our database for the specified user, then done(null, user) attaches that user object to req.user. Now in the rest of the request, we have access to that user object via req.user.

// Again, we aren’t going to be calling these functions on our own and we just need to define them, they’re used in the background by passport.

// LOG-IN ROUTE
app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  }),
);

//As you can see, all we have to do is call passport.authenticate(). This middleware performs numerous functions behind the scenes. Among other things, it looks at the request body for parameters named username and password then runs the LocalStrategy function that we defined earlier to see if the username and password are in the database. It then creates a session cookie that gets stored in the user’s browser and used in all future requests to see whether or not that user is logged in. It can also redirect you to different routes based on whether the login is a success or a failure. If we had a separate login page we might want to go back to that if the login failed, or we might want to take the user to their user dashboard if the login is successful. Since we’re keeping everything in the index we want to go back to “/” no matter what.

// As one last step… let’s make that log out link actually work for us. As you can see it’s sending us to /log-out so all we need to do is add a route for that in our app.js. Conveniently, the passport middleware adds a logout function to the req object, so logging out is as easy as this:

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});
