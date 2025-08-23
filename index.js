const express = require("express");
const csrf = require("csrf");
const Tokens = new csrf();
const cookieParser = require('cookie-parser');
const csrf = require('csrf');
const tokens = new csrf();
const app = express();

// CSRF Protection Middleware
const csrfProtection = (req, res, next) => {
  if (!req.session.csrfSecret) {
    req.session.csrfSecret = Tokens.secretSync();
  }
  
  // Generate token for GET requests
  if (req.method === 'GET') {
    res.locals.csrfToken = Tokens.create(req.session.csrfSecret);
  }
  
  // Skip CSRF check for GET, HEAD, OPTIONS
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  // Get token from body, query, or headers
  const token = req.body._csrf || req.query._csrf || req.headers['x-csrf-token'];
  
  if (!token || !Tokens.verify(req.session.csrfSecret, token)) {
    const err = new Error('Invalid CSRF token');
    err.status = 403;
    return next(err);
  }
  
  next();
};
app.use(csrfProtection);

// CSRF Protection Middleware
app.use(cookieParser());

// Generate CSRF secret if not exists
app.use((req, res, next) => {
  if (!req.session) {
    req.session = {};
  }
  if (!req.session.csrfSecret) {
    req.session.csrfSecret = tokens.secretSync();
  }
  next();
});

// CSRF token generation and validation
app.use((req, res, next) => {
  const token = req.body._csrf || req.query._csrf || req.headers["x-csrf-token"];
  
  // Generate token for GET requests
  if (req.method === "GET") {
    res.locals.csrfToken = tokens.create(req.session.csrfSecret);
  }
  
  // Validate token for state-changing requests
  if (["POST", "PUT", "DELETE", "PATCH"].includes(req.method)) {
    if (!token || !tokens.verify(req.session.csrfSecret, token)) {
      return res.status(403).json({ error: "Invalid CSRF token" });
    }
  }
  
  next();
});
require('dotenv').config();
const PORT= process.env.PORT || 4000

const cookieParser = require("cookie-parser");
app.use(cookieParser());
app.use(express.json()); // json data ko parse krne ke lie use krte h 

require("./config/database").connect();


//import route and mount

const user = require("./routes/user");

app.use("/api/v1", user);

//activate

app.listen(PORT, ()=> {
    console.log(`App is listening at port ${PORT}`);
})