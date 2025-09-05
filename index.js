const express = require('express');
const cookieParser = require('cookie-parser');
const Tokens = require('csrf');
const app = express();

// CSRF Protection
app.use(cookieParser());
app.use(csrfProtection({
  excludePaths: ['/api'] // Exclude API routes if they use token auth
}));
const port = 3000;

// Initialize CSRF tokens
const tokens = new Tokens();

// Middleware
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// CSRF Protection Middleware
app.use((req, res, next) => {
  // Generate secret if not exists
  if (!req.cookies.csrfSecret) {
    const secret = tokens.secretSync();
    res.cookie('csrfSecret', secret, { httpOnly: true });
    req.csrfSecret = secret;
  } else {
    req.csrfSecret = req.cookies.csrfSecret;
  }

  // Generate token for responses
  req.csrfToken = () => tokens.create(req.csrfSecret);

  // Skip CSRF check for GET, HEAD, OPTIONS
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  // Verify CSRF token for other methods
  const token = req.body._csrf || req.headers['x-csrf-token'];
  if (!token || !tokens.verify(req.csrfSecret, token)) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }

  next();
});

// Existing routes and middleware should go here
// (preserving the rest of the original index.js content)

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
