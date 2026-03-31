const express = require('express');
const cookieParser = require('cookie-parser');
const Tokens = require('csrf');
const tokens = new Tokens();
const cookieParser = require('cookie-parser');
const Tokens = require('csrf');
const app = express();
const rateLimit = require("express-rate-limit");

// CSRF Protection Middleware
app.use(cookieParser());

// Generate and validate CSRF tokens
app.use((req, res, next) => {
  // Skip CSRF for API routes or specific paths if needed
  if (req.path.startsWith('/api')) {
    return next();
  }
  
  // Generate secret if not exists
  if (!req.cookies.csrfSecret) {
    const secret = tokens.secretSync();
    res.cookie('csrfSecret', secret, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    req.csrfSecret = secret;
  } else {
    req.csrfSecret = req.cookies.csrfSecret;
  }
  
  // Generate token
  req.csrfToken = () => tokens.create(req.csrfSecret);
  
  // Make token available to views
  res.locals.csrfToken = req.csrfToken();
  
  // Validate token on state-changing methods
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    const token = req.body._csrf || req.headers['x-csrf-token'];
    if (!token || !tokens.verify(req.csrfSecret, token)) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
  }
  
  next();
});
const port = 3000;

// Initialize CSRF tokens
const tokens = new Tokens();

// Middleware
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CSRF protection middleware
app.use((req, res, next) => {
  // Generate secret for new sessions
  if (!req.cookies.csrfSecret) {
    const secret = tokens.secretSync();
    res.cookie('csrfSecret', secret, { httpOnly: true });
    req.csrfSecret = secret;
  } else {
    req.csrfSecret = req.cookies.csrfSecret;
  }

  // Generate token for GET requests
  if (req.method === 'GET') {
    req.csrfToken = () => tokens.create(req.csrfSecret);
  }

  // Verify token for state-changing requests
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    const token = req.body._csrf || req.query._csrf || req.headers['x-csrf-token'];
    
    if (!token || !tokens.verify(req.csrfSecret, token)) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
  }

  next();
});

// Routes
app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

require('dotenv').config();
const PORT= process.env.PORT || 4000

const cookieParser = require("cookie-parser");
app.use(cookieParser());
app.use(express.json()); // json data ko parse krne ke lie use krte h 

require("./config/database").connect();

// Rate limiter for authentication endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 requests per windowMs
    message: 'Too many authentication attempts, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

//import route and mount

const user = require("./routes/user");

app.use("/api/v1", authLimiter, user);

//activate

    console.log(`App is listening at port ${PORT}`);
})
