const express = require('express');
const csrf = require('csrf');
const cookieParser = require('cookie-parser');

const app = express();

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CSRF protection setup
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

// Apply CSRF protection to all routes
app.use(csrfProtection);

// Middleware to provide CSRF token to views
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

// Your existing routes go here
// Make sure to include the CSRF token in forms:
// <input type="hidden" name="_csrf" value="<%= csrfToken %>">

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
