const express = require('express');
const session = require('express-session');
const csrf = require('csurf');

const app = express();

// Session middleware (required for CSRF)
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true in production with HTTPS
}));

// Body parser middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// CSRF protection middleware
const csrfProtection = csrf({ cookie: false });
app.use(csrfProtection);

// Make CSRF token available to all routes
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

// CSRF error handler
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    res.status(403).json({ error: 'Invalid CSRF token' });
  } else {
    next(err);
  }
});

// Your existing routes go here
// Example route that provides CSRF token
app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
