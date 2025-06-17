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
app.use((req, res, next) => {
  // Skip CSRF for GET, HEAD, OPTIONS requests
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  try {
    csrfProtection(req, res, next);
  } catch (err) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
});

// Route to get CSRF token
app.get('/csrf-token', (req, res) => {
  const token = csrfProtection.create(req.csrfSecret || csrfProtection.secretSync());
  res.json({ csrfToken: token });
});

// Your existing routes go here
// Make sure to include CSRF token in forms and AJAX requests

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
