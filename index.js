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
    key: '_csrf',
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

// Apply CSRF protection middleware
app.use((req, res, next) => {
  // Skip CSRF for GET, HEAD, OPTIONS requests
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  try {
    const secret = req.cookies._csrf || csrfProtection.secretSync();
    const token = req.headers['x-csrf-token'] || req.body._csrf;
    
    if (!token || !csrfProtection.verify(secret, token)) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    
    res.cookie('_csrf', secret, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    next();
  } catch (err) {
    return res.status(403).json({ error: 'CSRF token validation failed' });
  }
});

// Route to get CSRF token
app.get('/csrf-token', (req, res) => {
  const secret = req.cookies._csrf || csrfProtection.secretSync();
  const token = csrfProtection.create(secret);
  
  res.cookie('_csrf', secret, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  
  res.json({ csrfToken: token });
});

// Your existing routes go here
// Make sure to include CSRF token in forms and AJAX requests

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
