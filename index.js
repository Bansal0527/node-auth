const express = require('express');
const csrf = require('csrf');
const cookieParser = require('cookie-parser');

const app = express();

// Initialize CSRF protection
const csrfProtection = csrf();

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CSRF middleware
app.use((req, res, next) => {
  // Skip CSRF for GET, HEAD, OPTIONS requests
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  // Get CSRF token from header or body
  const token = req.headers['x-csrf-token'] || req.body._csrf;
  const secret = req.cookies['csrf-secret'];
  
  if (!secret) {
    return res.status(403).json({ error: 'CSRF secret missing' });
  }
  
  if (!token) {
    return res.status(403).json({ error: 'CSRF token missing' });
  }
  
  // Verify CSRF token
  if (!csrfProtection.verify(secret, token)) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  
  next();
});

// Route to get CSRF token
app.get('/csrf-token', (req, res) => {
  let secret = req.cookies['csrf-secret'];
  
  if (!secret) {
    secret = csrfProtection.secretSync();
    res.cookie('csrf-secret', secret, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
  }
  
  const token = csrfProtection.create(secret);
  res.json({ csrfToken: token });
});

// Example protected route
app.post('/api/protected', (req, res) => {
  res.json({ message: 'This route is protected by CSRF' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    res.status(403).json({ error: 'Invalid CSRF token' });
  } else {
    res.status(500).json({ error: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
