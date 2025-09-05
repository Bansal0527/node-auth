const crypto = require('crypto');

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function csrfProtection(options = {}) {
  const {
    cookie = 'XSRF-TOKEN',
    header = 'X-XSRF-TOKEN',
    excludePaths = []
  } = options;

  return (req, res, next) => {
    // Skip CSRF check for excluded paths
    if (excludePaths.some(path => req.path.startsWith(path))) {
      return next();
    }

    // Skip CSRF check for GET requests
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
      // Generate and set token for GET requests
      if (!req.cookies[cookie]) {
        const token = generateToken();
        res.cookie(cookie, token, {
          httpOnly: false, // Must be false so client can read it
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict'
        });
      }
      return next();
    }

    // Validate CSRF token for state-changing requests
    const token = req.cookies[cookie];
    const submittedToken = req.headers[header.toLowerCase()] || req.body._csrf;

    if (!token || !submittedToken || token !== submittedToken) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    next();
  };
}

module.exports = csrfProtection;
