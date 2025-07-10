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

// Middleware to pass CSRF token to all views
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

// Your existing routes go here
app.get('/', (req, res) => {
  res.send(`
    <form method="POST" action="/submit">
      <input type="hidden" name="_csrf" value="${req.csrfToken()}">
      <input type="text" name="data" placeholder="Enter data">
      <button type="submit">Submit</button>
    </form>
  `);
});

app.post('/submit', (req, res) => {
  res.send('Data received: ' + req.body.data);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
