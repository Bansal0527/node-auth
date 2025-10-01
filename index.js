const express = require("express");
con
const co

// CSRF Protection
app.use(cookieParser());
const tokens = new Tokens();
const csrfProtection = (req, res, next) => {
  if (!req.session.csrfSecret) {
    req.session.csrfSecret = tokens.secretSync();
  }
  
  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE') {
    const token = req.body._csrf || req.headers['x-csrf-token'];
    if (!tokens.verify(req.session.csrfSecret, token)) {
      const err = new Error('Invalid CSRF token');
      err.code = 'EBADCSRFTOKEN';
      return next(err);
    }
  }
  
  res.locals.csrfToken = tokens.create(req.session.csrfSecret);
  next();
};
app.use(csrfProtection);okieParser = require("cookie-parser");
const Tokens = require("csrf");st app = express();

require('dotenv').config();
const PORT= process.env.PORT || 4000

const cookieParser = require("cookie-parser");

// CSRF Protection Middleware
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');

app.use(cookieParser());

const {
  generateToken,
  doubleCsrfProtection,
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || 'your-secret-key-change-in-production',
  cookieName: '_csrf',
  cookieOptions: {
    sameSite: 'strict',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
  },
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
});

app.use(doubleCsrfProtection);

// CSRF token endpoint
app.get('/csrf-token', (req, res) => {
  const token = generateToken(req, res);
  res.json({ csrfToken: token });
});

app.use(cookieParser());
app.use(express.json()); // json data ko parse krne ke lie use krte h 

require("./config/database").connect();


//import route and mount

const user = require("./routes/user");

app.use("/api/v1", user);

//activate

app.listen(PORT, ()=> {
    console.log(`App is listening at port ${PORT}`);
}
// CSRF error handler
app.use(function (err, req, res, next) {
  if (err.code !== 'EBADCSRFTOKEN') return next(err);
  
  res.status(403);
  res.send('Form tampered with');
});

)