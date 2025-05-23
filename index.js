const express = require('express');
const mongoose = require('mongoose');
const authRoutes = require('./routes/authRoutes');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const { requireAuth, checkUser } = require('./middleware/authMiddleware');
const app = express();

// middleware
app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

// CSRF protection
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

// view engine
app.set('view engine', 'ejs');

// database connection
const dbURI = 'mongodb://localhost:27017/node-auth';
mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex:true })
  .then((result) => app.listen(3000))
  .catch((err) => console.log(err));

// routes
app.get('*', checkUser);
app.get('/', (req, res) => res.render('home', { csrfToken: req.csrfToken() }));
app.get('/smoothies', requireAuth, (req, res) => res.render('smoothies', { csrfToken: req.csrfToken() }));
app.use(authRoutes);
