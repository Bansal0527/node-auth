const { Router } = require('express');
const authController = require('../controllers/authController');

const router = Router();

router.get('/signup', (req, res) => {
  res.render('signup', { csrfToken: req.csrfToken() });
});

router.post('/signup', authController.signup_post);

router.get('/login', (req, res) => {
  res.render('login', { csrfToken: req.csrfToken() });
});

router.post('/login', authController.login_post);

router.get('/logout', authController.logout_get);

module.exports = router;
