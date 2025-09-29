const express = require("express");
const csrf = require('csurf');
const app = express();

require('dotenv').config();
const PORT= process.env.PORT || 4000

const cookieParser = require("cookie-parser");
app.use(cookieParser('cookie-parser-secret-12345'));
app.use(csrf({ cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production' } }));
app.use(express.json()); // json data ko parse krne ke lie use krte h 
app.use(express.urlencoded({ extended: true }));

require("./config/database").connect();


//import route and mount

const user = require("./routes/user");

app.use("/api/v1", user);

//activate

app.listen(PORT, ()=> {
    console.log(`App is listening at port ${PORT}`);
})
app.use(function (err, req, res, next) {
  if (err.code !== 'EBADCSRFTOKEN') return next(err)

  // handle CSRF token errors here
  res.status(403)
  res.send('form tampered with')
});
