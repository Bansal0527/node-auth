const express = require("express");
const csrf = require('csrf');
const app = express();

require('dotenv').config();
const PORT= process.env.PORT || 4000

const cookieParser = require("cookie-parser");
app.use(cookieParser());
app.use(express.json()); // json data ko parse krne ke lie use krte h 

require("./config/database").connect();


//import route and mount

const user = require("./routes/user");

app.use("/api/v1", user);

//activate


// CSRF Protection
const csrfProtection = csrf();
app.use(csrfProtection);

// Make CSRF token available to all routes
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});
app.listen(PORT, ()=> {
    console.log(`App is listening at port ${PORT}`);
})