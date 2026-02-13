const express = require("express");
const app = express();
const rateLimit = require("express-rate-limit");

require('dotenv').config();
const PORT= process.env.PORT || 4000

const cookieParser = require("cookie-parser");
app.use(cookieParser());
app.use(express.json()); // json data ko parse krne ke lie use krte h 

require("./config/database").connect();

// Rate limiter for authentication endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 requests per windowMs
    message: 'Too many authentication attempts, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

//import route and mount

const user = require("./routes/user");

app.use("/api/v1", authLimiter, user);

//activate

app.listen(PORT, ()=> {
    console.log(`App is listening at port ${PORT}`);
})