const express = require("express");
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

app.listen(PORT, ()=> {
    console.log(`App is listening at port ${PORT}`);
})