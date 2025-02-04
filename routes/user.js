const express = require("express");
const router = express.Router();

const {login, signup} = require("../Controllers/Auth");
const {auth, isStudent, isAdmin} = require("../middlewares/auth");
const User = require("../models/User");
router.post("/login", login);
router.post("/signup", signup);


//Protected routes
router.get("/student", auth, isStudent, (req, res) => {
    res.json({
        success:true,
        message:'Welcome to the Protected route for Students'
    });
})


router.get("/admin", auth, isAdmin, (req, res) => {
    res.json({
        success:true,
        message:'Welcome to the Protected route for Admin'
    });
});
router.get("/getEmail", auth,async (req, res) => {
    try {
        const id = req.user.id;
        const user = await User.findById(id);

        res.status(200).json({
            success:true,
            user:user,
            message:'Welcome to email route'
        })
    } catch (error) {
        res.status(500).json({
            success:false,
            error:error,
            message:'Error occured'
        })
    }

})

module.exports = router;