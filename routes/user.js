const express = require("express");
const router = express.Router();
const rateLimit = require("express-rate-limit");

const {login, signup} = require("../Controllers/Auth");
const {auth, isStudent, isAdmin} = require("../middlewares/auth");
const User = require("../models/User");

// Rate limiter for authentication endpoints to prevent brute force attacks
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: {
        success: false,
        message: 'Too many authentication attempts from this IP, please try again after 15 minutes'
    },
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    // Security: Use a custom key generator to prevent IP spoofing via X-Forwarded-For
    keyGenerator: (req) => {
        // Only trust X-Forwarded-For if behind a known proxy (configure as needed)
        // For direct connections, use req.ip which is more reliable
        const forwardedFor = req.headers['x-forwarded-for'];
        
        // If X-Forwarded-For exists, validate it's not manipulated
        if (forwardedFor) {
            // Take only the first IP (leftmost is the original client)
            const ips = forwardedFor.split(',').map(ip => ip.trim());
            // Additional validation: check if IP format is valid
            const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
            if (ips[0] && ipRegex.test(ips[0])) {
                return ips[0];
            }
        }
        // Fall back to req.ip if X-Forwarded-For is absent or invalid
        return req.ip || req.connection.remoteAddress;
    },
    // Skip rate limiting for failed requests to avoid lockout on failed auth
    skipFailedRequests: false, // Count failed attempts to prevent brute force
    skipSuccessfulRequests: false,
});

// Rate limiter for general API endpoints
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
        success: false,
        message: 'Too many requests from this IP, please try again after 15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
    // Security: Use a custom key generator to prevent IP spoofing via X-Forwarded-For
    keyGenerator: (req) => {
        // Only trust X-Forwarded-For if behind a known proxy (configure as needed)
        // For direct connections, use req.ip which is more reliable
        const forwardedFor = req.headers['x-forwarded-for'];
        
        // If X-Forwarded-For exists, validate it's not manipulated
        if (forwardedFor) {
            // Take only the first IP (leftmost is the original client)
            const ips = forwardedFor.split(',').map(ip => ip.trim());
            // Additional validation: check if IP format is valid
            const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
            if (ips[0] && ipRegex.test(ips[0])) {
                return ips[0];
            }
        }
        // Fall back to req.ip if X-Forwarded-For is absent or invalid
        return req.ip || req.connection.remoteAddress;
    },
    skipFailedRequests: false,
    skipSuccessfulRequests: false,
});

router.post("/login", authLimiter, login);
router.post("/signup", authLimiter, signup);


//Protected routes
router.get("/student", apiLimiter, auth, isStudent, (req, res) => {
    res.json({
        success:true,
        message:'Welcome to the Protected route for Students'
    });
})


router.get("/admin", apiLimiter, auth, isAdmin, (req, res) => {
    res.json({
        success:true,
        message:'Welcome to the Protected route for Admin'
    });
});
router.get("/getEmail", apiLimiter, auth,async (req, res) => {
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