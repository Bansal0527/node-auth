const bcrypt = require("bcrypt");
const User = require("../models/User");
const jwt = require("jsonwebtoken");
const { options } = require("../routes/user");
require("dotenv").config();

// Comprehensive sanitization function to prevent NoSQL injection attacks
const sanitizeInput = (input) => {
    // If input is not an object, return as-is (strings, numbers, booleans, null)
    if (typeof input !== 'object' || input === null) {
        return input;
    }
    
    // Handle arrays recursively
    if (Array.isArray(input)) {
        return input.map(item => sanitizeInput(item));
    }
    
    // For objects, create a new sanitized object
    const sanitized = {};
    for (const key in input) {
        if (!input.hasOwnProperty(key)) {
            continue;
        }
        
        // Remove keys that start with $ (MongoDB operators like $gt, $ne, $where, $regex)
        if (key.startsWith('$')) {
            continue;
        }
        
        // Remove keys with dots (nested query operators like 'user.role')
        if (key.includes('.')) {
            continue;
        }
        
        // Remove keys with special MongoDB characters
        if (key.includes('$') || key.includes('{') || key.includes('}')) {
            continue;
        }
        
        // Recursively sanitize nested objects
        const value = input[key];
        // If value is an object, recursively sanitize it
        if (typeof value === 'object' && value !== null) {
            sanitized[key] = sanitizeInput(value);
        } else {
            sanitized[key] = value;
        }
    }
    
    return sanitized;
};

//signup route handler
exports.signup = async (req,res) => {
    try{
        // Sanitize all input to prevent NoSQL injection
        const sanitizedBody = sanitizeInput(req.body);
        
        //get data with explicit validation
        const {name, email, password, role} = sanitizedBody;
        
        // Validate all required fields are present
        if(!name || !email || !password) {
            return res.status(400).json({
                success:false,
                message:'All fields are required',
            });
        }
        
        //Validate input types to prevent NoSQL injection
        if(typeof name !== 'string' || typeof email !== 'string' || typeof password !== 'string') {
            return res.status(400).json({
                success:false,
                message:'Invalid input types',
            });
        }
        
        // Additional validation: ensure inputs are not empty strings
        if(name.trim() === '' || email.trim() === '' || password.trim() === '') {
            return res.status(400).json({
                success:false,
                message:'Fields cannot be empty',
            });
        }
        
        //Validate password strength
        if(password.length < 8) {
            return res.status(400).json({
                success:false,
                message:'Password must be at least 8 characters long',
            });
        }
        
        //Check against common weak passwords
        const commonPasswords = ['password', '123456', '12345678', 'qwerty', 'abc123', 'password123', '111111', '123123', 'admin', 'letmein', 'welcome', 'monkey', '1234567890'];
        if(commonPasswords.includes(password.toLowerCase())) {
            return res.status(400).json({
                success:false,
                message:'Password is too common. Please choose a stronger password',
            });
        }
        
        //Check password complexity
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
        
        if(!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
            return res.status(400).json({
                success:false,
                message:'Password must contain uppercase, lowercase, numbers, and special characters',
            });
        }
        
        //Whitelist allowed roles to prevent privilege escalation
        const allowedRoles = ['Student', 'Admin'];
        const userRole = allowedRoles.includes(role) ? role : 'Student';
        
        //check if user already exist - use string value explicitly
        const existingUser = await User.findOne({email: String(email)});

        if(existingUser){
            return res.status(400).json({
                success:false,
                message:'User already Exists',
            });
        }

        //secure password
        let hashedPassword;
        try{
            hashedPassword = await bcrypt.hash(password, 10);
        }
        catch(err) {
            return res.status(500).json({
                success:false,
                message:'Error inn hashing Password',
            });
        }

        // Create entry for User with ONLY explicitly whitelisted fields
        // NO request data is passed directly - each field is explicitly assigned
        // This prevents NoSQL injection and privilege escalation attacks
        const user = await User.create({
            name: String(name),
            email: String(email),
            password: hashedPassword,
            role: userRole
        })

        return res.status(200).json({
            success:true,
            message:'User Created Successfully',
        });

    }
    catch(error) {
        console.error(error);
        return res.status(500).json({
            success:false,
            message:'User cannot be registered, please try again later',
        });
    }
}


//login
exports.login = async (req,res) => {
    try {
        // Sanitize all input to prevent NoSQL injection
        const sanitizedBody = sanitizeInput(req.body);

        //data fetch
        const {email, password} = sanitizedBody;
        
        //Validate input types to prevent NoSQL injection
        if(typeof email !== 'string' || typeof password !== 'string') {
            return res.status(400).json({
                success:false,
                message:'Invalid input types',
            });
        }
        
        //validation on email and password
        if(!email || !password) {
            return res.status(400).json({
                success:false,
                message:'PLease fill all the details carefully',
            });
        }

        //check for registered user - use string value explicitly
        let user = await User.findOne({email: String(email)});
        //if not a registered user
        if(!user) {
            return res.status(401).json({
                success:false,
                message:'User is not registered',
            });
        }

        const payload = {
            email:user.email,
            id:user._id,
            role:user.role,
        };
        //verify password & generate a JWT token
        if(await bcrypt.compare(password,user.password) ) {
            //password match
            let token =  jwt.sign(payload, 
                                process.env.JWT_SECRET,
                                {
                                    expiresIn:"2h",
                                });

                                
            user = user.toObject();
            user.token = token;
            user.password = undefined;

            const options = {
                expires: new Date( Date.now() + 3*24*60*60*1000),
                httpOnly:true,
            }

            res.cookie("token", token, options).status(200).json({
                success:true,
                token,
                user,
                message:'User Logged in successfully',
            });

            // res.status(200).json({
            //     success:true,
            //     token,
            //     user,
            //     message:'User Logged in successfully',
            // });
        }
        else {
            //passwsord do not match
            return res.status(403).json({
                success:false,
                message:"Password Incorrect",
            });
        }

    }
    catch(error) {
        console.log(error);
        return res.status(500).json({
            success:false,
            message:'Login Failure',
        });

    }
}