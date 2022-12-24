const express = require("express");
const auth = require('../../middleware/auth');
const router = express.Router();
const User = require('../../models/User');
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken');
const config = require('config');
const {check, validationResult} = require("express-validator");

// @route   GET api/auth
// @desc    Test route
// @access  Public
router.get("/",auth, async(req, res)=>{
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.status(200).json(user);
    } catch (error) {
        res.status(500).send("Server Error");
    }
});

// @route   POST api/auth
// @desc    Authenticate user and get token
// @access  Public
router.post("/",[
    check('email',"Please include valid email").isEmail(),
    check('password',"Password is required").exists()
],
async (req, res)=>{
    const errors = validationResult(req);
    if(!errors.isEmpty()){
       return  res.status(400).json({errors: errors.array()});
    }
    const {email, password} = req.body;
    try {
        let user =  await User.findOne({email});
        if(!user){
           return res.status(400).json({errors : [{msg : "InValid Crendentials"}] })
        }

        const isMatch = bcrypt.compare(password, user.password);
        if(!isMatch){
           return res.status(400).json({errors : [{msg : "InValid Crendentials"}] })
             
        }
        const payload = {
            user :{
                id: user.id
            }
        }
        jwt.sign(payload, config.get('jwtSecret'),{expiresIn: 3600000},(err, token)=>{
            if(err){
                throw err;
            }
            res.json({token})
        } )
        // res.send(`User Registered ${user}`)

    } catch (error) {
        console.log(error.message);
        res.status(500).send("Server Error")
    }
});

module.exports = router;