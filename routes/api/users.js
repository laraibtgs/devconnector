const express = require("express");
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken');
const config = require('config');
const {check, validationResult} = require("express-validator");

const User = require('../../models/User');

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post("/",[
    check('name', 'Name is the required').not().isEmpty(),
    check('email',"Please include valid email").isEmail(),
    check('password',"Please Enter the password with six or more letters").isLength({min:6})
],
async (req, res)=>{
    const errors = validationResult(req);
    if(!errors.isEmpty()){
       return  res.status(400).json({errors: errors.array()});
    }
    const {name, email, password} = req.body;
    try {
        let user =  await User.findOne({email});
        if(user){
           return res.status(400).json({errors : [{msg : "User Already registered"}] })
        }

        const avatar = gravatar.url(email,{
            s: '200',
            r: 'pg',
            d: 'mm'
        });

        user = new User({
            name,
            email,
            avatar,
            password
        });

        const salt = await bcrypt.genSalt(10);

        user.password = await bcrypt.hash(password, salt);
        await user. save();
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