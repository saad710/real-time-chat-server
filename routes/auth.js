const router = require("express").Router();
const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
const config = require('../config');
const VerifyToken = require('./VerifyToken');

//REGISTER
router.post("/register", async (req, res) => {
  try {
    //generate new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    //create new user
    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
    });

    //save user and respond
    const user = await newUser.save();

    const token = jwt.sign({ id: user._id }, config.secret, {
            expiresIn: 86400 // expires in 24 hours
         });
    res.status(200).json({ auth: true, token: token });
  } catch (err) {
    res.status(500).json(err)
  }
});


router.get('/me', VerifyToken, function(req, res, next) {

  User.findById(req.userId, { password: 0 }, function (err, user) {
    if (err) return res.status(500).send("There was a problem finding the user.");
    if (!user) return res.status(404).send("No user found.");
    
    res.status(200).send(user);
  });
  
});




// router.post('/register', function(req, res) {
  
//   const hashedPassword = bcrypt.hashSync(req.body.password, 8);
  
//   User.create({
//     username : req.body.username,
//     email : req.body.email,
//     password : hashedPassword
//   },
//   function (err, user) {
//     if (err) return res.status(500).send("There was a problem registering the user.")
//     // create a token
//     const token = jwt.sign({ id: user._id }, config.secret, {
//       expiresIn: 86400 // expires in 24 hours
//     });
//     res.status(200).send({ auth: true, token: token });
//   }); 
// });

//LOGIN
router.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    !user && res.status(404).json("user not found");

    const validPassword = await bcrypt.compare(req.body.password, user.password)
    !validPassword && res.status(400).json("wrong password")

    const token = jwt.sign({ id: user._id }, config.secret, {
      expiresIn: 86400 // expires in 24 hours
    });
    res.status(200).json({ auth: true, token: token })
  } catch (err) {
    res.status(500).json(err)
  }
});

module.exports = router;
