const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
var nodemailer = require('nodemailer');
const verify = require('../routes/verifyToken');
const User = require('../models/User');
const { registerValidation, loginValidation } = require('../validation');

router.post('/register', verify, async (req, res) => {
    try {
        
        //Validate Registration
        const validation = registerValidation(req.body);

        if (validation.error)
            return res.status(400).send(validation.error.details[0].message);

        const emailExists = await User.findOne({ email: req.body.email });
        if (emailExists)
            return res.status(400).send('Email already registered.');

        //Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);
        const user = new User({
            name: req.body
            .name,
            email: req.body
            .email,
            password: hashedPassword
        });

        const savedUser = await user.save();
        res.send(savedUser);

    } catch (err) {
        res.status(400).send(err);
    }
});

router.post('/email', async (req, res) => {
    try {
        var transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'email@email.com', //Change this infos before submit
                pass: 'teste1234'
            }
        });

        var mailOptions = {
            from: 'email@email.com', //Change this infos before submit
            to: req.body.mailTo,
            subject: req.body.subject,
            text: req.body.text
        };

        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                res.status(400).send(error);
            } else {
                res.status(200).send('Email sent: ' + info.response);
            }
        });

    } catch (err) {
        res.status(400).send(err);
    }
});

//Login validation
router.post('/login', async (req, res) => {
    try {
        var validation = loginValidation(req.body);

        if (validation.error)
            return res.status.send(validation.error.details[0].message);

        const correspondingUser = await User.findOne({ email: req.body.email });
        if (!correspondingUser) {
            return res.status(400).send('Email or password is wrong.');
        }

        const validPass = await bcrypt.compare(req.body.password, correspondingUser.password);
        if (!validPass) {
            return res.status(400).send('Email or password is wrong.')
        }

        //Create token
        const token = jwt.sign({ _id: correspondingUser._id }, process.env.TOKEN_SECRET);
        res.header('auth-token', token).send(token);

    } catch (err) {

    }
});

router.get('/all', async (req, res) => {
    try {
        User.find(function (err, users) {
            if (err)
                res.status(400).send(err);

            res.send(users);
        })
    } catch (err) {

    }
})

router.get('/getById/:id', async (req, res) => {
    try {
        var id = req.params.id;
        var user = await User.findOne({ _id: id })
        res.send(user);

    } catch (err) {
        res.status(400).send(err);
    }
})

router.put('/update', async (req, res) => {
    try {
        var id = req.body.id;
        var user = await User.findOne({ _id: id });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);

        user.password = hashedPassword;
        user.name = req.body.name;
        user.email = req.body.email;
        res.send(user);

    } catch (err) {
        res.status(400).send(err.message);
    }
})

module.exports = router;