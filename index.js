const dotenv = require('dotenv');
const mongoose = require('mongoose');
const express = require('express');
const app = express();

//Import Routes
const authRoute = require('./routes/auth');
const postsRoute = require('./routes/posts');

dotenv.config();

//Connect to database
mongoose.connect(process.env.DB_CONNECT,
    { useNewUrlParser: true, useUnifiedTopology: true },
    () => console.log('Connected to database!')
);

//Middleware
app.use(express.json());

//Routes Middlewares
app.use('/api/user', authRoute);
app.use('api/posts', postsRoute)

app.listen(3000, () => console.log('Connected to server!'));