const express = require('express');
const database = require('./database');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const recaptcha = require('recaptcha2');
const recaptchaVerify = require('recaptcha-verify');
const fetch = require('node-fetch');
var request = require("request");
const session = require("express-session")
const filestore = require("session-file-store")(session)
const path = require("path")
const cookieParser = require('cookie-parser');


dotenv.config({ path: './.env' });

const port = process.env.PORT;
console.log("Port:", port);

const app = express();
const router = express.Router();
app.use(cors());
app.use(cookieParser());

// app.use(session({
//   name: "session-id",
//   secret: "GFGEnter", // Secret key,
//   saveUninitialized: false,
//   resave: false,
//   store: new filestore()
// }))

// // Asking for the authorization
// function auth(req, res, next) {
//   // Checking for the session
//   console.log(req.session)

//   // Checking for the authorization
//   if (!req.session.user) {
//     var authHeader = req.headers.authorization;
//     console.log(authHeader);
//     var err = new Error("You are not authenticated")
//     res.setHeader("WWW-Authenticate", "Basic")
//     err.status = 401
//     next(err)

//     var auth = new Buffer.from(authHeader.split(' ')[1],
//       "base64").toString().split(":")

//     // Reading username and password
//     var username = auth[0]
//     var password = auth[1]
//     if (username == "admin2" && password == "password") {
//       req.session.user = "admin2"
//       next()
//     }
//     else {
//       // Retry incase of incorrect credentials
//       var err = new Error('You are not authenticated!');
//       res.setHeader("WWW-Authenticate", "Basic")
//       err.status = 401;
//       return next(err);
//     }
//   }
//   else {
//     if (req.session.user === "admin2") {
//       next()
//     }
//     else {
//       var err = new Error('You are not authenticated!');
//       res.setHeader("WWW-Authenticate", "Basic")
//       err.status = 401;
//       return next(err);
//     }
//   }
// }

// Middlewares
// app.use(auth)
// app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "font-src 'self'");
  next();
});

app.use(bodyParser.json());

app.use(bodyParser.urlencoded({ extended: true }));

// res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

database.connect();

app.get('/', (req, res) => {
  res.send('Hello, World!');
});

app.get('/alluser', (req, res) => {
  database.alluser().then((users) => {
    console.log("From /alluser :", users);
    res.send(users);
  });
});

app.post('/users', (req, res) => {
  // code to retrieve a list of users from the database and send it as a response
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  const users = { user: "test", password: "lol" };
  database.insertUser(users);
  console.log("Inserted user:", users);
  // res.send("Inserted user:", users);

});

app.post('/login', async (req, res) => {
  console.log(req.params)
  console.log("username : ", req.body.username)
  console.log("password : ", req.body.password)
  console.log("rechapha : ", req.body.recaptcha)
  console.log("ip : ", req.ip)
  const username = req.body.username;
  const password = req.body.password;
  console.log("username on /login : ", username)
  // Retrieve the user from the database by their username
  const user = await database.getUserByUsername(username);

  console.log("checking from database :" + user)
  console.log("/login checking " + username)

  if (user == null) {
    res.json({ success: false, message: 'Incorrect username or password' });
    console.log(req.body.username, "No username found");
    // console.log(res)
    return;
  }

  if (user.username != username) {
    res.json({ success: false, message: 'Incorrect username or password' });
    console.log(req.body.username, "Incorrect username");
    // console.log(res)
    return;
  }
  // Check if the password is correct using bcrypt
  const isPasswordCorrect = await bcrypt.compare(password,
    user.password);
  if (!isPasswordCorrect) {
    res.json({ success: false, message: 'Incorrect username or password' });
    console.log(req.body.username, "Incorrect password");
    return;
  }
  // Verify the reCAPTCHA response
  const recaptchaResponse = req.body.recaptcha;
  console.log("recaptcha secret key = ", process.env.KEY)

  // const REcaptcha = new recaptcha({
  //   siteKey: recaptchaResponse,
  //   secretKey: process.env.KEY, // Replace this with your reCAPTCHA secret key
  //   ssl: true
  // });

  try {
    request.post({
      url: 'https://www.google.com/recaptcha/api/siteverify',
      form: {
        secret: process.env.KEY,
        response: recaptchaResponse
      }
    }, (err, httpResponse, body) => {
      console.log(body)
      const bodyObject = JSON.parse(body);
      console.log("SUCCESS:", bodyObject.success);
      if (err) {
        console.error('Error:', err);
        return;
      }
      if (bodyObject.success == true) {
        res.json({ success: true, message: 'Valid reCAPTCHA' });
        console.log("Valid reCAPTCHA")
        res.cookie('username', req.body.username , { maxAge: 900000, httpOnly: true });

        return;
      }
      else {
        res.json({ success: false, message: 'Invalid reCAPTCHA' });
        console.log("Invalid reCAPTCHA")
        return;
      }
    });
  } catch (error) {
    console.error(error);
    // code to run if there are any problems
  }

});

app.post('/register', async (req, res) => {

  console.log("registering user : ", req.body.username + " " + req.body.password);
  console.log("data : ", req.body)
  const result = await database.getUserByUsername(req.body.username);
  console.log("result : ", result)
  console.log("result is null")

  if (result) {
    console.log("Username already exists");
    res.json({ success: false, message: 'Username already exists' });
    console.log("LOL");
    return;
  }
  let data = {
    username: req.body.username,
    password: req.body.password,
    name: req.body.name,
    matrix: req.body.matrix,
    email: req.body.email,
    phone: req.body.phone,
    address: req.body.address
  }

  console.log("USER DATA THAT WILL BE INSERTED : ", data)

  console.log("user Register : ", req.body.username);

  const recaptchaResponse = req.body.recaptcha;
  console.log("recaptcha secret key = ", process.env.KEY2)

  try {
    request.post({
      url: 'https://www.google.com/recaptcha/api/siteverify',
      form: {
        secret: process.env.KEY2,
        response: recaptchaResponse,
      }
    }, async (err, httpResponse, body) => {
      console.log(body)
      const bodyObject = JSON.parse(body);
      console.log("SUCCESS:", bodyObject.success);
      if (err) {
        console.error('Error:', err);
        return;
      }
      if (bodyObject.success == true) {

        const user = await database.registerUser(data);
        console.log("user Registered: ", user)
        console.log("Valid reCAPTCHA")
        res.json({ success: true, message: 'Valid reCAPTCHA and User registered' });
        return;
      }
      else {
        res.json({ success: false, message: 'Invalid reCAPTCHA' });
        console.log("Invalid reCAPTCHA")
        return;
      }
    });
  } catch (error) {
    console.error(error);
    // code to run if there are any problems
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('username');
  res.redirect('/login');
});

app.post('/use', (req, res) => {
  const user = req.body;
  database.insertUser(user).then(() => {
    res.send('User inserted into the database');
  });
});

app.put('/users/:id', (req, res) => {
  // code to update a user in the database and send a response
});

app.delete('/users/:id', (req, res) => {
  // code to delete a user from the database and send a response
});

app.use('/api', router);

app.listen(3000, () => {
  console.log('Server is listening on port ' + port);
});