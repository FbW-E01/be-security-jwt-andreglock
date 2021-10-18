import express from "express";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import dotenv from 'dotenv';

// This makes a very secure random secret with every app reboot
const secret = crypto.randomBytes(64).toString("hex");
dotenv.config();
console.log({ secret });
const users = [
  { username: "Veera cat", password: process.env.VERA_PASS},
  { username: "Linda", password: process.env.LINDA_PASS}
]

// This middleware can be used to check if a request contains a valid token
function checkTokenMiddleware(req, res, next) {
  const tokenRaw = req.headers.authorization;
  console.log(`Token raw is: "${tokenRaw}""`);
  if (!tokenRaw) {
    return res.sendStatus(401);
  }

  const tokenToCheck = tokenRaw.split(" ")[1];
  console.log(`Token to check is: "${tokenToCheck}"`);
  if (!tokenToCheck) {
    return res.sendStatus(401);
  }

  jwt.verify(tokenToCheck, secret, (error, payload) => {
    console.log({ error, payload });

    if (error) {
      return res.status(400).send(error.message);
    }

    req.userData = {
      userId: payload.userId,
      username: payload.username,
      admin: payload.admin,
    };
    next();
  });
}

// Setup Express application
const app = express();
app.use(express.json());

// This endpoint returns a fresh token
app.get("/token", (req, res) => {
  // TODO: Check login username / password somehow
  if(!req.body.username) {
    res.status(400).send("Please provide an username")
  }
  if(!req.body.password) {
    res.status(400).send("Please provide a password")
  }
  const user = users.find(u => u.username === req.body.username);
  if(!user) {
    res.status(401).send("User not found")
  } else if (user.password !== req.body.password) {
    res.status(401).send("Incorrect password")
  }

  const payload = { userId: 42, username: user.username, admin: true };
  const options = { expiresIn: "5m" };
  const token = jwt.sign(payload, secret, options);
  res.send(token);
});

// This endpoint is secured; only requests with a valid token can access it
app.get("/secure", checkTokenMiddleware, (req, res) => {
  // check token and return something
  res.send(`Hooray, ${req.userData.username}, you have access`);
});

const port = 8000;
app.listen(port, () => {
  console.log("Listening on http://localhost:" + port);
});
