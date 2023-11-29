const express = require("express");
const bcrypt = require("bcrypt");
const db = require("./config/db");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const uuid = require("uuid");
const https = require("https");
const fs = require("fs");
// const winston = require("winston");
// const { Loggly } = require("winston-loggly");

const app = express();
const cookieParser = require("cookie-parser");
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ credentials: true, origin: "https://localhost:3002" }));
const PORT = process.env.PORT || 2001;

// ! Set X-Content-Type-Options header for preventing MIME sniffing
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  next();
});

// ! Set Content Security Policy (CSP) headers for Preventing XSS
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  next();
});

// ! Set Strict-Transport-Security header (HSTS) for enforcing HTTPS
app.use((req, res, next) => {
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains; preload"
  );
  next();
});

const logger = require("./logger");

app.post("/check-username", async (req, res) => {
  try {
    const { username } = req.body;
    const [result] = await db.query("SELECT * FROM Users WHERE username=?;", [
      username,
    ]);

    if (result.length > 0) {
      console.log("sup");
      return res.json({ message: "username is taken", isTaken: true });
    } else {
      return res.json({ isTaken: false });
    }
  } catch (error) {
    res.status(500).json({ message: "Issue occurred during check username!" });
  }
});

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    const [result] = await db.query("SELECT * FROM Users WHERE username=?;", [
      username,
    ]);

    if (result.length > 0) {
      return res.status(409).json({ message: "username is taken" });
    }

    // ! hashing password and store digest in the db
    let hashedPassword = await bcrypt.hash(password, 10);

    const [row] = await db.query(
      "INSERT INTO Users (username, user_password) VALUES (?, ?);",
      [username, hashedPassword]
    );

    if (row.affectedRows === 1) {
      logger.info(`user ${username} has successfully created an account!`);
      return res.status(201).json({ message: "User Created" });
    } else {
      logger.info(
        `user ${username} has attempted to create account unser an existing username`
      );
      return res.status(500).json({ message: "Unable to create account!" });
    }
  } catch (error) {
    logger.info(
      `user ${username} has failed to create account due to error occured`
    );
    res.status(500).json({ message: "Account was not created!" });
  }
});

// ! login
app.post("/", async (req, res) => {
  try {
    const { username, password } = req.body;
    const [row] = await db.query("SELECT * FROM Users WHERE username=?", [
      username,
    ]);

    if (row.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    // ! hashing password and compare the digest to the one in the database
    bcrypt.compare(password, row[0].user_password, (err, result) => {
      if (result) {
        // ! generate a secure, random session ID
        const sessionId = uuid.v4();
        const role = "user";
        const token = jwt.sign(
          { username, sessionId, role }, // ! RBAC
          process.env.SECRET_KEY,
          {
            expiresIn: "1h",
          }
        );
        res.cookie("token", token, {
          maxAge: 1000 * 60 * 60,
          httpOnly: true,
        });

        logger.info(`user ${username} has successfully logged in`);
        return res.status(200).json({
          message: "Login Successful",
          token: token,
          success: true,
          username: username,
          role: role,
        });
      } else {
        logger.info(`user ${username} has attempted to log in`);
        res.status(400).json({ message: "Wrong Username or password" });
      }
    });
  } catch (error) {
    logger.error(`user ${username} failed to log in due to error occurred`);
    res.status(500).json({ message: "There's an issue with login" });
  }
});

// Middleware to verify JWT and extract username
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized, No token found" });
  }

  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Unauthorized, wrong token" });
    }

    req.username = decoded.username;
    next();
  });
};

app.get("/profile", verifyToken, async (req, res) => {
  logger.info(
    `user ${req.username} has successfully accessed the profile page`
  );
  res.json({ message: `Hello ${req.username}`, username: req.username });
});

// server configuration with key cert for HSTS
const keyPath = "./key.pem"; // ! private key
const certPath = "./cert.pem"; // ! self-signed certificate

const options = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath),
};

const server = https.createServer(options, app);

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// app.listen(PORT, (err) => {
//   if (err) {
//     console.log(`Error occurred`);
//   } else {
//     console.log(`Listening on PORT ${PORT}`);
//   }
// });
