require("dotenv").config();
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const massive = require("massive");

const app = express();

app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

massive(CONNECTION_STRING).then(db => {
  app.set("db", db);
});

app.post("/auth/signup", (req, res, next) => {
  const { email, password } = req.body;
  const db = req.app.get("db");
  db.check_user_exists(email).then(user => {
    if (user.length) {
      res.status(403).send("Nice try Sean!");
    } else {
      const saltRounds = 12;
      bcrypt.genSalt(saltRounds).then(generatedSalt => {
        bcrypt.hash(password, generatedSalt).then(hashedPassword => {
          db.create_user([email, hashedPassword]).then(([createdUser]) => {
            req.session.user = {
              id: createdUser.id,
              email: createdUser.email
            };
            res.status(200).send(req.session.user);
          });
        });
      });
    }
  });
});

app.post("/auth/login", async (req, res, next) => {
  const db = req.app.get("db");
  const { email, password } = req.body;

  const foundUser = await db.check_user_exists(email);
  if (!foundUser) {
    res.status(400).send("Nice try again Sean, you ain't getting in my app");
  } else {
    const authenticated = await bcrypt.compare(password, foundUser[0].user_password);
    if (authenticated) {
      req.session.user = {
        id: foundUser[0].id,
        email: foundUser[0].email
      };
      res.status(200).send(req.session.user);
    } else {
      res.status(403).send("I SAID NO SEAN!!!!!");
    }
  }
});

app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
