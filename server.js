const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const session = require("express-session");
require("dotenv").config();

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const app = express();

app.use(cors());
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,

    cookie: {
      secure: false,
      httpOnly: true,
      sameSite: "lax",
    },
  })
);
app.use(express.static("public"));

const PORT = 3000;

// ===== RP CONFIG =====
const rpName = "CSE722 WebAuthn";
const rpID = "labibabdullah444.duckdns.org";
const origin = "https://labibabdullah444.duckdns.org";

// const rpName = "CSE722 WebAuthn";
// const rpID = "localhost";
// const origin = "http://localhost:3000";
 
// ===== TEMP DATABASE =====
const users = {};

// ================= REGISTER =================

app.post("/generate-registration-options", async (req, res) => {
  const { username } = req.body;

  users[username] = users[username] || {
    id: crypto.randomUUID(),
    username,
    devices: [],
  };

  const user = users[username];

  const options = await generateRegistrationOptions({
    rpName,
    rpID,

    userID: Buffer.from(user.id),
    userName: user.username,

    attestationType: "none",

    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
      authenticatorAttachment: "platform",
    },

    excludeCredentials: user.devices.map(device => ({
      id: device.credentialID,
      type: "public-key",
    })),
  });

  user.currentChallenge = options.challenge;

  res.json(options);
});

// VERIFY REGISTRATION

app.post("/verify-registration", async (req, res) => {
  const { username, credential } = req.body;

  const user = users[username];

  try {
    const verification = await verifyRegistrationResponse({
      response: credential,

      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      user.devices.push({
        credentialID: registrationInfo.credential.id,
        credentialPublicKey: registrationInfo.credential.publicKey,
        counter: registrationInfo.credential.counter,
        transports: credential.response.transports,
      });
    }

    res.json({ verified });
  } catch (err) {
    console.log(err);
    res.status(400).json({
      error: err.message,
    });
  }
});

// ================= LOGIN =================

app.post("/generate-authentication-options", async (req, res) => {
  const { username } = req.body;

  const user = users[username];

  if (!user) {
    return res.status(404).json({
      error: "User not found",
    });
  }

  const options = await generateAuthenticationOptions({
    rpID,

    allowCredentials: user.devices.map(device => ({
      id: device.credentialID,
      type: "public-key",
      transports: device.transports,
    })),

    userVerification: "preferred",
  });

  user.currentChallenge = options.challenge;

  res.json(options);
});

// VERIFY LOGIN

app.post("/verify-authentication", async (req, res) => {
  const { username, credential } = req.body;

  const user = users[username];

  const authenticator = user.devices.find(d =>
    d.credentialID === credential.id
  );

  try {
    //console.log(authenticator);
    const verification = await verifyAuthenticationResponse({
      response: credential,

      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,

      credential: {
        id: authenticator.credentialID,
        publicKey: authenticator.credentialPublicKey,
        counter: authenticator.counter,
        transports: authenticator.transports,
     },
    });

    const { verified, authenticationInfo } = verification;

    if (verified) {
        authenticator.counter = authenticationInfo.newCounter;
        req.session.username = username;
    }

    res.json({
      verified,
    });
    } catch (err) {
        console.log(err);

        res.status(400).json({
        error: err.message,
        });
    }
});


app.get("/dashboard", (req, res) => {
  if (!req.session.username) {
    return res.status(403).send("Access Denied");
  }

  const username = req.session.username;

  const user = users[username];

  const devicesHTML = user.devices.map((device, index) => {
    const transports = device.transports
      ? device.transports.join(", ")
      : "Unknown";

    return `
      <div style="margin-top:20px; text-align:left;">
        <h3>Authenticator ${index + 1}</h3>

        <p>
          <strong>Credential ID:</strong><br/>
          ${device.credentialID}
        </p>

        <p>
          <strong>Transport:</strong>
          ${transports}
        </p>

        <p>
          <strong>Signature Counter:</strong>
          ${device.counter}
        </p>
      </div>
    `;
  }).join("");

  res.send(`
  <!DOCTYPE html>
  <html>
  <head>
    <title>Dashboard</title>

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <style>
      body {
        font-family: Arial;
        margin: 0;
        min-height: 100vh;

        display: flex;
        justify-content: center;
        align-items: center;

        padding: 20px;
      }

      .box {
        border: 1px solid #ddd;

        border-radius: 10px;

        padding: 30px;

        width: 100%;
        max-width: 500px;

        text-align: center;
      }

      button {
        padding: 10px 20px;

        cursor: pointer;

        margin-top: 20px;
      }

      p {
        word-wrap: break-word;
      }

      @media (max-width: 480px) {
        .box {
          padding: 20px;
        }
      }
    </style>
  </head>

  <body>

    <div class="box">

      <h2>Protected Dashboard</h2>

      <p>
        You are successfully authenticated using WebAuthn.
      </p>

      <p>
        <strong>Username:</strong>
        ${username}
      </p>

      ${devicesHTML}

      <button onclick="window.location='/logout'">
        Logout
      </button>

    </div>

  </body>
  </html>
  `);
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});


app.listen(PORT, () => {
  console.log(`Server running on ${origin}`);
});



