const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const sessions = {};

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const PORT = 3000;

// ===== RP CONFIG =====
const rpName = "CSE722 WebAuthn";
const rpID = "labibabdullah444.duckdns.org";
const origin = "https://labibabdullah444.duckdns.org";
 
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
        sessions[username] = true;
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
  const username = req.query.username;

  if (!sessions[username]) {
    return res.status(403).send("Access Denied");
  }

  res.send(`
    <h1>Welcome ${username}</h1>
    <p>You are successfully logged in using WebAuthn</p>
    <p>Authenticator: Windows Hello / Passkey</p>
  `);
});


app.listen(PORT, () => {
  console.log(`Server running on ${origin}`);
});



