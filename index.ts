import express from 'express';
import cors from 'cors';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import Credential from './model/Credential.js';
import User from './model/User.js';
import mongoose from 'mongoose';
import * as config from './config.js'
import path from "path";
import { fileURLToPath } from "url";

const rpName = 'Passkey Demo App';
const rpID = 'unmumbling-untechnical-andera.ngrok-free.dev';
const port = 8888;
const origin = `https://${rpID}`;

mongoose.connect(config.MONGO_URL, {
  dbName: config.MONGO_DB_NAME,
  user: config.MONGO_USERNAME,
  pass: config.MONGO_PASSWORD
})
  .then(() => console.log("MongoDB connected successfully"))
  .catch((err) => console.log("MongoDB error: ", err))

const app = express();
app.use(express.json());
app.use(cors());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use("/.well-known", express.static(path.join(__dirname, "public/.well-known")));

app.post('/generate-registration-options', async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ error: 'Missing userId' });
  }

  const userCredentials = await Credential.find({ userId: userId });

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: userId,
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: "required",
      residentKey: 'preferred',
    },
    excludeCredentials: userCredentials.map(cred => ({
      id: cred.id,
      type: 'public-key',
    })),
  });

  await User.findOneAndUpdate(
    { id: userId },
    { currentChallenge: options.challenge },
    { upsert: true }
  )

  res.status(200).json(options);
});

app.post('/verify-registration', async (req, res) => {
  const { userId, credential } = req.body;

  const user = await User.findOne({ id: userId })

  if (!user || !user.currentChallenge) {
    return res.status(400).json({ error: 'User not found or no challenge' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });

    if (verification.verified && verification.registrationInfo) {
      const { id: credentialID, publicKey: credentialPublicKey, counter } = verification.registrationInfo.credential;

      const newCredential = {
        id: credentialID,
        publicKey: Buffer.from(credentialPublicKey).toString('base64url').toString(),
        counter,
        userId: user.id,
      };

      await Credential.findOneAndUpdate(
        { id: newCredential.id },
        newCredential,
        { upsert: true }
      )

      await User.findOneAndUpdate(
        { id: userId },
        { currentChallenge: null },
        { upsert: true }
      )

      return res.status(200).json({ verified: true });
    }

    res.status(400).json({ error: 'Verification failed' });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/generate-authentication-options', async (req, res) => {
  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: [],
    userVerification: 'preferred',
  });

  (app as any).currentChallenge = options.challenge;

  res.status(200).json(options);
});

app.post('/verify-authentication', async (req, res) => {
  const { credential } = req.body;

  const expectedChallenge = (app as any).currentChallenge;

  if (!expectedChallenge) {
    return res.status(400).json({ error: 'No challenge found' });
  }

  const savedCredential = await Credential.findOne({ id: credential.id });

  if (!savedCredential) {
    return res.status(400).json({ error: 'Credential not found' });
  }

  const user = await User.findOne({ id: savedCredential.userId })
  if (!user) {
    return res.status(400).json({ error: 'User for credential not found' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: savedCredential.id,
        publicKey: Buffer.from(savedCredential.publicKey, 'base64url'),
        counter: savedCredential.counter,
      },
      requireUserVerification: true,
    });

    if (verification.verified) {
      savedCredential.counter = verification.authenticationInfo.newCounter;
      await Credential.findOneAndUpdate(
        { id: savedCredential.id },
        savedCredential,
        { upsert: true }
      )

      delete (app as any).currentChallenge;

      return res.json({ verified: true, user: { id: user.id } });
    }

    res.status(400).json({ error: 'Login verification failed' });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server demo passkey đang chạy tại http://localhost:${port}`);
  console.log(`RP ID: ${rpID}`);
  console.log(`Origin: ${origin}`);
});