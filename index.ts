import express from 'express';
import cors from 'cors';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import Credential from './model/Credential';
import User from './model/User';
import mongoose from 'mongoose';
import * as config from './config'
import base64url from 'base64url'
import { Connection, sendAndConfirmTransaction } from '@solana/web3.js';
import { LazorkitClient } from './contract-integration/index';
import { createProviderFromMnemonic, extractCompressedPubkey } from './utils';
// import path from "path";
// import { fileURLToPath } from "url";

const port = 8888;
const rpName = 'android_app';
const rpID = 'unmumbling-untechnical-andera.ngrok-free.dev';
const sha256_cert_fingerprints = "22:AD:AA:BF:2D:F3:72:D2:30:26:60:0A:72:18:1F:79:6C:DD:BE:D3:F7:FE:A4:DC:11:A5:19:0B:D5:E1:32:C3"

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

// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);

// app.use("/.well-known", express.static(path.join(__dirname, "public/.well-known")));

app.get('/.well-known/assetlinks.json', (_req, res) => {
  res.setHeader('Content-Type', 'application/json');

  const assetLinks = [
    {
      "relation": [
        "delegate_permission/common.handle_all_urls",
        "delegate_permission/common.get_login_creds"
      ],
      "target": {
        "namespace": "android_app",
        "package_name": "com.anonymous.cryptobank",
        "sha256_cert_fingerprints": [
          sha256_cert_fingerprints
        ]
      }
    }
  ];

  res.json(assetLinks);
});

app.post('/register/challenge', async (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Missing username' });
  }

  const userCredentials = await Credential.find({ username: username });

  const optionsGen = await generateRegistrationOptions({
    rpName,
    rpID,
    userDisplayName: username,
    userName: username,
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

  const options: any = {
    challenge: optionsGen.challenge,
    user: optionsGen.user,
    rp: optionsGen.rp,
    authenticatorSelection: {
      userVerification: "required",
      residentKey: "required",
    },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
  }

  await User.findOneAndUpdate(
    { username: username },
    { currentChallenge: options.challenge },
    { upsert: true }
  )

  res.status(200).json(options);
});

app.post('/register/verify', async (req, res) => {
  const { username, credential } = req.body;

  const user = await User.findOne({ username: username })

  if (!user || !user.currentChallenge) {
    return res.status(400).json({ error: 'User not found or no challenge' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: [
        `https://${rpID}`,
        `android:apk-key-hash:${base64url(Buffer.from(sha256_cert_fingerprints.replace(/:/g, ''), 'hex'))}`
      ],
      expectedRPID: rpID,
      requireUserVerification: true,
    });

    if (verification.verified && verification.registrationInfo) {
      const { id: credentialID, publicKey: credentialPublicKey, counter } = verification.registrationInfo.credential;

      const newCredential = {
        id: credentialID,
        publicKey: Buffer.from(credentialPublicKey).toString('base64url').toString(),
        counter,
        username: username,
      };

      await Credential.findOneAndUpdate(
        { id: newCredential.id },
        newCredential,
        { upsert: true }
      )

      await User.findOneAndUpdate(
        { username: username },
        { currentChallenge: null },
        { upsert: true }
      )

      return res.status(200).json({ verified: true });
    }

    res.status(400).json({ error: 'Verification failed' });
  } catch (error: any) {
    console.log(error);
    res.status(500).json({ error: error.toString() });
  }
});

app.post('/create-smart-wallet', async (req, res) => {
  try {
    const { username } = req.body;

    const credential = await Credential.findOne({ username: username });

    if (!credential) {
      res.status(400).json({ error: "User credential not exist" });
    }

    const provider = await createProviderFromMnemonic(config.MNEMONIC, config.RPC_URL_SOLANA)
    const connection = new Connection(config.RPC_URL_SOLANA);
    const lazorkitClient = new LazorkitClient(connection);
    const { transaction,
      smartWalletId,
      smartWallet
    } = await lazorkitClient.createSmartWalletTransaction({
      payer: provider.keypair.publicKey,
      credentialIdBase64: credential.id,
      passkeyPubkey: extractCompressedPubkey(credential.publicKey) as any,
    });

    console.log(smartWallet, smartWalletId)

    transaction.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
    transaction.feePayer = provider.keypair.publicKey;

    transaction.sign(provider.keypair);

    const txid = await sendAndConfirmTransaction(connection, transaction, [provider.keypair]);
    console.log("Sent create-smart-wallet:", txid);

    await User.findOneAndUpdate(
      { username: username },
      { smartWallet: String(smartWallet), smartWalletId: Number(smartWalletId) }
    )
    res.status(200).json({ message: 'ok' })
  } catch (err: any) {
    console.log(err);
    res.status(500).json({ message: 'vcl' })
  }
})

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

  const user = await User.findOne({ username: savedCredential.username })
  if (!user) {
    return res.status(400).json({ error: 'User for credential not found' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: expectedChallenge,
      expectedOrigin: [
        `https://${rpID}`,
        `android:apk-key-hash:${base64url(Buffer.from(sha256_cert_fingerprints.replace(/:/g, ''), 'hex'))}`
      ],
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
});