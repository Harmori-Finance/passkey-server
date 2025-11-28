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
import * as config from './config/config'
import base64url from 'base64url'
import { Connection, LAMPORTS_PER_SOL, PublicKey, sendAndConfirmTransaction, SystemProgram, Transaction, TransactionMessage, VersionedTransaction } from '@solana/web3.js';
import { LazorkitClient } from './contract-integration/index';
import { bufferToBase64url, createProviderFromMnemonic, extractCompressedPubkey } from './utils';
import { BN } from 'bn.js';
import { sha256 } from 'js-sha256';
import { lookupTableAccount } from './contract-integration/alt';
import { RegisterController } from './controller/RegisterController';
import { SendTokenController } from './controller/SendTokenController';

const port = config.PORT;
const rpID = config.RPID;
const sha256_cert_fingerprints = config.SHA256_CERT_FINGERPRINTS

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

app.get('/user/info/smart-wallet', async (req, res) => {
  try {
    const { username } = req.query;
    const user = await User.findOne({ username: username })
    if (!user) {
      res.status(400).json({ error: 'user not yet register' })
    }
    res.status(200).json({ smartWallet: user.smartWallet })
  } catch (err: any) {
    console.log(err);
    res.status(500).json({ error: err.toString() })
  }
})

const registerController = new RegisterController();

app.post('/register/challenge', registerController.Challenge);
app.post('/register/verify', registerController.Verify);
app.post('/create-smart-wallet', registerController.CreateSmartWallet)

const sendTokenController = new SendTokenController();

app.post('/send-token/options', sendTokenController.Options)
app.post('/send-token/verify', sendTokenController.Verify)

app.listen(port, () => {
  console.log(`Server demo passkey running http://localhost:${port}`);
  console.log(`RP ID: ${rpID}`);
});