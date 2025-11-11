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
import { Connection, LAMPORTS_PER_SOL, PublicKey, sendAndConfirmTransaction, SystemProgram, Transaction } from '@solana/web3.js';
import { LazorkitClient } from './contract-integration/index';
import { createProviderFromMnemonic, extractCompressedPubkey } from './utils';
import { BN } from 'bn.js';

const port = 8888;
const rpName = 'android_app';
const rpID = 'unmumbling-untechnical-andera.ngrok-free.dev';
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
    let { transaction,
      smartWalletId,
      smartWallet
    } = await lazorkitClient.createSmartWalletTxn(
      {
        payer: provider.keypair.publicKey,
        credentialIdBase64: credential.id,
        passkeyPublicKey: extractCompressedPubkey(credential.publicKey) as any,
        amount: new BN(0)
      },
      {
        useVersionedTransaction: false
      }
    );

    transaction = transaction as Transaction;
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

app.post('/send-SOL/options', async (req, res) => {
  const { username } = req.body;

  const user = await User.findOne({ username: username })
  const userCredentials = await Credential.find({ username: username })

  if (userCredentials.length === 0) res.status(400).json({ error: 'not credential' })

  const provider = await createProviderFromMnemonic(config.MNEMONIC, config.RPC_URL_SOLANA)
  const connection = new Connection(config.RPC_URL_SOLANA);
  const lazorkitClient = new LazorkitClient(connection);

  const message = await lazorkitClient.buildAuthorizationMessage({
    payer: provider.keypair.publicKey,
    smartWallet: new PublicKey(user.smartWallet),
    passkeyPublicKey: extractCompressedPubkey(userCredentials[0].publicKey) as any,
    action: {
      type: 'execute_transaction',
      args: {
        policyInstruction: null,
        cpiInstruction: SystemProgram.transfer({
          fromPubkey: new PublicKey(user.smartWallet),
          toPubkey: new PublicKey('MTSLZDJppGh6xUcnrSSbSQE5fgbvCtQ496MqgQTv8c1'),
          lamports: 0.1 * LAMPORTS_PER_SOL,
        }),
      },
    } as any
  })

  let allowCredentials: any[] = [];
  for (let cred of userCredentials) {
    allowCredentials.push({
      id: cred.id,
      transports: ['internal']
    })
  }

  const optionsGen = await generateAuthenticationOptions({
    rpID,
    allowCredentials,
    userVerification: 'preferred',
    challenge: message.toString(),
    timeout: 60000
  })

  const options = {
    challenge: optionsGen.challenge,
    timeout: optionsGen.timeout,
    rpId: optionsGen.rpId,
    allowCredentials: optionsGen.allowCredentials,
    userVerification: optionsGen.userVerification,
  }

  await User.findOneAndUpdate(
    { username: username },
    { currentChallenge: options.challenge }
  )

  res.status(200).json(options)
})

app.post('/send-SOL/verify', async (req, res) => {
  const { credential } = req.body;

  const savedCredential = await Credential.findOne({ id: credential.id });

  if (!savedCredential) {
    return res.status(400).json({ error: 'Credential not found' });
  }

  const user = await User.findOne({ username: savedCredential.username })
  if (!user) {
    return res.status(400).json({ error: 'User for credential not found' });
  }

  const expectedChallenge = user.currentChallenge;

  if (!expectedChallenge) {
    return res.status(400).json({ error: 'No challenge found' });
  }


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

  if (!verification.verified) res.status(400).json({ error: "not verify" })

  const provider = await createProviderFromMnemonic(config.MNEMONIC, config.RPC_URL_SOLANA)
  const connection = new Connection(config.RPC_URL_SOLANA);
  const lazorkitClient = new LazorkitClient(connection);

  // const transaction = await lazorkitClient.executeTransactionWithAuth({
  //   payer: provider.keypair.publicKey,
  //   smartWallet: new PublicKey(user.smartWallet),
  //   passkeySignature: {
  //     passkeyPubkey: extractCompressedPubkey(savedCredential.publicKey) as any,
  //     signature64: credential.response.signature,
  //     clientDataJsonRaw64: credential.response.clientDataJSON,
  //     authenticatorDataRaw64: credential.response.authenticatorData,
  //   },
  //   policyInstruction: null,
  //   cpiInstruction: SystemProgram.transfer({
  //     fromPubkey: new PublicKey(user.smartWallet),
  //     toPubkey: new PublicKey('MTSLZDJppGh6xUcnrSSbSQE5fgbvCtQ496MqgQTv8c1'),
  //     lamports: 0.1 * LAMPORTS_PER_SOL,
  //   })
  // })

  // console.log(provider.keypair.secretKey)
  // transaction.sign([provider.keypair]);

  // const signature = await connection.sendTransaction(transaction, {
  //   skipPreflight: false,
  //   maxRetries: 3,
  // });

  // console.log("Signature:", signature);

  res.status(200).json({ message: 'ok' })
})

app.listen(port, () => {
  console.log(`Server demo passkey đang chạy tại http://localhost:${port}`);
  console.log(`RP ID: ${rpID}`);
});