import { Request, Response } from "express";
import Credential from "../model/Credential";
import { generateRegistrationOptions, verifyRegistrationResponse } from "@simplewebauthn/server";
import User from "../model/User";
import * as config from '../config/config'
import base64url from "base64url";
import { createProviderFromMnemonic, extractCompressedPubkey } from "../utils";
import { Connection, LAMPORTS_PER_SOL, sendAndConfirmTransaction, Transaction } from "@solana/web3.js";
import { LazorkitClient } from "../contract-integration";
import { BN } from "bn.js";

const rpName = 'android_app';
const rpID = config.RPID;
const sha256_cert_fingerprints = config.SHA256_CERT_FINGERPRINTS
const init_amount_sw = config.INIT_AMOUNT_SMART_WALLET

export class RegisterController {
  constructor() {
    this.Challenge = this.Challenge.bind(this)
    this.Verify = this.Verify.bind(this)
    this.CreateSmartWallet = this.CreateSmartWallet.bind(this)
  }

  public async Challenge(req: Request, res: Response) {
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
  }

  public async Verify(req: Request, res: Response) {
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
  }

  public async CreateSmartWallet(req: Request, res: Response) {
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
          amount: new BN(init_amount_sw * LAMPORTS_PER_SOL)
        },
        {
          useVersionedTransaction: false
        }
      );

      transaction = transaction as Transaction;

      transaction.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
      transaction.feePayer = provider.keypair.publicKey;

      transaction.sign(provider.keypair);

      const txid = await sendAndConfirmTransaction(connection, transaction, [provider.keypair]);
      console.log("Sent create-smart-wallet:", txid);

      await User.findOneAndUpdate(
        { username: username },
        { smartWallet: String(smartWallet), smartWalletId: Number(smartWalletId) }
      )
      res.status(200).json({ smartWallet: smartWallet, txId: txid })
    } catch (err: any) {
      console.log(err);
      res.status(500).json({ error: err.toString() })
    }
  }
}