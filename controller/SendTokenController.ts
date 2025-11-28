import { Request, Response } from "express";
import User from "../model/User";
import Credential from "../model/Credential";
import { bufferToBase64url, createProviderFromMnemonic, extractCompressedPubkey } from "../utils";
import { Connection, LAMPORTS_PER_SOL, PublicKey, SystemProgram, TransactionInstruction, TransactionMessage, VersionedTransaction } from "@solana/web3.js";
import { LazorkitClient } from "../contract-integration";
import * as config from '../config/config'
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import base64url from "base64url";
import { BN } from "bn.js";
import { addAddressToAlt, lookupTableAccount } from "../contract-integration/alt";
import { ASSOCIATED_TOKEN_PROGRAM_ID, createAssociatedTokenAccountInstruction, createTransferInstruction, getAssociatedTokenAddress, TOKEN_PROGRAM_ID } from "@solana/spl-token";
import { symbolToMint } from "../config/constant";
import { web3 } from "@coral-xyz/anchor";

const rpID = config.RPID;
const sha256_cert_fingerprints = config.SHA256_CERT_FINGERPRINTS

export class SendTokenController {
  constructor() {
    this.createUnifiedTransferInstruction = this.createUnifiedTransferInstruction.bind(this);
    this.Options = this.Options.bind(this);
    this.Verify = this.Verify.bind(this);
  }

  public async createUnifiedTransferInstruction(
    fromWallet: PublicKey,
    toWallet: PublicKey,
    mint: PublicKey,
    amount: number
  ): Promise<TransactionInstruction> {
    if (mint.equals(SystemProgram.programId)) {
      const lamports = Math.round(amount * 1_000_000_000);
      if (lamports <= 0) throw new Error('Amount must be > 0');

      return SystemProgram.transfer({
        fromPubkey: fromWallet,
        toPubkey: toWallet,
        lamports,
      })
    }

    const provider = await createProviderFromMnemonic(config.MNEMONIC, config.RPC_URL_SOLANA)

    const accountInfo = await provider.connection.getParsedAccountInfo(mint);
    if (!accountInfo.value) throw new Error(`Mint not found: ${mint.toBase58()}`);
    const decimals = (accountInfo.value.data as any).parsed.info.decimals;

    const amountInUnits = BigInt(Math.round(amount * 10 ** decimals));
    if (amountInUnits <= 0) throw new Error('Amount must be > 0');

    const fromATA = await getAssociatedTokenAddress(mint, fromWallet, true);
    const toATA = await getAssociatedTokenAddress(mint, toWallet, true);

    const toAccountInfo = await provider.connection.getAccountInfo(toATA);
    if (!toAccountInfo) {
      const provider = await createProviderFromMnemonic(config.MNEMONIC, config.RPC_URL_SOLANA)
      const ix = createAssociatedTokenAccountInstruction(
        fromWallet,
        toATA,
        toWallet,
        mint,
        TOKEN_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID
      )
      const tx = new web3.Transaction().add(ix);
      tx.recentBlockhash = (await provider.connection.getLatestBlockhash()).blockhash;
      tx.feePayer = provider.wallet.publicKey;
      const sig = await provider.provider.sendAndConfirm(tx);
      console.log("Create toAccountInfo:", sig);
    }

    return createTransferInstruction(
      fromATA,
      toATA,
      fromWallet,
      amountInUnits,
      [],
      TOKEN_PROGRAM_ID
    )

  }

  public async Options(req: Request, res: Response) {
    const { username, symbol, amount, toAddress } = req.body;

    const user = await User.findOne({ username: username })
    const userCredentials = await Credential.find({ username: username })

    if (userCredentials.length === 0) res.status(400).json({ error: 'not credential' })

    const provider = await createProviderFromMnemonic(config.MNEMONIC, config.RPC_URL_SOLANA)
    const connection = new Connection(config.RPC_URL_SOLANA);
    const lazorkitClient = new LazorkitClient(connection);

    const cpiInstruction = await this.createUnifiedTransferInstruction(
      new PublicKey(user.smartWallet),
      new PublicKey(toAddress),
      symbolToMint[symbol],
      amount
    )
    const timestamp = Math.floor(Date.now() / 1000);
    const message = await lazorkitClient.buildAuthorizationMessage({
      payer: provider.keypair.publicKey,
      smartWallet: new PublicKey(user.smartWallet),
      passkeyPublicKey: extractCompressedPubkey(userCredentials[0].publicKey) as any,
      action: {
        type: 'execute',
        args: {
          policyInstruction: null,
          // cpiInstruction: SystemProgram.transfer({
          //   fromPubkey: new PublicKey(user.smartWallet),
          //   toPubkey: new PublicKey(toAddress),
          //   lamports: Number(amount) * LAMPORTS_PER_SOL,
          // }),
          cpiInstruction: cpiInstruction
        },
      } as any,
      timestampExecute: timestamp
    })

    let allowCredentials: any[] = [];
    for (let cred of userCredentials) {
      allowCredentials.push({
        id: cred.id,
        transports: ['internal']
      })
    }

    const options = {
      challenge: bufferToBase64url(message),
      timeout: 60000,
      rpId: rpID,
      allowCredentials: allowCredentials,
      userVerification: 'preferred',
    }

    console.log('challenge send token: ', options.challenge)

    await User.findOneAndUpdate(
      { username: username },
      {
        currentChallenge: options.challenge,
        executeData: {
          timestamp: timestamp,
          type: 'send-token',
          symbol: symbol,
          amount: amount,
          toAddress: toAddress
        }
      }
    )

    res.status(200).json(options)
  }

  public async Verify(req: Request, res: Response) {
    try {
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

      const cpiInstruction = await this.createUnifiedTransferInstruction(
        new PublicKey(user.smartWallet),
        new PublicKey(user.executeData.toAddress),
        symbolToMint[user.executeData.symbol],
        user.executeData.amount
      )
      let ins = await lazorkitClient.executeIns(
        {
          payer: provider.keypair.publicKey,
          smartWallet: new PublicKey(user.smartWallet),
          passkeySignature: {
            passkeyPublicKey: extractCompressedPubkey(savedCredential.publicKey) as any,
            signature64: credential.response.signature,
            clientDataJsonRaw64: credential.response.clientDataJSON,
            authenticatorDataRaw64: credential.response.authenticatorData,
            signCount: credential.response.signCount
          },
          policyInstruction: null,
          // cpiInstruction: SystemProgram.transfer({
          //   fromPubkey: new PublicKey(user.smartWallet),
          //   toPubkey: new PublicKey(user.executeData.toAddress),
          //   lamports: Number(user.executeData.amount) * LAMPORTS_PER_SOL,
          // }),
          cpiInstruction: cpiInstruction,
          timestamp: new BN(user.executeData.timestamp)
        },
        {
          useVersionedTransaction: false
        }
      );

      // // add smart wallet to alt
      // try {
      //   await addAddressToAlt([new PublicKey(user.smartWallet)]);
      //   await addAddressToAlt([new PublicKey(user.executeData.toAddress)]);
      // } catch (err) {
      //   console.log('Add alt error: ', err)
      // }

      const altAccount = await lookupTableAccount.getTable();

      const messageV0 = new TransactionMessage({
        payerKey: provider.keypair.publicKey,
        recentBlockhash: (await connection.getLatestBlockhash()).blockhash,
        instructions: ins
      }).compileToV0Message([altAccount]);

      const txV0 = new VersionedTransaction(messageV0);

      const txid = await provider.provider.sendAndConfirm(txV0, [])
      console.log("Txid send token:", txid);

      await User.findOneAndUpdate(
        { username: user.username },
        { executeData: {} }
      )

      res.status(200).json({ txId: txid })
    } catch (err: any) {
      console.log(err)
      res.status(500).json({ error: err.toString() })
    }
  }
}