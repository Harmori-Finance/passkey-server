import { Connection, Keypair, Transaction, VersionedTransaction } from "@solana/web3.js";
import * as bip39 from "bip39";
import { derivePath } from "ed25519-hd-key";
import * as cbor from "cbor";
import { AnchorProvider, Wallet } from "@coral-xyz/anchor";

export async function createProviderFromMnemonic(mnemonic: string, rpcUrl: string) {
  const seed = await bip39.mnemonicToSeed(mnemonic);
  const path = "m/44'/501'/0'/0'";
  const derivedSeed = derivePath(path, seed.toString("hex")).key;
  const keypair = Keypair.fromSeed(derivedSeed);

  const connection = new Connection(rpcUrl, "confirmed");

  const wallet = new Wallet(keypair)

  const provider = new AnchorProvider(connection, wallet, { commitment: "confirmed" })

  return { provider, wallet, keypair, connection };
}

export function base64urlToBuffer(base64url: string): Buffer {
  const base64 = base64url
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(base64url.length / 4) * 4, "=");
  return Buffer.from(base64, "base64");
}

export function bufferToBase64url(buffer: Buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '')
    .replace(/=+$/, '');
}

export function extractCompressedPubkey(publicKeyBase64Url: string): Uint8Array {
  const coseBuffer = base64urlToBuffer(publicKeyBase64Url);
  const coseStruct = cbor.decodeAllSync(coseBuffer)[0];

  const x = coseStruct.get(-2);
  const y = coseStruct.get(-3);

  const prefix = (y[31] & 1) ? 0x03 : 0x02;

  const compressed = new Uint8Array(33);
  compressed[0] = prefix;
  compressed.set(x, 1);

  return compressed;
}
