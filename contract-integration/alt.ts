import { PublicKey, Keypair, Connection, ComputeBudgetProgram, TransactionInstruction, VersionedMessage, VersionedTransaction, TransactionMessage, SystemProgram, AccountMeta, Transaction, AddressLookupTableProgram, sendAndConfirmTransaction, Signer } from '@solana/web3.js';
import * as dotenv from "dotenv";
import { getAssociatedTokenAddress, getAccount, TYPE_SIZE, getAssociatedTokenAddressSync, createAssociatedTokenAccount, createAssociatedTokenAccountInstruction } from "@solana/spl-token";
import { AnchorProvider, BN, Program, Wallet } from "@coral-xyz/anchor";
import { Lazorkit } from './anchor/types/lazorkit';
import { DefaultPolicy } from './anchor/types/default_policy';
import lazorkit_idl from './anchor/idl/lazorkit.json';
import default_policy_idl from './anchor/idl/default_policy.json';
import * as lazorkit_pda from './pda/lazorkit';
import * as default_policy_pda from './pda/defaultPolicy';
import bs58 from "bs58";

dotenv.config();

const secretKeyBase58 = process.env.SECRET_KEY;
const secret_key = bs58.decode(secretKeyBase58);
const signerKeypair = Keypair.fromSecretKey(secret_key)
const connection = new Connection("https://api.devnet.solana.com", "confirmed");
const wallet = new Wallet(signerKeypair)
const provider = new AnchorProvider(connection, wallet, { commitment: "confirmed" })
const my_public_key = wallet.publicKey.toBase58()

// program
const lazorkit_id = new PublicKey("FHociuhzHmgDtB8JbXP3ZU7sigicgEZrCenYyWSD1ynm");
const default_policy_id = new PublicKey("78swgvAWkyabhWqTg1pQnS4n44AM7LDta4RvJgtJVCZr");
const lazorkit: Program<Lazorkit> = new Program(lazorkit_idl as any, provider);
const default_policy: Program<DefaultPolicy> = new Program(default_policy_idl as any, provider);

// alt devnet
const altAddress = new PublicKey("BX5ZSTm1ytrLytXy1mCSrgHgZV8bNxhiVSU7bD1ekVvN");

async function createAlt() {
  const slot = await connection.getSlot("confirmed");

  const [lookupTableInst, lookupTableAddress] = AddressLookupTableProgram.createLookupTable({
    authority: provider.publicKey,
    payer: provider.publicKey,
    recentSlot: slot,
  });

  console.log("Address lookup table's address: ", lookupTableAddress.toBase58());
  const tx = new Transaction().add(lookupTableInst);
  (await provider.sendAndConfirm(tx, []));
}

export async function addAddressToAlt(account: PublicKey[]) {
  const extendIx = AddressLookupTableProgram.extendLookupTable({
    payer: provider.publicKey,
    authority: provider.publicKey,
    lookupTable: altAddress,
    addresses: account
  });
  const tx = new Transaction().add(extendIx);
  await provider.sendAndConfirm(tx, []);
}

export const lookupTableAccount = {
  getTable: async () => {
    return (await connection.getAddressLookupTable(altAddress)).value;
  }
}

// async function main() {
//   //await createAlt();
//   const address_to_add: PublicKey[] = [
//     lazorkit_id,
//     default_policy_id,
//     lazorkit_pda.derivePolicyProgramRegistryPda(lazorkit_id),
//   ]
//   await addAddressToAlt(address_to_add);

// }

// main();