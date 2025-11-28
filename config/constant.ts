import { PublicKey, SystemProgram } from "@solana/web3.js";

export const symbolToMint = {
  'SOL': SystemProgram.programId,
  'USDC': new PublicKey('4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'),
}