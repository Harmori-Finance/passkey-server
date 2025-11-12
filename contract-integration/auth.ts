import * as anchor from '@coral-xyz/anchor';
import { buildSecp256r1VerifyIx } from './webauthn/secp256r1';
import { sha256 } from 'js-sha256';
import { PasskeySignature } from './types';
import { p256 } from "@noble/curves/p256";

/**
 * Builds a Secp256r1 signature verification instruction for passkey authentication
 */
// export function buildPasskeyVerificationInstruction(
//   passkeySignature: PasskeySignature
// ): anchor.web3.TransactionInstruction {
//   const authenticatorDataRaw = Buffer.from(
//     passkeySignature.authenticatorDataRaw64,
//     'base64'
//   );
//   const clientDataJsonRaw = Buffer.from(
//     passkeySignature.clientDataJsonRaw64,
//     'base64'
//   );

//   return buildSecp256r1VerifyIx(
//     Buffer.concat([
//       authenticatorDataRaw,
//       Buffer.from(sha256.arrayBuffer(clientDataJsonRaw)),
//     ]),
//     passkeySignature.passkeyPublicKey,
//     Buffer.from(passkeySignature.signature64, 'base64')
//     // Buffer.from(p256.Signature.fromDER(Buffer.from(passkeySignature.signature64, "base64")).toCompactRawBytes())
//   );
// }

export function buildPasskeyVerificationInstruction(
  passkeySignature: PasskeySignature
): anchor.web3.TransactionInstruction {
  const authenticatorDataRaw = Buffer.from(passkeySignature.authenticatorDataRaw64, 'base64');

  let fullAuthData: Buffer;
  if (authenticatorDataRaw.length === 33) {
    fullAuthData = Buffer.alloc(37);
    authenticatorDataRaw.copy(fullAuthData, 0, 0, 33);
    fullAuthData.writeUInt32BE(passkeySignature.signCount, 33);
  } else {
    fullAuthData = authenticatorDataRaw;
  }

  const clientDataJsonRaw = Buffer.from(passkeySignature.clientDataJsonRaw64, 'base64');
  const clientDataHash = Buffer.from(sha256.arrayBuffer(clientDataJsonRaw));

  const message = Buffer.concat([fullAuthData, clientDataHash]);

  const pubkeyBytes = Uint8Array.from(passkeySignature.passkeyPublicKey);
  if (pubkeyBytes.length !== 33) throw new Error("pubkey must be 33 bytes");

  return buildSecp256r1VerifyIx(
    message,
    Array.from(pubkeyBytes),
    // Buffer.from(passkeySignature.signature64, 'base64'),
    Buffer.from(p256.Signature.fromDER(Buffer.from(passkeySignature.signature64, "base64")).normalizeS().toCompactRawBytes())
  );
}

/**
 * Converts passkey signature data to the format expected by smart contract instructions
 */
export function convertPasskeySignatureToInstructionArgs(
  passkeySignature: PasskeySignature
): {
  passkeyPublicKey: number[];
  signature: Buffer;
  clientDataJsonRaw: Buffer;
  authenticatorDataRaw: Buffer;
} {
  const authenticatorDataRaw = Buffer.from(passkeySignature.authenticatorDataRaw64, 'base64');

  let fullAuthData: Buffer;
  if (authenticatorDataRaw.length === 33) {
    fullAuthData = Buffer.alloc(37);
    authenticatorDataRaw.copy(fullAuthData, 0, 0, 33);
    fullAuthData.writeUInt32BE(passkeySignature.signCount, 33);
  } else {
    fullAuthData = authenticatorDataRaw;
  }

  return {
    passkeyPublicKey: passkeySignature.passkeyPublicKey,
    // signature: Buffer.from(passkeySignature.signature64, 'base64'),
    signature: Buffer.from(p256.Signature.fromDER(Buffer.from(passkeySignature.signature64, "base64")).normalizeS().toCompactRawBytes()),
    clientDataJsonRaw: Buffer.from(
      passkeySignature.clientDataJsonRaw64,
      'base64'
    ),
    // authenticatorDataRaw: Buffer.from(
    //   passkeySignature.authenticatorDataRaw64,
    //   'base64'
    // ),
    authenticatorDataRaw: fullAuthData
  };
}
