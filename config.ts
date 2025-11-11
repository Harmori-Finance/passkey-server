import dotenv from 'dotenv'

dotenv.config()

export const MONGO_URL = process.env.MONGO_URL ?? "";
export const MONGO_DB_NAME = process.env.MONGO_DB_NAME ?? "";
export const MONGO_USERNAME = process.env.MONGO_USERNAME ?? "";
export const MONGO_PASSWORD = process.env.MONGO_PASSWORD ?? "";

export const MNEMONIC = process.env.MNEMONIC ?? "";
export const RPC_URL_SOLANA = process.env.RPC_URL_SOLANA ?? "";

export const SHA256_CERT_FINGERPRINTS = process.env.SHA256_CERT_FINGERPRINTS ?? "";