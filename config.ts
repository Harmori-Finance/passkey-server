import dotenv from 'dotenv'

dotenv.config()

export const MONGO_URL = process.env.MONGO_URL ?? "";
export const MONGO_DB_NAME = process.env.MONGO_DB_NAME ?? "";
export const MONGO_USERNAME = process.env.MONGO_USERNAME ?? "";
export const MONGO_PASSWORD = process.env.MONGO_PASSWORD ?? "";