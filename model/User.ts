import mongoose from "mongoose";

interface IUser {
  username: string;
  currentChallenge?: string;
  smartWallet: string;
  smartWalletId: number;
  timestampExecute: number;
}

export const UserSchema = new mongoose.Schema<IUser>({
  username: { type: String, required: true },
  currentChallenge: { type: String },
  smartWallet: { type: String },
  smartWalletId: { type: Number },
  timestampExecute: { type: Number }
})

export default mongoose.model<IUser>("User", UserSchema, "user");