import mongoose from "mongoose";

interface IUser {
  id: string;
  username: string;
  currentChallenge?: string;
}

export const UserSchema = new mongoose.Schema<IUser>({
  id: { type: String },
  username: { type: String },
  currentChallenge: { type: String }
})

export default mongoose.model<IUser>("User", UserSchema, "user");