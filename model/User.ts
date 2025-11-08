import mongoose from "mongoose";

interface IUser {
  id: string;
  currentChallenge?: string;
}

export const UserSchema = new mongoose.Schema<IUser>({
  id: { type: String, required: true },
  currentChallenge: { type: String }
})

export default mongoose.model<IUser>("User", UserSchema, "user");