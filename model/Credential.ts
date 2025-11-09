import mongoose from "mongoose";

interface ICredential {
  id: string;
  publicKey: string;
  counter: number;
  username: string;
}

const CredentialSchema = new mongoose.Schema<ICredential>({
  id: { type: String },
  publicKey: { type: String },
  counter: { type: Number },
  username: { type: String }
})

export default mongoose.model<ICredential>("Credential", CredentialSchema, "credential")