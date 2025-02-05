const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
   {
      name: {
         type: String,
         required: true,
      },
      email: {
         type: String,
         required: true,
         unique: true,
         lowercase: true,
      },
      password: {
         type: String,
         required: true,
      },
      salt: {
         type: String,
         required: true,
      },
      role: {
         type: String,
         enum: ["user", "admin"],
         default: "user",
      },
      verified: {
         type: Boolean,
         default: false,
      },
      otp: {
         type: String,
         default: null,
      },
      otp_expiry: {
         type: Date,
         default: null,
      },
      status: {
         type: String,
         enum: ["active", "inactive", "banned"],
         default: "active",
      },
   },
   { timestamps: true }
);

const UserModel = mongoose.model("User", UserSchema);
module.exports = UserModel;
