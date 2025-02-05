const UserModel = require("./model");
const { createHmac, randomBytes } = require("node:crypto");
const JWT = require("jsonwebtoken");
const { SendEmail } = require("../notifications");

function generateHash(salt, password) {
   const hashedPassword = createHmac("sha256", salt)
      .update(password)
      .digest("hex");
   return hashedPassword;
}

function generateToken(user) {
   if (!user) throw new Error("User not found");

   if (!user.verified) throw new Error("User not verified");

   if (user.status !== "active") throw new Error("User not active");

   return JWT.sign(
      {
         _id: user._id,
         email: user.email,
         role: user.role,
      },
      process.env.JWT_SECRET
   );
}

async function createUser(args) {
   try {
      const salt = randomBytes(32).toString("hex");
      const hashedPassword = generateHash(salt, args.password);

      const userExist = await getUserByEmail(args.email);
      if (userExist) throw new Error("User already exists");

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const sent = await SendEmail(args.email, "Verify Email", otp, "otp");

      if (!sent) throw new Error("Email not sent");

      await UserModel.create({
         ...args,
         salt,
         otp,
         otp_expiry: Date.now() + 3600000,
         password: hashedPassword,
      });

      return {
         success: true,
         message: "User created successfully",
      };
   } catch (error) {
      throw new Error(error.message);
   }
}

async function updateUser(args) {
   try {
      const userExist = await getUserById(args._id);
      if (!userExist) throw new Error("User not found");

      const user = await UserModel.findByIdAndUpdate(args._id, args, {
         new: true,
         runValidators: true,
      });

      return {
         success: true,
         message: "User updated successfully",
         data: user,
      };
   } catch (error) {
      throw new Error(error.message);
   }
}

async function verifyEmail(args) {
   console.log(args);
   try {
      const user = await getUserByEmail(args.email);
      if (!user) throw new Error("User not found");
      if (user.verified) throw new Error("Email already verified");
      if (user.otp !== args.otp) throw new Error("Invalid OTP");
      if (user.otp_expiry < Date.now()) throw new Error("OTP expired");

      const newUser = await UserModel.findByIdAndUpdate(
         user._id,
         {
            verified: true,
            otp: null,
            otp_expiry: null,
         },
         {
            new: true,
         }
      );

      const token = generateToken(newUser);

      return {
         success: true,
         message: "Email verified successfully",
         data: token,
      };
   } catch (error) {
      throw new Error(error.message);
   }
}

async function getUserToken({ email, password }) {
   try {
      const user = await getUserByEmail(email);
      if (!user) throw new Error("user not found");

      const userSalt = user.salt;
      const usersHashPassword = generateHash(userSalt, password);

      if (usersHashPassword !== user.password)
         throw new Error("Incorrect Password");

      if (!user.verified) {
         const otp = String(Math.floor(100000 + Math.random() * 900000));

         await UserModel.findByIdAndUpdate(user._id, {
            otp,
            otp_expiry: Date.now() + 3600000,
         });

         await SendEmail(user.email, "OTP Verification", otp, "otp");

         return {
            success: true,
            message: "User not verified",
            data: {
               isVerified: false,
               token: null,
            },
         };
      }

      const token = generateToken(user);

      return {
         success: true,
         message: "User logged in successfully",
         data: {
            isVerified: true,
            token,
         },
      };
   } catch (error) {
      throw new Error(error.message);
   }
}

async function resendVerificationEmail(args) {
   try {
      const user = await getUserByEmail(args.email);
      if (!user) throw new Error("User not found");
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      await SendEmail(args.email, "Verify Email", otp, "otp");

      await UserModel.findByIdAndUpdate(user._id, {
         otp,
         otp_expiry: Date.now() + 3600000,
      });
      return {
         success: true,
         message: "Email sent successfully",
      };
   } catch (error) {
      throw new Error(error.message);
   }
}

async function forgotPassword(args) {
   try {
      const user = await getUserByEmail(args.email);
      if (!user) throw new Error("User not found");
      if (user.otp_expiry > Date.now() + 300000) {
         // 5 mints
         return {
            success: true,
            message: "OTP sent already",
         };
      }

      const otp = String(Math.floor(100000 + Math.random() * 900000));

      await SendEmail(args.email, "Reset Password", otp, "otp");

      await UserModel.findByIdAndUpdate(user._id, {
         otp,
         otp_expiry: Date.now() + 3600000, // 1 hour
      });

      return {
         success: true,
         message: "OTP sent successfully",
      };
   } catch (error) {
      console.log(error);
      throw new Error(error.message);
   }
}

async function resetPassword(args) {
   try {
      const user = await getUserByEmail(args.email);
      if (!user) throw new Error("User not found");

      if (args.otp !== user.otp) throw new Error("Invalid OTP");

      if (user.otp_expiry < Date.now()) throw new Error("OTP expired");

      const salt = randomBytes(32).toString("hex");
      const hashedPassword = generateHash(salt, args.password);

      await UserModel.findByIdAndUpdate(user._id, {
         salt,
         password: hashedPassword,
         otp: null,
         otp_expiry: null,
      });

      const token = generateToken(user);

      return {
         success: true,
         message: "Password reset successfully",
         data: token,
      };
   } catch (error) {
      console.log(error);
      throw new Error(error.message);
   }
}

async function changePassword(args) {
   try {
      const user = await getUserById(args._id);
      if (!user) throw new Error("User not found");

      const userSalt = user.salt;
      const usersHashPassword = generateHash(userSalt, args.old_password);

      if (usersHashPassword !== user.password)
         throw new Error("Incorrect Password");

      const salt = randomBytes(32).toString("hex");
      const hashedPassword = generateHash(salt, args.new_password);

      await UserModel.findByIdAndUpdate(user._id, {
         salt,
         password: hashedPassword,
      });
      return {
         success: true,
         message: "Password Changed Successfully",
      };
   } catch (error) {
      console.log(error);
      throw new Error(error.message);
   }
}

async function deleteUserById(id) {
   try {
      if (!id) throw new Error("Id is required");
      const user = await UserModel.findById(id);
      if (!user) throw new Error("User not found");
      await UserModel.findByIdAndDelete(id);
      return {
         success: true,
         message: "User deleted successfully",
      };
   } catch (error) {
      throw new Error(error.message);
   }
}

async function getAllUsers() {
   try {
      const users = await UserModel.find();
      console.log(users);
      return {
         success: true,
         message: "Users fetched successfully",
         data: users,
      };
   } catch (error) {
      throw new Error(error.message);
   }
}

async function findNearbyUsers() {
   try {
      const users = await UserModel.find({
         role: "user",
         status: "active",
      });

      return {
         success: true,
         message: "Users fetched successfully",
         data: users,
      };
   } catch (error) {
      console.error("Error finding nearby users:", error);
      throw error;
   }
}
async function getUserByEmail(email) {
   try {
      return await UserModel.findOne({ email });
   } catch (error) {
      throw new Error(error.message);
   }
}

async function getUserById(id) {
   try {
      console.log(id);
      if (!id) throw new Error("Id is required");
      const user = await UserModel.findById(id);
      if (!user) throw new Error("User not found");
      return {
         success: true,
         message: "User fetched successfully",
         data: user,
      };
   } catch (error) {
      throw new Error(error.message);
   }
}

module.exports.UserService = {
   getAllUsers,
   findNearbyUsers,
   getUserToken,
   getUserByEmail,
   getUserById,
   createUser,
   updateUser,
   verifyEmail,
   resendVerificationEmail,
   forgotPassword,
   resetPassword,
   changePassword,
   deleteUserById,
};
