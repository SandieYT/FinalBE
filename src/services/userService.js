import User from "../models/userModel.js";
import bcrypt from "bcrypt";
import jwtService from "./jwtService.js";

const userService = {
  createUser: async (data) => {
    try {
      const existingUser = await User.findOne({
        $or: [{ email: data.email }, { username: data.username }],
      }).select("email username");

      if (existingUser) {
        const field = existingUser.email === data.email ? "email" : "username";
        throw new Error(
          `Registration failed: ${field} '${data[field]}' is already registered`
        );
      }

      const user = await User.create({
        ...data,
        password: await bcrypt.hash(data.password, 10),
      });

      const userObj = user.toObject();
      delete userObj.password;
      delete userObj.access_token;
      delete userObj.refresh_token;
      delete userObj.__v;

      return {
        success: true,
        data: userObj,
        message: "User registered successfully",
      };
    } catch (error) {
      console.error("[User Registration] Error:", error);

      if (error.name === "ValidationError") {
        const messages = Object.values(error.errors).map((err) => err.message);
        throw new Error(`Registration failed: ${messages.join(", ")}`);
      }

      throw error.message.includes("failed:")
        ? error
        : new Error(`Registration failed: ${error.message}`);
    }
  },

  loginUser: async ({ email, password }) => {
    try {
      if (!password) throw new Error("Password is required for authentication");

      const user = await User.findOne({ email }).select(
        "+password +refresh_token"
      );

      if (!user) {
        throw new Error("Authentication failed: Invalid email or password");
      }

      if (!user.password) {
        await User.deleteOne({ _id: user._id });
        throw new Error(
          "Account error: Password not properly set up. Please contact support"
        );
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        throw new Error("Authentication failed: Invalid email or password");
      }

      const accessToken = jwtService.generateAccessToken({
        userId: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        isActive: user.isActive,
      });

      const refreshToken = jwtService.generateRefreshToken({
        userId: user._id,
      });

      await User.updateOne(
        { _id: user._id },
        {
          refresh_token: refreshToken,
          lastLogin: new Date(),
        }
      );

      const userObj = user.toObject();
      delete userObj.password;
      delete userObj.__v;
      delete userObj.refresh_token;

      return {
        success: true,
        data: {
          accessToken,
        },
        message: "Login successful",
      };
    } catch (error) {
      console.error("[User Login] Error:", error);

      throw error.message.includes("failed:") ||
        error.message.includes("error:")
        ? error
        : new Error(`Authentication failed: ${error.message}`);
    }
  },
};

export default userService;
