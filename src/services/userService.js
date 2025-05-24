import mongoose from "mongoose";
import User from "../models/userModel.js";
import bcrypt from "bcrypt";
import jwtService from "./jwtService.js";
import { updateUserSchema } from "../middlewares/userValidation.js";
import { ERROR_TYPES, AppError } from "../utils/errorTypes.js";

const userService = {
  getUser: async (userId) => {
    try {
      if (!userId) {
        throw new AppError(ERROR_TYPES.MISSING_FIELDS, {
          missingFields: ["userId"],
          message: "User ID is required",
        });
      }

      if (!mongoose.Types.ObjectId.isValid(userId)) {
        throw new AppError(ERROR_TYPES.VALIDATION_ERROR, {
          invalidField: "userId",
          message: "Invalid user ID format",
        });
      }

      const user = await User.findById(userId).select(
        "-password -refresh_token -__v"
      );

      if (!user) {
        throw new AppError(ERROR_TYPES.USER_NOT_FOUND, {
          userId,
          message: "User not found",
        });
      }

      if (!user.isActive) {
        throw new AppError(ERROR_TYPES.FORBIDDEN, {
          userId,
          message: "User is not active",
        });
      }

      return user;
    } catch (error) {
      if (error instanceof AppError) {
        if (!error.details) {
          error.details = {
            operation: "get user data",
            userId,
          };
        }
        throw error;
      }
      throw new AppError(ERROR_TYPES.INTERNAL_ERROR, {
        operation: "get user data",
        rawError: error.message,
      });
    }
  },

  createUser: async (data) => {
    try {
      const existingUser = await User.findOne({
        $or: [{ email: data.email }, { username: data.username }],
      }).select("email username");

      if (existingUser) {
        const field = existingUser.email === data.email ? "email" : "username";
        throw new AppError(ERROR_TYPES.USER_EXISTS, {
          field,
          value: data[field],
          message: `${field} '${data[field]}' is already registered`,
        });
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
      if (error.name === "ValidationError") {
        const messages = Object.values(error.errors).map((err) => err.message);
        throw new AppError(ERROR_TYPES.VALIDATION_ERROR, {
          errors: messages,
          rawError: error.message,
        });
      }

      throw error instanceof AppError
        ? error
        : new AppError(ERROR_TYPES.INTERNAL_ERROR, {
            operation: "user registration",
            rawError: error.message,
          });
    }
  },

  loginUser: async ({ email, password }) => {
    try {
      if (!password) {
        throw new AppError(ERROR_TYPES.MISSING_FIELDS, {
          missingField: "password",
          message: "Password is required",
        });
      }

      const user = await User.findOne({ email }).select(
        "+password +refresh_token"
      );

      if (!user) {
        throw new AppError(ERROR_TYPES.INVALID_CREDENTIALS, {
          attemptedEmail: email,
          message: "No user found with this email",
        });
      }

      if (!user.password) {
        await User.deleteOne({ _id: user._id });
        throw new AppError(ERROR_TYPES.INTERNAL_ERROR, {
          issue: "password_not_set",
          userId: user._id,
          message: "Password not properly set up",
        });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        throw new AppError(ERROR_TYPES.INVALID_CREDENTIALS, {
          attemptedEmail: email,
          message: "Password does not match",
        });
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
          refreshToken,
        },
        message: "Login successful",
      };
    } catch (error) {
      if (error instanceof AppError) {
        if (!error.details) {
          error.details = {
            operation: "user login",
            attemptedEmail: email,
          };
        }
        throw error;
      }

      throw new AppError(ERROR_TYPES.AUTHENTICATION_FAILED, {
        operation: "user login",
        attemptedEmail: email,
        rawError: error.message,
      });
    }
  },

  loginWithGoogle: async (googleUser) => {
    try {
      const { email, name, picture } = googleUser;

      if (!email) {
        throw new AppError(ERROR_TYPES.MISSING_FIELDS, {
          missingField: "email",
          message: "Email is required",
        });
      }

      const existingUser = await User.findOne({ email }).select(
        "+password +refresh_token"
      );

      if (existingUser) {
        const accessToken = jwtService.generateAccessToken({
          userId: existingUser._id,
          username: existingUser.username,
          email: existingUser.email,
          role: existingUser.role,
          isActive: existingUser.isActive,
        });

        const refreshToken = jwtService.generateRefreshToken({
          userId: existingUser._id,
        });

        await User.updateOne(
          { _id: existingUser._id },
          {
            refresh_token: refreshToken,
            lastLogin: new Date(),
          }
        );

        return {
          success: true,
          data: {
            accessToken,
            refreshToken,
            userId: existingUser._id,
          },
          message: "Login successful",
        };
      }

      const newUser = await User.create({
        email,
        username: name || email.split("@")[0],
        password: null,
        profilePicture: picture || null,
      });

      const accessToken = jwtService.generateAccessToken({
        userId: newUser._id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        isActive: newUser.isActive,
      });

      const refreshToken = jwtService.generateRefreshToken({
        userId: newUser._id,
      });

      await User.updateOne(
        { _id: newUser._id },
        {
          refresh_token: refreshToken,
          lastLogin: new Date(),
        }
      );

      return {
        success: true,
        data: {
          accessToken,
          refreshToken,
          userId: newUser._id,
        },
        message: "Google login successful",
      };
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError(ERROR_TYPES.INTERNAL_ERROR, {
        operation: "google login",
        rawError: error.message,
      });
    }
  },
  
  refreshToken: async (refreshToken) => {
    try {
      if (!refreshToken) {
        throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
          issue: "missing_token",
          message: "No refresh token provided",
        });
      }

      const { valid, decoded } = jwtService.verifyRefreshToken(refreshToken);
      if (!valid) {
        throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
          issue: "invalid_signature",
          token: refreshToken.substring(0, 10) + "...",
          message: "Token verification failed",
        });
      }

      const user = await User.findOne({ _id: decoded.data.userId }).select(
        "+refresh_token"
      );
      if (!user) {
        throw new AppError(ERROR_TYPES.USER_NOT_FOUND, {
          userId: decoded.data.userId,
          message: "User associated with token not found",
        });
      }

      if (user.refresh_token !== refreshToken) {
        throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
          issue: "token_mismatch",
          userId: user._id,
          message: "Token does not match stored token",
        });
      }

      const newAccessToken = jwtService.generateAccessToken({
        userId: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        isActive: user.isActive,
      });

      const newRefreshToken = jwtService.generateRefreshToken({
        userId: user._id,
      });

      await User.updateOne(
        { _id: user._id },
        { refresh_token: newRefreshToken }
      );

      return {
        success: true,
        data: {
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
          userId: user._id,
        },
        message: "Token refreshed successfully",
      };
    } catch (error) {
      if (error instanceof AppError) {
        if (error.code === ERROR_TYPES.TOKEN_EXPIRED.code) {
          error.details = {
            ...error.details,
            operation: "token_refresh",
            tokenType: "refresh",
          };
        }
        throw error;
      }

      throw new AppError(ERROR_TYPES.INTERNAL_ERROR, {
        operation: "token_refresh",
        rawError: error.message,
      });
    }
  },

  logoutUser: async (refreshToken) => {
    try {
      if (!refreshToken) {
        return { success: true };
      }

      const { decoded } = jwtService.verifyRefreshToken(refreshToken);

      await User.updateOne(
        { _id: decoded.data.userId },
        { $unset: { refresh_token: 1 } }
      );

      return { success: true };
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        throw new AppError(ERROR_TYPES.TOKEN_EXPIRED, {
          operation: "user logout",
          tokenType: "refresh",
        });
      }

      if (error.name === "JsonWebTokenError") {
        throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
          operation: "user logout",
          tokenType: "refresh",
          reason: error.message,
        });
      }

      throw new AppError(ERROR_TYPES.INTERNAL_ERROR, {
        operation: "user logout",
        rawError: error.message,
      });
    }
  },

  listUsers: async (options = {}) => {
    try {
      const { page = 1, limit = 10, search = "" } = options;
      const skip = (page - 1) * limit;

      const query = {
        $or: [
          { username: { $regex: search, $options: "i" } },
          { email: { $regex: search, $options: "i" } },
        ],
      };

      const users = await User.find(query)
        .select("-password -refresh_token -__v")
        .skip(skip)
        .limit(limit)
        .lean();

      const total = await User.countDocuments(query);

      return {
        success: true,
        data: users,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / limit),
        },
      };
    } catch (error) {
      throw new AppError(ERROR_TYPES.INTERNAL_ERROR, {
        operation: "list users",
        rawError: error.message,
      });
    }
  },

  deleteUser: async (userId, currentUserId) => {
    try {
      if (!userId) {
        throw new AppError(ERROR_TYPES.MISSING_FIELDS, {
          missingFields: ["userId"],
          message: "User ID is required",
        });
      }

      if (userId === currentUserId) {
        throw new AppError(ERROR_TYPES.FORBIDDEN, {
          message: "Cannot delete your own account",
        });
      }

      if (!mongoose.Types.ObjectId.isValid(userId)) {
        throw new AppError(ERROR_TYPES.VALIDATION_ERROR, {
          invalidField: "userId",
          message: "Invalid user ID format",
        });
      }

      const user = await User.findByIdAndDelete(userId);
      if (!user) {
        throw new AppError(ERROR_TYPES.USER_NOT_FOUND, {
          userId,
          message: "User not found",
        });
      }

      return {
        success: true,
        message: "User deleted successfully",
      };
    } catch (error) {
      if (error instanceof AppError) {
        if (!error.details) {
          error.details = {
            operation: "delete user",
            userId,
          };
        }
        throw error;
      }
      throw new AppError(ERROR_TYPES.INTERNAL_ERROR, {
        operation: "delete user",
        rawError: error.message,
      });
    }
  },

  updateUser: async (userId, updateData) => {
    try {
      const { error, value } = updateUserSchema.validate(updateData, {
        abortEarly: false,
        stripUnknown: true,
      });

      if (error) {
        const validationErrors = error.details.reduce((acc, curr) => {
          acc[curr.path[0]] = curr.message;
          return acc;
        }, {});

        throw new AppError(ERROR_TYPES.VALIDATION_ERROR, {
          errors: validationErrors,
          message: "Validation failed",
        });
      }

      if (value.username) {
        const existingUser = await User.findOne({
          username: value.username,
          _id: { $ne: userId },
        });
        if (existingUser) {
          throw new AppError(ERROR_TYPES.VALIDATION_ERROR, {
            errors: { username: "Username is already taken" },
          });
        }
      }

      if (value.email) {
        const existingUser = await User.findOne({
          email: value.email,
          _id: { $ne: userId },
        });
        if (existingUser) {
          throw new AppError(ERROR_TYPES.VALIDATION_ERROR, {
            errors: { email: "Email is already registered" },
          });
        }
      }

      if (value.password) {
        value.password = await bcrypt.hash(value.password, 10);
      }

      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { $set: value },
        { new: true, select: "-password -refresh_token -__v" }
      );

      if (!updatedUser) {
        throw new AppError(ERROR_TYPES.USER_NOT_FOUND, {
          userId,
          message: "User not found",
        });
      }

      return {
        success: true,
        data: updatedUser,
        message: "User updated successfully",
      };
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError(ERROR_TYPES.INTERNAL_ERROR, {
        operation: "update user",
        rawError: error.message,
      });
    }
  },
};

export default userService;
