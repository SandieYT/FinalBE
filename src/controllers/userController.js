import userService from "../services/userService.js";
import { ERROR_TYPES, AppError } from "../utils/errorTypes.js";

const userController = {
  createUser: async (req, res) => {
    try {
      const requiredFields = [
        "username",
        "email",
        "password",
        "confirmPassword",
      ];
      const missingFields = requiredFields.filter((field) => !req.body[field]);

      if (missingFields.length > 0) {
        throw new AppError(ERROR_TYPES.MISSING_FIELDS, {
          missingFields,
          message: `Missing: ${missingFields.join(", ")}`,
        });
      }

      if (req.body.password !== req.body.confirmPassword) {
        throw new AppError(ERROR_TYPES.PASSWORD_MISMATCH);
      }

      const result = await userService.createUser(req.body);
      res.status(201).json(result);
    } catch (error) {
      if (error instanceof AppError) {
        return res.status(error.status).json({
          success: false,
          error: {
            code: error.code,
            message: error.message,
            details: error.details,
          },
        });
      }

      res.status(500).json({
        success: false,
        error: {
          code: ERROR_TYPES.INTERNAL_ERROR.code,
          message: ERROR_TYPES.INTERNAL_ERROR.message,
          details: {
            rawError: error.message,
            operation: "user registration",
          },
        },
      });
    }
  },

  loginUser: async (req, res) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        throw new AppError(ERROR_TYPES.MISSING_FIELDS, {
          missingFields: [
            !email ? "email" : null,
            !password ? "password" : null,
          ].filter(Boolean),
          message: "Email and password are required",
        });
      }

      const result = await userService.loginUser({ email, password });

      res.cookie("accessToken", result.data.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 15 * 60 * 1000,
      });

      res.cookie("refreshToken", result.data.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.status(200).json({
        success: true,
        data: {
          userId: result.data.userId,
          username: result.data.username,
          email: result.data.email,
          role: result.data.role,
        },
        message: "Login successful",
      });
    } catch (error) {
      if (error instanceof AppError) {
        return res.status(error.status).json({
          success: false,
          error: {
            code: error.code,
            message: error.message,
            details: {
              ...error.details,
              attemptedEmail: req.body.email,
            },
          },
        });
      }

      res.status(500).json({
        success: false,
        error: {
          code: ERROR_TYPES.INTERNAL_ERROR.code,
          message: ERROR_TYPES.INTERNAL_ERROR.message,
          details: {
            rawError: error.message,
            operation: "user login",
          },
        },
      });
    }
  },

  refreshToken: async (req, res) => {
    try {
      const refreshToken = req.cookies.refreshToken || req.body.refreshToken;

      if (!refreshToken) {
        throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
          issue: "missing_token",
          message: "Refresh token is required",
        });
      }

      const result = await userService.refreshToken(refreshToken);

      res.cookie("accessToken", result.data.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 15 * 60 * 1000,
      });

      res.cookie("refreshToken", result.data.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.status(200).json({
        success: true,
        data: {
          userId: result.data.userId,
        },
        message: "Token refreshed successfully",
      });
    } catch (error) {
      if (error instanceof AppError) {
        const status =
          error.code === ERROR_TYPES.TOKEN_EXPIRED.code ? 401 : error.status;
        return res.status(status).json({
          success: false,
          error: {
            code: error.code,
            message: error.message,
            details: error.details,
          },
        });
      }

      res.status(500).json({
        success: false,
        error: {
          code: ERROR_TYPES.INTERNAL_ERROR.code,
          message: ERROR_TYPES.INTERNAL_ERROR.message,
          details: {
            rawError: error.message,
            operation: "token refresh",
          },
        },
      });
    }
  },

  logoutUser: async (req, res) => {
    try {
      const { refreshToken } = req.cookies;

      if (!refreshToken) {
        res.clearCookie("accessToken");
        res.clearCookie("refreshToken");
        return res.status(200).json({
          success: true,
          message: "Logout successful (no active session)",
        });
      }

      const result = await userService.logoutUser(refreshToken);

      res.clearCookie("accessToken");
      res.clearCookie("refreshToken");

      res.status(200).json({
        success: true,
        message: "Logout successful",
      });
    } catch (error) {
      if (error instanceof AppError) {
        return res.status(error.status).json({
          success: false,
          error: {
            code: error.code,
            message: error.message,
            details: error.details || {
              operation: "user logout",
              rawError: error.message,
            },
          },
        });
      }

      res.status(500).json({
        success: false,
        error: {
          code: ERROR_TYPES.INTERNAL_ERROR.code,
          message: ERROR_TYPES.INTERNAL_ERROR.message,
          details: {
            operation: "user logout",
            rawError: error.message,
          },
        },
      });
    }
  },
};

export default userController;
