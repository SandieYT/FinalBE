import userService from "../services/userService.js";
import { OAuth2Client } from "google-auth-library";
import { ERROR_TYPES, AppError } from "../utils/errorTypes.js";

const client = new OAuth2Client(process.env.GG_CLIENT_ID);
const isProduction = process.env.NODE_ENV === 'production';
const cookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? 'none' : 'lax',
};

const userController = {
  getUser: async (req, res) => {
    try {
      const userId = req.params.userId;
      const result = await userService.getUser(userId);
      if (!result) {
        throw new AppError(ERROR_TYPES.USER_NOT_FOUND, {
          message: "User not found",
          details: { userId },
        });
      }
      res.status(200).json({
        success: true,
        data: result,
        message: "User data retrieved successfully",
      });
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
            operation: "get user data",
          },
        },
      });
    }
  },

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
        ...cookieOptions,
        maxAge: 15 * 60 * 1000,
      });

      res.cookie("refreshToken", result.data.refreshToken, {
        ...cookieOptions,
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.status(200).json({
        success: true,
        data: {
          accessToken: result.data.accessToken,
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

  loginWithGoogle: async (req, res) => {
    try {
      const { token } = req.body;

      if (!token) {
        throw new AppError(ERROR_TYPES.MISSING_FIELDS, {
          missingFields: ["token"],
          message: "Google token is required",
        });
      }

      const ticket = await client.verifyIdToken({
        idToken: token,
        audience: process.env.GG_CLIENT_ID,
      });

      const payload = ticket.getPayload();
      if (!payload || !payload.email) {
        throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
          message: "Google token is invalid or missing email",
        });
      }

      const { sub: googleId, email, name, picture } = payload;

      const result = await userService.loginWithGoogle({
        userId: googleId,
        email,
        name,
        picture,
      });

      res.cookie("accessToken", result.data.accessToken, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000, 
      });

      res.cookie("refreshToken", result.data.refreshToken, {
        ...cookieOptions,
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.status(200).json({
        success: true,
        data: {
          accessToken: result.data.accessToken,
        },
        message: result.message || "Google login successful",
      });
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
          message: "Google login failed",
          details: {
            rawError: error.message,
            operation: "google login",
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

    res.cookie("refreshToken", result.data.refreshToken, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      success: true,
      accessToken: result.data.accessToken,
    });

  } catch (error) {
    res.clearCookie("refreshToken", cookieOptions);

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

      return res.status(200).json({
        success: true,
        message: "No active session. Already logged out.",
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

  listUsers: async (req, res) => {
    try {
      const { page = 1, limit = 10, search = "" } = req.query;

      const result = await userService.listUsers({
        page,
        limit: Math.min(limit, 100),
        search,
      });

      res.status(200).json({
        success: true,
        data: result.data,
        pagination: result.pagination,
        message: "Users retrieved successfully",
      });
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
            operation: "list users",
          },
        },
      });
    }
  },

  deleteUser: async (req, res) => {
    try {
      const userId = req.params.userId;
      const currentUserId = req.user.userId;

      const result = await userService.deleteUser(userId, currentUserId);
      res.status(200).json(result);
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
            operation: "delete user",
          },
        },
      });
    }
  },

  updateUser: async (req, res) => {
    try {
      const userId = req.params.userId;
      const updateData = req.body;

      const result = await userService.updateUser(userId, updateData);
      res.status(200).json(result);
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
            operation: "update user",
          },
        },
      });
    }
  },

  updateUserPassword: async (req, res) => {
    try {
      const userId = req.params.userId;
      const { currentPassword, newPassword } = req.body;

      if (!currentPassword || !newPassword) {
        throw new AppError(
          400,
          ERROR_TYPES.VALIDATION_ERROR.code,
          'Both currentPassword and newPassword are required.',
          { missingFields: ['currentPassword', 'newPassword'] }
        );
      }

      const result = await userService.updateUserPassword(userId, currentPassword, newPassword);
      res.status(200).json({ success: true, message: "Password updated successfully." });

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
            operation: "update user password",
          },
        },
      });
    }
  },
};

export default userController;
