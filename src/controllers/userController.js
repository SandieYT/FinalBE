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
      res.status(200).json(result);
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
      const { refreshToken } = req.body;

      if (!refreshToken) {
        throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
          issue: "missing_token",
          message: "Refresh token is required",
        });
      }

      const result = await userService.refreshToken(refreshToken);
      res.status(200).json(result);
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
};

export default userController;
