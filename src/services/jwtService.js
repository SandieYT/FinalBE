import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { ERROR_TYPES, AppError } from "../utils/errorTypes.js";

dotenv.config();

const jwtService = {
  generateAccessToken: (payload) => {
    try {
      if (!payload)
        throw new AppError(ERROR_TYPES.VALIDATION_ERROR, {
          field: "payload",
          message: "Payload is required",
        });

      if (!process.env.ACCESS_TOKEN) {
        throw new AppError(ERROR_TYPES.INTERNAL_ERROR, {
          config: "ACCESS_TOKEN",
          message: "Access token secret not configured",
        });
      }

      return jwt.sign({ data: payload }, process.env.ACCESS_TOKEN, {
        expiresIn: "5s",
      });
    } catch (error) {
      throw new AppError(ERROR_TYPES.INTERNAL_ERROR, {
        operation: "token_generation",
        tokenType: "access",
        rawError: error.message,
      });
    }
  },

  generateRefreshToken: (payload) => {
    try {
      if (!payload)
        throw new AppError(ERROR_TYPES.VALIDATION_ERROR, {
          field: "payload",
          message: "Payload is required",
        });

      if (!process.env.REFRESH_TOKEN) {
        throw new AppError(ERROR_TYPES.INTERNAL_ERROR, {
          config: "REFRESH_TOKEN",
          message: "Refresh token secret not configured",
        });
      }

      return jwt.sign({ data: payload }, process.env.REFRESH_TOKEN, {
        expiresIn: "7d",
      });
    } catch (error) {
      throw new AppError(ERROR_TYPES.INTERNAL_ERROR, {
        operation: "token_generation",
        tokenType: "refresh",
        rawError: error.message,
      });
    }
  },

  verifyAccessToken: (token) => {
    try {
      if (!token)
        throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
          issue: "missing_token",
          tokenType: "access",
        });

      if (!process.env.ACCESS_TOKEN) {
        throw new AppError(ERROR_TYPES.INTERNAL_ERROR, {
          config: "ACCESS_TOKEN",
          message: "Access token secret not configured",
        });
      }

      const cleanToken = token.replace("Bearer ", "");
      const decoded = jwt.verify(cleanToken, process.env.ACCESS_TOKEN);

      return {
        valid: true,
        decoded,
      };
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        throw new AppError(ERROR_TYPES.TOKEN_EXPIRED, {
          tokenType: "access",
          expiredAt: error.expiredAt,
        });
      }
      throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
        tokenType: "access",
        rawError: error.message,
      });
    }
  },

  verifyRefreshToken: (token) => {
    try {
      if (!token)
        throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
          issue: "missing_token",
          tokenType: "refresh",
        });

      if (!process.env.REFRESH_TOKEN) {
        throw new AppError(ERROR_TYPES.INTERNAL_ERROR, {
          config: "REFRESH_TOKEN",
          message: "Refresh token secret not configured",
        });
      }

      const decoded = jwt.verify(token, process.env.REFRESH_TOKEN);

      return {
        valid: true,
        decoded,
      };
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        throw new AppError(ERROR_TYPES.TOKEN_EXPIRED, {
          tokenType: "refresh",
          expiredAt: error.expiredAt,
        });
      }
      throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
        tokenType: "refresh",
        rawError: error.message,
      });
    }
  },

  refreshTokenPair: async (refreshToken) => {
    try {
      if (!refreshToken)
        throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
          issue: "missing_token",
          tokenType: "refresh",
        });

      const { valid, decoded } = jwtService.verifyRefreshToken(refreshToken);
      if (!valid) throw new AppError(ERROR_TYPES.INVALID_TOKEN);

      const accessToken = jwtService.generateAccessToken(decoded.data);
      const newRefreshToken = jwtService.generateRefreshToken(decoded.data);

      return {
        status: "success",
        accessToken,
        refreshToken: newRefreshToken,
        message: "Token pair refreshed successfully",
      };
    } catch (error) {
      throw new AppError(ERROR_TYPES.INTERNAL_ERROR, {
        operation: "token_refresh",
        rawError: error.message,
      });
    }
  },
};

export default jwtService;
