import jwtService from "../services/jwtService.js";
import { ERROR_TYPES, AppError } from "../utils/errorTypes.js";
import userService from "../services/userService.js";
import jwt from "jsonwebtoken";

export const authenticate = async (req, res, next) => {
  try {
    let token;

    if (req.cookies?.accessToken) {
      token = req.cookies.accessToken;
    } else if (req.headers.authorization?.startsWith("Bearer ")) {
      token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
      throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
        issue: "missing_token",
        tokenType: "access",
        message: "No authentication token provided",
      });
    }

    try {
      const { decoded } = jwtService.verifyAccessToken(token);
      req.user = decoded.data;
      next();
    } catch (verifyError) {
      if (verifyError.name === "TokenExpiredError") {
        req.tokenExpired = true;
        const decoded = jwt.decode(token);
        req.user = decoded.data;
        next();
        return;
      }
      throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
        issue: "invalid_token",
        tokenType: "access",
        message: "Invalid authentication token",
        rawError: verifyError.message,
      });
    }
  } catch (error) {
    const response = {
      success: false,
      error: {
        code: error.code || ERROR_TYPES.INTERNAL_ERROR.code,
        message: error.message,
        details: {
          ...(error.details || {}),
          operation: "authentication",
          tokenType: "access",
          ...(error.rawError ? { rawError: error.rawError } : {}),
        },
      },
    };

    const statusCode = error.status || ERROR_TYPES.INTERNAL_ERROR.status;
    return res.status(statusCode).json(response);
  }
};

export const authorize = (roles = []) => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        throw new AppError(ERROR_TYPES.AUTHENTICATION_FAILED, {
          message: "User not authenticated",
          operation: "authorization",
        });
      }

      if (!roles.includes(req.user.role)) {
        throw new AppError(ERROR_TYPES.FORBIDDEN, {
          requiredRoles: roles,
          userRole: req.user.role,
          message: "Insufficient permissions",
          operation: "authorization",
        });
      }
      next();
    } catch (error) {
      const response = {
        success: false,
        error: {
          code: error.code || ERROR_TYPES.INTERNAL_ERROR.code,
          message: error.message,
          details: {
            ...(error.details || {}),
            operation: "authorization",
            ...(error.rawError ? { rawError: error.rawError } : {}),
          },
        },
      };

      const statusCode = error.status || ERROR_TYPES.INTERNAL_ERROR.status;
      return res.status(statusCode).json(response);
    }
  };
};

export const handleTokenRefresh = async (req, res, next) => {
  if (req.tokenExpired) {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        error: {
          code: ERROR_TYPES.REFRESH_TOKEN_EXPIRED.code,
          message: "Session expired - please login again",
          details: {
            operation: "token_refresh",
            tokenType: "refresh",
          },
        },
      });
    }

    try {
      const newTokens = await userService.refreshToken(refreshToken);

      res.cookie(
        "accessToken",
        newTokens.data.accessToken,
        cookieOptions.accessToken
      );
      res.cookie(
        "refreshToken",
        newTokens.data.refreshToken,
        cookieOptions.refreshToken
      );

      const { decoded } = jwtService.verifyAccessToken(
        newTokens.data.accessToken
      );
      req.user = decoded.data;
      req.tokenRefreshed = true;

      return next();
    } catch (error) {
      const code =
        error.code === ERROR_TYPES.TOKEN_EXPIRED.code
          ? ERROR_TYPES.REFRESH_TOKEN_EXPIRED.code
          : error.code || ERROR_TYPES.INTERNAL_ERROR.code;

      return res.status(error.status || 401).json({
        success: false,
        error: {
          code,
          message: error.message,
          details: {
            ...error.details,
            operation: "token_refresh",
          },
        },
      });
    }
  }
  next();
};
