import jwtService from "../services/jwtService.js";
import { ERROR_TYPES, AppError } from "../utils/errorTypes.js";

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
        throw new AppError(ERROR_TYPES.TOKEN_EXPIRED, {
          tokenType: "access",
          message: "Session expired, please login again",
        });
      }
      throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
        issue: "invalid_token",
        tokenType: "access",
        message: "Invalid authentication token",
      });
    }
  } catch (error) {
    const response = {
      success: false,
      error: {
        code: error.code || ERROR_TYPES.INTERNAL_ERROR.code,
        message: error.message,
        details: error.details || {
          operation: "authentication",
          tokenType: "access",
        },
      },
    };

    const statusCode = error.status || ERROR_TYPES.INTERNAL_ERROR.status;

    if (
      error.code === ERROR_TYPES.INVALID_TOKEN.code ||
      error.code === ERROR_TYPES.TOKEN_EXPIRED.code
    ) {
      res.clearCookie("accessToken");
      res.clearCookie("refreshToken");
    }

    return res.status(statusCode).json(response);
  }
};

export const authorize = (roles = []) => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        throw new AppError(ERROR_TYPES.AUTHENTICATION_FAILED, {
          message: "User not authenticated",
        });
      }

      if (!roles.includes(req.user.role)) {
        throw new AppError(ERROR_TYPES.FORBIDDEN, {
          requiredRoles: roles,
          userRole: req.user.role,
          message: "Insufficient permissions",
        });
      }
      next();
    } catch (error) {
      const statusCode = error.status || ERROR_TYPES.INTERNAL_ERROR.status;
      res.status(statusCode).json({
        success: false,
        error: {
          code: error.code,
          message: error.message,
          details: error.details,
        },
      });
    }
  };
};
