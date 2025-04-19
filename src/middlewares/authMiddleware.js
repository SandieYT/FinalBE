import jwtService from "../services/jwtService.js";
import { ERROR_TYPES, AppError } from "../utils/errorTypes.js";

export const authenticate = async (req, res, next) => {
  try {
    const token =
      req.cookies.accessToken || req.headers.authorization?.split(" ")[1];

    if (!token) {
      throw new AppError(ERROR_TYPES.INVALID_TOKEN, {
        issue: "missing_token",
        tokenType: "access",
      });
    }

    const { decoded } = jwtService.verifyAccessToken(token);
    req.user = decoded.data;
    next();
  } catch (error) {
    next(error);
  }
};

export const authorize = (roles = []) => {
  return (req, res, next) => {
    try {
      if (!roles.includes(req.user.role)) {
        throw new AppError(ERROR_TYPES.FORBIDDEN, {
          requiredRoles: roles,
          userRole: req.user.role,
        });
      }
      next();
    } catch (error) {
      next(error);
    }
  };
};
