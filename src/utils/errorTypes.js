export const ERROR_TYPES = {
  // Authentication
  AUTHENTICATION_FAILED: {
    code: "AUTH_001",
    status: 401,
    message: "Authentication failed",
  },
  INVALID_CREDENTIALS: {
    code: "AUTH_002",
    status: 401,
    message: "Invalid credentials",
  },
  TOKEN_EXPIRED: {
    code: "AUTH_003",
    status: 401,
    message: "Token expired",
  },
  INVALID_TOKEN: {
    code: "AUTH_004",
    status: 401,
    message: "Invalid token",
  },

  // Validation
  VALIDATION_ERROR: {
    code: "VAL_001",
    status: 400,
    message: "Validation error",
  },
  MISSING_FIELDS: {
    code: "VAL_002",
    status: 400,
    message: "Missing required fields",
  },
  PASSWORD_MISMATCH: {
    code: "VAL_003",
    status: 400,
    message: "Password confirmation does not match",
  },

  // User
  USER_EXISTS: {
    code: "USER_001",
    status: 409,
    message: "User already exists",
  },
  USER_NOT_FOUND: {
    code: "USER_002",
    status: 404,
    message: "User not found",
  },

  // Server
  INTERNAL_ERROR: {
    code: "SRV_001",
    status: 500,
    message: "Internal server error",
  },
};

export class AppError extends Error {
  constructor(errorType, details = null) {
    super(errorType.message);
    this.name = this.constructor.name;
    this.code = errorType.code;
    this.status = errorType.status;
    this.details = details;
    Error.captureStackTrace(this, this.constructor);
  }
}
