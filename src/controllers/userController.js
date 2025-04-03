import userService from "../services/userService.js";

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
        return res.status(400).json({
          status: "error",
          message: `Required fields missing: ${missingFields.join(", ")}`,
          errorCode: "MISSING_FIELDS",
        });
      }

      if (req.body.password !== req.body.confirmPassword) {
        return res.status(400).json({
          status: "error",
          message: "Password confirmation does not match",
          errorCode: "PASSWORD_MISMATCH",
        });
      }

      const result = await userService.createUser(req.body);
      return res.status(201).json(result);
    } catch (error) {
      const statusCode =
        error.message.includes("already exists") ||
        error.message.includes("Validation failed") ||
        error.message.includes("invalid")
          ? 400
          : 500;

      return res.status(statusCode).json({
        status: "error",
        message: error.message || "Internal server error",
        errorCode: statusCode === 400 ? "VALIDATION_ERROR" : "SERVER_ERROR",
      });
    }
  },

  loginUser: async (req, res) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          status: "error",
          message: "Both email and password are required",
          errorCode: "MISSING_CREDENTIALS",
        });
      }

      const result = await userService.loginUser({ email, password });
      return res.status(200).json(result);
    } catch (error) {
      const statusCode =
        error.message.includes("Authentication failed") ||
        error.message.includes("Account error")
          ? 400
          : 500;

      return res.status(statusCode).json({
        status: "error",
        message: error.message || "Internal server error",
        errorCode: statusCode === 400 ? "AUTHENTICATION_ERROR" : "SERVER_ERROR",
      });
    }
  },
};

export default userController;
