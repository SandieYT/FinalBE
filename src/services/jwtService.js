import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const jwtService = {
  generateAccessToken: (payload) => {
    try {
      if (!payload) throw new Error("Payload is required for token generation");
      if (!process.env.ACCESS_TOKEN) {
        throw new Error("Access token is not configured");
      }

      return jwt.sign({ data: payload }, process.env.ACCESS_TOKEN, {
        expiresIn: "15m",
      });
    } catch (error) {
      console.error("[JWT] Access token generation failed:", error.message);
      throw new Error(`Access token generation failed: ${error.message}`);
    }
  },

  generateRefreshToken: (payload) => {
    try {
      if (!payload) throw new Error("Payload is required for token generation");
      if (!process.env.REFRESH_TOKEN) {
        throw new Error("Refresh token is not configured");
      }

      return jwt.sign({ data: payload }, process.env.REFRESH_TOKEN, {
        expiresIn: "7d",
      });
    } catch (error) {
      console.error("[JWT] Refresh token generation failed:", error.message);
      throw new Error(`Refresh token generation failed: ${error.message}`);
    }
  },

  verifyAccessToken: (token) => {
    try {
      if (!token) throw new Error("No access token provided");
      if (!process.env.ACCESS_TOKEN) {
        throw new Error("Access token is not configured");
      }

      const cleanToken = token.replace("Bearer ", "");
      return {
        valid: true,
        decoded: jwt.verify(cleanToken, process.env.ACCESS_TOKEN),
      };
    } catch (error) {
      console.error("[JWT] Access token verification failed:", error.message);

      return {
        valid: false,
        message: "Invalid access token",
        error: error.message,
        expired: error.name === "TokenExpiredError",
        code:
          error.name === "TokenExpiredError"
            ? "TOKEN_EXPIRED"
            : "INVALID_TOKEN",
      };
    }
  },

  verifyRefreshToken: (token) => {
    try {
      if (!token) throw new Error("No refresh token provided");
      if (!process.env.REFRESH_TOKEN) {
        throw new Error("Refresh token is not configured");
      }

      return {
        valid: true,
        decoded: jwt.verify(token, process.env.REFRESH_TOKEN),
      };
    } catch (error) {
      console.error("[JWT] Refresh token verification failed:", error.message);

      return {
        valid: false,
        message: "Invalid refresh token",
        error: error.message,
        expired: error.name === "TokenExpiredError",
        code:
          error.name === "TokenExpiredError"
            ? "TOKEN_EXPIRED"
            : "INVALID_TOKEN",
      };
    }
  },

  refreshTokenPair: async (refreshToken) => {
    try {
      if (!refreshToken) throw new Error("Refresh token is required");

      const { valid, decoded, message } =
        jwtService.verifyRefreshToken(refreshToken);
      if (!valid) throw new Error(message);

      const accessToken = jwtService.generateAccessToken(decoded.data);
      const newRefreshToken = jwtService.generateRefreshToken(decoded.data);

      return {
        status: "success",
        accessToken,
        refreshToken: newRefreshToken,
        message: "Token pair refreshed successfully",
      };
    } catch (error) {
      console.error("[JWT] Token refresh failed:", error.message);
      throw new Error(`Token refresh failed: ${error.message}`);
    }
  },
};

export default jwtService;
