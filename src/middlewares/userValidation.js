import Joi from "joi";

export const updateUserSchema = Joi.object({
  username: Joi.string().min(3).max(30).messages({
    "string.min": "Username must be at least 3 characters",
    "string.max": "Username cannot exceed 30 characters",
  }),
  email: Joi.string().email().messages({
    "string.email": "Please enter a valid email address",
  }),
  password: Joi.string().min(6).messages({
    "string.min": "Password must be at least 6 characters",
  }),
  role: Joi.string().valid("user", "admin"),
  isActive: Joi.boolean(),
  profile_picture: Joi.string(),
  description: Joi.string(),
  thumbnail: Joi.string()
}).min(1);
