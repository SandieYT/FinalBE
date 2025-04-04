import express from "express";
const router = express.Router();

import userController from "../controllers/userController.js";

router.post("/register", userController.createUser);
router.post("/login", userController.loginUser);
router.post("/refresh-token", userController.refreshToken);

export default router;
