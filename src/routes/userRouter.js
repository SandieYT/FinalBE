import express from "express";
const router = express.Router();

import userController from "../controllers/userController.js";
import { authenticate, authorize } from "../middlewares/authMiddleware.js";

router.post("/data-user", authenticate, userController.getUser);
router.post("/register", userController.createUser); 
router.post("/login", userController.loginUser);
router.post("/refresh-token", userController.refreshToken);
router.post("/logout", authenticate, userController.logoutUser);
// router.get("/admin/users", authenticate, authorize(['admin']), userController.listUsers);

export default router;