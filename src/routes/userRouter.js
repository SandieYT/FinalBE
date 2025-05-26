import express from "express";
const router = express.Router();

import userController from "../controllers/userController.js";
import { authenticate, authorize, handleTokenRefresh } from "../middlewares/authMiddleware.js";

router.post("/register", userController.createUser); 
router.post("/login", userController.loginUser);
router.post("/refresh-token", userController.refreshToken);
router.post("/logout", authenticate, userController.logoutUser);
router.get("/profile", authenticate, handleTokenRefresh, userController.getUser);
router.get("/admin", authenticate, handleTokenRefresh, authorize(['admin']), userController.listUsers);
router.delete("/delete/:userId", authenticate, handleTokenRefresh, authorize(["admin"]), userController.deleteUser);
router.put("/update/:userId", authenticate, handleTokenRefresh, authorize(["admin"], { allowSelf: true }), userController.updateUser);
router.get("/get/:userId", authenticate, handleTokenRefresh, authorize(["admin"], { allowSelf: true }), userController.getUser);

export default router;