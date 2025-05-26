import express from 'express';
const router = express.Router();

import upload from '../middlewares/multer.js';
import uploadController from '../controllers/uploadController.js';
import { setUploadPreset } from '../middlewares/uploadMiddleware.js';
import { authenticate } from "../middlewares/authMiddleware.js";

router.post('/pfp', setUploadPreset('profile'), upload.single('image'), uploadController.uploadImage);
router.post('/thumbnail', setUploadPreset('thumbnail'), upload.single('image'), uploadController.uploadImage);

export default router;