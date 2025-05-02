import express from 'express';
const router = express.Router();

import upload from '../middlewares/multer.js';
import uploadController from '../controllers/uploadController.js';

router.post('/', upload.single('image'), uploadController.uploadImage);

export default router;