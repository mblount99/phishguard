import express from "express";
import { scanUrl, analyzeEmail } from "./services/riskEngine.js";

const router = express.Router();

router.post("/scan-url", scanUrl);
router.post("/analyze-email", analyzeEmail);

export default router;
