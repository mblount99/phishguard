import "./config.js"; // 🔥 MUST BE FIRST

import express from "express";
import cors from "cors";
import routes from "./routes.js";

const app = express();

app.use(cors());

app.use((req, res, next) => {
  if (req.originalUrl === "/api/webhook") {
    next();
  } else {
    express.json()(req, res, next);
  }
});

app.use("/api", routes);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
