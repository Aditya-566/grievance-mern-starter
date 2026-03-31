const express = require("express");
const cors = require("cors");
const path = require("path");
const dotenv = require("dotenv");
const connectDB = require("./config/db");
const errorHandler = require("./middleware/errorHandler");

// Route imports
const authRoutes = require("./routes/authRoutes");
const grievanceRoutes = require("./routes/grievanceRoutes");
const adminRoutes = require("./routes/adminRoutes");

dotenv.config();

const app = express();

// ── Middleware ──────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Serve uploaded files statically
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ── Database ───────────────────────────────────────────
connectDB();

// ── Routes ─────────────────────────────────────────────
app.get("/", (req, res) => {
  res.send("GrievEase API is running...");
});

app.use("/api/auth", authRoutes);
app.use("/api/grievance", grievanceRoutes);
app.use("/api/admin", adminRoutes);

// ── Error Handler ──────────────────────────────────────
app.use(errorHandler);

// ── Start Server ───────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
