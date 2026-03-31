const express = require("express");
const { body } = require("express-validator");
const { protect, adminOnly } = require("../middleware/authMiddleware");
const {
  getAllGrievances,
  updateGrievance,
  getStats,
  adminComment,
} = require("../controllers/adminController");

const router = express.Router();

// All admin routes require authentication + admin role
router.use(protect, adminOnly);

// GET /api/admin/stats – dashboard statistics
router.get("/stats", getStats);

// GET /api/admin/grievances – all grievances with search/filter/pagination
router.get("/grievances", getAllGrievances);

// PUT /api/admin/grievance/:id – update status / assignedTo
router.put("/grievance/:id", updateGrievance);

// POST /api/admin/grievance/:id/comment – admin comment
router.post(
  "/grievance/:id/comment",
  [body("text").trim().notEmpty().withMessage("Comment text is required")],
  adminComment
);

module.exports = router;
