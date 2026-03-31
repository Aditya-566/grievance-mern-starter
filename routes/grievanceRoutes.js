const express = require("express");
const { body } = require("express-validator");
const { protect } = require("../middleware/authMiddleware");
const upload = require("../middleware/upload");
const {
  createGrievance,
  getMyGrievances,
  getGrievanceById,
  addComment,
} = require("../controllers/grievanceController");

const router = express.Router();

// POST /api/grievance/create – submit a new grievance with optional file
router.post(
  "/create",
  protect,
  upload.single("file"),
  [body("title").trim().notEmpty().withMessage("Title is required")],
  createGrievance
);

// GET /api/grievance/my – user's grievances (search, filter, paginate)
router.get("/my", protect, getMyGrievances);

// GET /api/grievance/:id – single grievance detail
router.get("/:id", protect, getGrievanceById);

// POST /api/grievance/:id/comment – add comment
router.post(
  "/:id/comment",
  protect,
  [body("text").trim().notEmpty().withMessage("Comment text is required")],
  addComment
);

module.exports = router;
