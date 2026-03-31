const { validationResult } = require("express-validator");
const Grievance = require("../models/Grievance");
const Comment = require("../models/Comment");

// @desc    Create a new grievance
// @route   POST /api/grievance/create
const createGrievance = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }

    const { title, description, category, priority } = req.body;
    const attachment = req.file ? req.file.filename : "";

    const grievance = await Grievance.create({
      title,
      description,
      category: category || "Other",
      priority: priority || "Medium",
      user: req.user._id,
      attachment,
    });

    res.status(201).json(grievance);
  } catch (err) {
    next(err);
  }
};

// @desc    Get current user's grievances (with search, filter, pagination)
// @route   GET /api/grievance/my
const getMyGrievances = async (req, res, next) => {
  try {
    const { status, category, search, page = 1, limit = 10 } = req.query;
    const query = { user: req.user._id };

    if (status) query.status = status;
    if (category) query.category = category;
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await Grievance.countDocuments(query);
    const grievances = await Grievance.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    res.json({ grievances, total, page: parseInt(page), pages: Math.ceil(total / parseInt(limit)) });
  } catch (err) {
    next(err);
  }
};

// @desc    Get single grievance by ID
// @route   GET /api/grievance/:id
const getGrievanceById = async (req, res, next) => {
  try {
    const grievance = await Grievance.findById(req.params.id).populate("user", "name email");
    if (!grievance) {
      return res.status(404).json({ message: "Grievance not found" });
    }

    // Only owner or admin can view
    if (grievance.user._id.toString() !== req.user._id.toString() && req.user.role !== "admin") {
      return res.status(403).json({ message: "Not authorized to view this grievance" });
    }

    // Get comments for this grievance
    const comments = await Comment.find({ grievance: grievance._id })
      .populate("user", "name role")
      .sort({ createdAt: 1 });

    res.json({ grievance, comments });
  } catch (err) {
    next(err);
  }
};

// @desc    Add comment to a grievance
// @route   POST /api/grievance/:id/comment
const addComment = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }

    const grievance = await Grievance.findById(req.params.id);
    if (!grievance) {
      return res.status(404).json({ message: "Grievance not found" });
    }

    // Only owner or admin can comment
    if (grievance.user.toString() !== req.user._id.toString() && req.user.role !== "admin") {
      return res.status(403).json({ message: "Not authorized" });
    }

    const comment = await Comment.create({
      grievance: grievance._id,
      user: req.user._id,
      text: req.body.text,
    });

    const populated = await comment.populate("user", "name role");
    res.status(201).json(populated);
  } catch (err) {
    next(err);
  }
};

module.exports = { createGrievance, getMyGrievances, getGrievanceById, addComment };
