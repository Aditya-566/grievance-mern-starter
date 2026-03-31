const { validationResult } = require("express-validator");
const Grievance = require("../models/Grievance");
const Comment = require("../models/Comment");

// @desc    Get all grievances (admin) with search, filter, pagination
// @route   GET /api/admin/grievances
const getAllGrievances = async (req, res, next) => {
  try {
    const { status, category, priority, search, page = 1, limit = 10 } = req.query;
    const query = {};

    if (status) query.status = status;
    if (category) query.category = category;
    if (priority) query.priority = priority;
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await Grievance.countDocuments(query);
    const grievances = await Grievance.find(query)
      .populate("user", "name email")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    res.json({ grievances, total, page: parseInt(page), pages: Math.ceil(total / parseInt(limit)) });
  } catch (err) {
    next(err);
  }
};

// @desc    Update grievance status / assignedTo (admin)
// @route   PUT /api/admin/grievance/:id
const updateGrievance = async (req, res, next) => {
  try {
    const grievance = await Grievance.findById(req.params.id);
    if (!grievance) {
      return res.status(404).json({ message: "Grievance not found" });
    }

    const { status, assignedTo } = req.body;
    if (status) grievance.status = status;
    if (assignedTo !== undefined) grievance.assignedTo = assignedTo;

    await grievance.save();
    const updated = await Grievance.findById(grievance._id).populate("user", "name email");
    res.json(updated);
  } catch (err) {
    next(err);
  }
};

// @desc    Get dashboard stats (admin)
// @route   GET /api/admin/stats
const getStats = async (req, res, next) => {
  try {
    const total = await Grievance.countDocuments();
    const pending = await Grievance.countDocuments({ status: "Pending" });
    const inProgress = await Grievance.countDocuments({ status: "In Progress" });
    const resolved = await Grievance.countDocuments({ status: "Resolved" });
    const rejected = await Grievance.countDocuments({ status: "Rejected" });

    // Category breakdown
    const byCategory = await Grievance.aggregate([
      { $group: { _id: "$category", count: { $sum: 1 } } },
    ]);

    // Priority breakdown
    const byPriority = await Grievance.aggregate([
      { $group: { _id: "$priority", count: { $sum: 1 } } },
    ]);

    res.json({ total, pending, inProgress, resolved, rejected, byCategory, byPriority });
  } catch (err) {
    next(err);
  }
};

// @desc    Admin add comment on a grievance
// @route   POST /api/admin/grievance/:id/comment
const adminComment = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }

    const grievance = await Grievance.findById(req.params.id);
    if (!grievance) {
      return res.status(404).json({ message: "Grievance not found" });
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

module.exports = { getAllGrievances, updateGrievance, getStats, adminComment };
