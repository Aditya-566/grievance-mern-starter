const mongoose = require("mongoose");

const grievanceSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, required: true },
    category: {
      type: String,
      enum: ["Academic", "Infrastructure", "Hostel", "Faculty", "Administration", "Other"],
      default: "Other",
    },
    priority: {
      type: String,
      enum: ["Low", "Medium", "High"],
      default: "Medium",
    },
    status: {
      type: String,
      enum: ["Pending", "In Progress", "Resolved", "Rejected"],
      default: "Pending",
    },
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    assignedTo: { type: String, default: "" },
    attachment: { type: String, default: "" }, // filename stored in uploads/
  },
  { timestamps: true }
);

// Index for search and filtering
grievanceSchema.index({ title: "text", description: "text" });
grievanceSchema.index({ user: 1, status: 1 });

module.exports = mongoose.model("Grievance", grievanceSchema);
