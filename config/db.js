const mongoose = require("mongoose");

const connectDB = async () => {
  const uri = process.env.MONGO_URI;
  console.log("Connecting to MongoDB...");

  try {
    await mongoose.connect(uri, {});
    console.log("MongoDB connected successfully!");
  } catch (err) {
    console.error("❌ MongoDB Connection Error:");
    console.error(err);
    process.exit(1);
  }
};

module.exports = connectDB;
