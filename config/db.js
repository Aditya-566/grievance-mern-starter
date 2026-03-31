const mongoose = require("mongoose");

const connectDB = async () => {
  const uri = process.env.MONGO_URI;

  if (!uri) {
    console.error("❌ MONGO_URI is not defined in .env file. Please add it to your environment variables.");
    process.exit(1);
  }
  
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
