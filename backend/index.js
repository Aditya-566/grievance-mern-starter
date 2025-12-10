import dotenv from "dotenv";
dotenv.config();

import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcrypt';

// Import your existing routes and models
import grievanceRoutes from './routes/grievanceRoutes.js';
import authRoutes from './routes/authRoutes.js';
import User from './models/User.js';

const app = express();

// --- CRITICAL CORS FIX ---
app.use(cors({
  origin: [
    "http://localhost:5173",             // Your local development
    "https://grievance-redressal-system-5.onrender.com", // Your Render Backend
    // ADD YOUR VERCEL URL BELOW (Allow any vercel.app subdomain for safety)
    /\.vercel\.app$/ 
  ],
  credentials: true
}));
// -------------------------

app.use(express.json());

// Routes
app.use('/api/grievances', grievanceRoutes);
app.use('/api/auth', authRoutes);

// Health Check Route (Good for Render to know app is alive)
app.get('/', (req, res) => res.send('API is running...'));

const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/grievance_db';

// Server Startup & Seeding
(async function start() {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    // --- SEEDING LOGIC (Preserved from your code) ---
    try {
      const passwordHash = await bcrypt.hash('password', 10);

      // 1. Admin User
      let admin = await User.findOne({ email: 'admin@example.com' });
      if (!admin) {
        admin = new User({
          email: 'admin@example.com',
          passwordHash,
          name: 'Admin User',
          role: 'admin'
        });
        await admin.save();
        console.log('👤 Created admin user: admin@example.com / password');
      } else if (admin.role !== 'admin') {
        admin.role = 'admin';
        await admin.save();
        console.log('👤 Updated admin privileges');
      }

      // 2. Regular User
      let user = await User.findOne({ email: 'user@example.com' });
      if (!user) {
        user = new User({
          email: 'user@example.com',
          passwordHash,
          name: 'Demo User',
          role: 'user'
        });
        await user.save();
        console.log('👤 Created regular user: user@example.com / password');
      }

    } catch (e) {
      console.error('⚠️ User seed error:', e.message);
    }
    // ------------------------------------------------

    app.listen(PORT, () => {
      console.log(`🚀 Server listening on port ${PORT}`);
    });

  } catch (err) {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  }
})();