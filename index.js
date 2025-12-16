import express from 'express'
import dotenv from 'dotenv'
dotenv.config()
import mongoose from 'mongoose'
import cors from 'cors'

import grievanceRoutes from './routes/grievanceRoutes.js'
import authRoutes from './routes/authRoutes.js'
import User from './models/User.js'
import bcrypt from 'bcrypt'

0
const app = express()
const FRONTEND_URL = (process.env.FRONTEND_URL || 'https://grievance-platform.vercel.app').replace(/"/g, '').trim()
const NODE_ENV = process.env.NODE_ENV || 'development'

console.log('Environment:', NODE_ENV)
console.log('Frontend URL:', FRONTEND_URL)
console.log('MongoDB URI configured:', !!process.env.MONGODB_URI)

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true)

      // Allow the configured frontend URL
      if (origin === FRONTEND_URL) return callback(null, true)

      // In development, allow localhost
      if (NODE_ENV === 'development' && origin && origin.startsWith('http://localhost:')) {
        return callback(null, true)
      }

      // Allow Vercel preview deployments
      if (origin && (origin.includes('vercel-preview') || origin.includes('vercel.app'))) {
        return callback(null, true)
      }

      console.log('CORS blocked origin:', origin, 'Allowed:', FRONTEND_URL)
      return callback(new Error(`CORS policy violation: ${origin} not allowed`))
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With']
  })



app.use(express.json())




// local logging helpers (avoid global name collisions)
function _safeLog(...args){
  try{
    if(globalThis.console && typeof globalThis.console.log === 'function') return console.log(...args)
  }catch(e){}
  try{ process.stdout.write(args.map(a=>String(a)).join(' ') + '\n') }catch(e){}
}
function _safeError(...args){
  try{
    if(globalThis.console && typeof globalThis.console.error === 'function') return console.error(...args)
  }catch(e){}
  try{ process.stderr.write(args.map(a=>String(a)).join(' ') + '\n') }catch(e){}
}

process.on('uncaughtException', (err)=> {
  try{ process.stderr.write('uncaughtException ' + (err && err.stack ? err.stack : String(err)) + '\n') }catch(e){}
  process.exit(1)
})
process.on('unhandledRejection', (reason)=> {
  try{ process.stderr.write('unhandledRejection ' + (reason && reason.stack ? reason.stack : String(reason)) + '\n') }catch(e){}
})

// routes
app.use('/api/grievances', grievanceRoutes)
app.use('/api/auth', authRoutes)

// Health check endpoint
app.get('/api/health', (req, res) => {
  const health = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    mongodb: {
      connected: mongoose.connection.readyState === 1,
      state: mongoose.connection.readyState,
      name: mongoose.connection.name
    },
    cors: {
      frontend_url: FRONTEND_URL,
      request_origin: req.headers.origin,
      allowed: req.headers.origin === FRONTEND_URL || !req.headers.origin
    },
    server: {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      version: process.version
    }
  }

  const statusCode = health.mongodb.connected ? 200 : 503
  res.status(statusCode).json(health)
})

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err.message)
  console.error('Stack:', err.stack)
  console.error('Origin:', req.headers.origin)
  console.error('Method:', req.method)
  console.error('URL:', req.url)

  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      error: 'CORS policy violation',
      message: 'Origin not allowed',
      origin: req.headers.origin
    })
  }

  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  })
})

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found', path: req.originalUrl })
})

const PORT = process.env.PORT || 5000
const MONGODB_URI = process.env.MONGODB_URI

if (!MONGODB_URI) {
  console.error("❌ MONGODB_URI is missing")
  process.exit(1)
}


;(async function start(){
  try{
    await mongoose.connect(MONGODB_URI)
    try{ process.stdout.write('Connected to MongoDB\n') }catch(e){}

    app.listen(PORT, ()=> { try{ process.stdout.write('Server listening on ' + PORT + '\n') }catch(e){} })
  }catch(err){
    try{ process.stderr.write('MongoDB connection error ' + (err && err.stack ? err.stack : String(err)) + '\n') }catch(e){}
    process.exit(1)
  }
})()
