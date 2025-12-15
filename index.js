import express from 'express'
import dotenv from 'dotenv'
dotenv.config()
import mongoose from 'mongoose'
import cors from 'cors'
import passport from 'passport'
import session from 'express-session'


import grievanceRoutes from './routes/grievanceRoutes.js'
import authRoutes from './routes/authRoutes.js'
import User from './models/User.js'
import bcrypt from 'bcrypt'


const app = express()
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://grievance-platform.vercel.app'

app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
  })
)



app.use(express.json())
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev_session_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Use HTTPS in production
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}))
app.use(passport.initialize())
app.use(passport.session())




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
