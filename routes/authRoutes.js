import express from 'express'
import User from '../models/User.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import passport from 'passport'
import { Strategy as GoogleStrategy } from 'passport-google-oauth20'
import { authenticate } from '../middleware/auth.js'



const router = express.Router()

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret'

// Google OAuth Strategy - only if credentials are provided
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BACKEND_URL || 'http://localhost:5000'}/api/auth/google/callback`
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id })
        if (!user) {
          // Check if email already exists
          const existingUser = await User.findOne({ email: profile.emails[0].value })
          if (existingUser) {
            // Link Google account to existing user
            existingUser.googleId = profile.id
            existingUser.avatar = profile.photos[0].value
            existingUser.isVerified = true
            await existingUser.save()
            return done(null, existingUser)
          } else {
            // Create new user
            user = new User({
              googleId: profile.id,
              email: profile.emails[0].value,
              name: profile.displayName,
              avatar: profile.photos[0].value,
              isVerified: true,
              role: 'user'
            })
            await user.save()
          }
        }
        return done(null, user)
      } catch (error) {
        return done(error, null)
      }
    }
  ))
}



// Google OAuth routes - only if credentials are provided
router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false
  })
)

router.get(
  '/google/callback',
  passport.authenticate('google', {
    failureRedirect: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/login`,
    session: false
  }),
  (req, res) => {
    const token = jwt.sign(
      { id: req.user._id, email: req.user.email, role: req.user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    )

    res.redirect(
      `${process.env.FRONTEND_URL || 'http://localhost:5173'}/login?token=${token}`
    )
  }
)

// register (optional)
router.post('/register', async (req,res) => {
  try{
    const { email, password, name } = req.body
    if(!email || !password) {
      return res.status(400).json({ error: 'Email and password required' })
    }
    const existing = await User.findOne({ email })
    if(existing) {
      return res.status(409).json({ error: 'User already exists' })
    }
    const passwordHash = await bcrypt.hash(password, 10)
    const u = new User({ email, passwordHash, name, role: 'user' })
    await u.save()
    res.status(201).json({ id: u._id, email: u.email, name: u.name, role: u.role })
  }catch(e){
    console.error('Registration error:', e)
    res.status(500).json({ error: e.message || 'Internal server error' })
  }
})

// login
router.post('/login', async (req,res)=>{
  try{
    const { email, password } = req.body
    if(!email || !password) {
      return res.status(400).json({ error: 'Email and password required' })
    }
    const user = await User.findOne({ email })
    if(!user) {
      return res.status(401).json({ error: 'Invalid email or password' })
    }
    const ok = await bcrypt.compare(password, user.passwordHash)
    if(!ok) {
      return res.status(401).json({ error: 'Invalid email or password' })
    }
    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' })
    res.json({ 
      token, 
      user: { 
        id: user._id, 
        email: user.email, 
        name: user.name, 
        role: user.role 
      } 
    })
  }catch(e){
    console.error('Login error:', e)
    res.status(500).json({ error: e.message || 'Internal server error' })
  }
})

// GET current user info
router.get('/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-passwordHash')
    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }
    res.json({ user })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})
router.get('/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-passwordHash')
    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }
    res.json({ user })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

export default router
