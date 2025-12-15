import express from 'express'
import User from '../models/User.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { authenticate } from '../middleware/auth.js'

const router = express.Router()

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret'

console.log('JWT_SECRET loaded:', JWT_SECRET ? 'YES' : 'NO')


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

export default router
