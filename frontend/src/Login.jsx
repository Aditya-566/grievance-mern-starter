import React, { useState } from 'react'
import axios from 'axios'

export default function Login({ onLoggedIn, initialEmail }) {
  const [isSignUp, setIsSignUp] = useState(false)
  const [email, setEmail] = useState(initialEmail || '')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function submit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      if (isSignUp) {
        await axios.post('/api/auth/register', { email, password, name })
        const res = await axios.post('/api/auth/login', { email, password })
        onLoggedIn && onLoggedIn(res.data)
      } else {
        const res = await axios.post('/api/auth/login', { email, password })
        onLoggedIn && onLoggedIn(res.data)
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Connection failed. Please check the backend.');
    } finally { 
      setLoading(false) 
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-900 relative overflow-hidden">
      {/* Abstract Background Blobs */}
      <div className="absolute top-0 left-0 w-full h-full overflow-hidden z-0">
          <div className="absolute top-[-10%] right-[-5%] w-96 h-96 bg-purple-600/20 rounded-full blur-3xl"></div>
          <div className="absolute bottom-[-10%] left-[-5%] w-96 h-96 bg-indigo-600/20 rounded-full blur-3xl"></div>
      </div>

      <div className="relative z-10 w-full max-w-md p-8 bg-slate-800/50 backdrop-blur-xl border border-slate-700 rounded-2xl shadow-2xl">
        <div className="text-center mb-8">
            <h2 className="text-3xl font-bold text-white mb-2">
                {isSignUp ? 'Get Started' : 'Welcome Back'}
            </h2>
            <p className="text-slate-400">
                {isSignUp ? 'Create your account to continue' : 'Enter your details to sign in'}
            </p>
        </div>

        {error && (
            <div className="mb-6 p-3 bg-red-500/10 border border-red-500/20 text-red-200 text-sm rounded-lg text-center animate-pulse">
                {error}
            </div>
        )}

        <form onSubmit={submit} className="space-y-5">
            {isSignUp && (
                <input 
                    className="w-full px-4 py-3 bg-slate-900/50 border border-slate-600 rounded-lg focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-white outline-none transition-all"
                    placeholder="Full Name"
                    value={name} onChange={e => setName(e.target.value)} required 
                />
            )}
            <input 
                type="email" 
                className="w-full px-4 py-3 bg-slate-900/50 border border-slate-600 rounded-lg focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-white outline-none transition-all"
                placeholder="Email Address"
                value={email} onChange={e => setEmail(e.target.value)} required 
            />
            <input 
                type="password" 
                className="w-full px-4 py-3 bg-slate-900/50 border border-slate-600 rounded-lg focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-white outline-none transition-all"
                placeholder="Password"
                value={password} onChange={e => setPassword(e.target.value)} required 
            />

            <button 
                type="submit" 
                disabled={loading}
                className="w-full py-3.5 bg-indigo-600 hover:bg-indigo-500 text-white font-bold rounded-lg shadow-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed">
                {loading ? 'Processing...' : (isSignUp ? 'Create Account' : 'Sign In')}
            </button>
        </form>

        <div className="mt-6 text-center">
            <button 
                onClick={() => { setIsSignUp(!isSignUp); setError(''); }} 
                className="text-sm text-slate-400 hover:text-indigo-400 transition-colors">
                {isSignUp ? 'Already have an account? Sign In' : "Don't have an account? Sign Up"}
            </button>
        </div>
      </div>
    </div>
  )
}