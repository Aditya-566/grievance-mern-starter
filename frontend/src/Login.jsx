import React, { useState } from 'react'
import axios from 'axios'
import { 
  Mail, 
  Lock, 
  User as UserIcon, 
  Eye, 
  EyeOff,
  Shield,
  AlertCircle,
  CheckCircle
} from 'lucide-react'

export default function Login({ onLoggedIn, initialEmail }) {
  const [isSignUp, setIsSignUp] = useState(false)
  const [email, setEmail] = useState(initialEmail || '')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [rememberMe, setRememberMe] = useState(!!initialEmail)

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
      
      if (rememberMe) {
        localStorage.setItem('rememberEmail', email)
      } else {
        localStorage.removeItem('rememberEmail')
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Connection failed. Please check the backend.')
    } finally { 
      setLoading(false) 
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 to-slate-950 relative overflow-hidden">
      {/* Background Animation */}
      <div className="absolute inset-0">
        <div className="absolute top-0 left-0 w-96 h-96 bg-purple-600/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-0 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl animate-pulse delay-1000"></div>
      </div>

      <div className="relative z-10 w-full max-w-md p-0">
        <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800 rounded-3xl shadow-2xl overflow-hidden">
          {/* Header */}
          <div className="p-8 pb-0">
            <div className="flex items-center justify-center mb-8">
              <div className="p-3 bg-gradient-to-br from-indigo-500 to-purple-500 rounded-xl">
                <Shield className="w-8 h-8 text-white" />
              </div>
            </div>
            
            <div className="text-center mb-8">
              <h2 className="text-3xl font-bold text-white mb-2">
                {isSignUp ? 'Create Account' : 'Welcome Back'}
              </h2>
              <p className="text-slate-400">
                {isSignUp ? 'Join thousands of satisfied users' : 'Sign in to your account to continue'}
              </p>
            </div>
          </div>

          {/* Form */}
          <div className="p-8 pt-0">
            {error && (
              <div className="mb-6 p-4 bg-rose-500/10 border border-rose-500/20 rounded-xl">
                <div className="flex items-center gap-3">
                  <AlertCircle className="w-5 h-5 text-rose-400 flex-shrink-0" />
                  <p className="text-sm text-rose-200">{error}</p>
                </div>
              </div>
            )}

            <form onSubmit={submit} className="space-y-5">
              {isSignUp && (
                <div className="relative">
                  <UserIcon className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-400" />
                  <input 
                    className="w-full pl-12 pr-4 py-3.5 bg-slate-800/50 border border-slate-700 rounded-xl focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 text-white placeholder-slate-400 outline-none transition-all"
                    placeholder="Full Name"
                    value={name} 
                    onChange={e => setName(e.target.value)} 
                    required 
                  />
                </div>
              )}
              
              <div className="relative">
                <Mail className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-400" />
                <input 
                  type="email" 
                  className="w-full pl-12 pr-4 py-3.5 bg-slate-800/50 border border-slate-700 rounded-xl focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 text-white placeholder-slate-400 outline-none transition-all"
                  placeholder="Email Address"
                  value={email} 
                  onChange={e => setEmail(e.target.value)} 
                  required 
                />
              </div>
              
              <div className="relative">
                <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-400" />
                <input 
                  type={showPassword ? "text" : "password"} 
                  className="w-full pl-12 pr-12 py-3.5 bg-slate-800/50 border border-slate-700 rounded-xl focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 text-white placeholder-slate-400 outline-none transition-all"
                  placeholder="Password"
                  value={password} 
                  onChange={e => setPassword(e.target.value)} 
                  required 
                />
                <button 
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-4 top-1/2 transform -translate-y-1/2 text-slate-400 hover:text-slate-300"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>

              {!isSignUp && (
                <div className="flex items-center justify-between">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input 
                      type="checkbox" 
                      checked={rememberMe}
                      onChange={(e) => setRememberMe(e.target.checked)}
                      className="w-4 h-4 rounded border-slate-700 bg-slate-800 text-indigo-600 focus:ring-indigo-500 focus:ring-offset-slate-900"
                    />
                    <span className="text-sm text-slate-400">Remember me</span>
                  </label>
                  <button type="button" className="text-sm text-indigo-400 hover:text-indigo-300 transition-colors">
                    Forgot password?
                  </button>
                </div>
              )}

              <button 
                type="submit" 
                disabled={loading}
                className="w-full py-4 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white font-bold rounded-xl shadow-lg transition-all transform hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
              >
                {loading ? (
                  <div className="flex items-center justify-center gap-2">
                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    Processing...
                  </div>
                ) : (isSignUp ? 'Create Account' : 'Sign In')}
              </button>
            </form>

            <div className="mt-8 pt-8 border-t border-slate-800">
              <div className="text-center">
                <button 
                  onClick={() => { setIsSignUp(!isSignUp); setError(''); }} 
                  className="text-slate-400 hover:text-white transition-colors font-medium"
                >
                  {isSignUp ? (
                    <div className="flex items-center justify-center gap-2">
                      <span>Already have an account?</span>
                      <span className="text-indigo-400">Sign In</span>
                    </div>
                  ) : (
                    <div className="flex items-center justify-center gap-2">
                      <span>Don't have an account?</span>
                      <span className="text-indigo-400">Sign Up</span>
                    </div>
                  )}
                </button>
              </div>
              
              {!isSignUp && (
                <div className="mt-6 p-4 bg-slate-800/30 rounded-xl">
                  <div className="flex items-center gap-3 mb-2">
                    <CheckCircle className="w-4 h-4 text-emerald-400" />
                    <span className="text-sm text-slate-300 font-medium">Demo Accounts</span>
                  </div>
                  <div className="text-xs text-slate-400 space-y-1">
                    <p>Admin: admin@example.com / password</p>
                    <p>User: user@example.com / password</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}