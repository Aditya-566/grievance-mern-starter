import React, { useState } from 'react'
import axios from 'axios'

// Use Vite environment variable
const API = import.meta.env.VITE_API_URL;

export default function Login({ onLoggedIn, initialEmail }) {
  const [isSignUp, setIsSignUp] = useState(false)
  const [email, setEmail] = useState(initialEmail || '')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [fieldErrors, setFieldErrors] = useState({})

  async function submit(e) {
    e.preventDefault()
    setError('')

    const errs = {}

    if (!email) errs.email = 'Email is required'
    else if (!/^\S+@\S+\.\S+$/.test(email)) errs.email = 'Enter a valid email'

    if (!password) errs.password = 'Password is required'
    else if (password.length < 6) errs.password = 'Password must be at least 6 characters'

    if (isSignUp && !name) errs.name = 'Name is required'

    setFieldErrors(errs)
    if (Object.keys(errs).length) return

    setLoading(true)

    try {
      if (isSignUp) {
        // Register new user
        await axios.post(`${API}/api/auth/register`, { email, password, name })

        // Auto-login after registration
        const res = await axios.post(`${API}/api/auth/login`, { email, password })
        onLoggedIn && onLoggedIn(res.data)

      } else {
        // Login existing user
        const res = await axios.post(`${API}/api/auth/login`, { email, password })
        onLoggedIn && onLoggedIn(res.data)
      }

    } catch (err) {
      console.error('Login/Register error:', err)
      const status = err?.response?.status

      if (!err.response) {
        setError('Network error: Unable to reach server.')
      } else if (isSignUp) {
        if (status === 409) setError('This email is already registered.')
        else setError(err.response?.data?.error || 'Registration failed.')
      } else {
        if (status === 401) setError('Invalid email or password')
        else setError(err.response?.data?.error || 'Login failed.')
      }

    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      {/* UI Code remains unchanged */}
      {/* (I kept the UI exactly the same as yours) */}

      <div className="login-container">
        <div className="login-card" data-tilt>

          <div className="login-header">
            <h1 className="login-title">
              <span className="title-highlight">
                {isSignUp ? 'Create Account' : 'Welcome Back'}
              </span>
            </h1>
            <p className="login-subtitle">
              {isSignUp ? 'Sign up to get started' : 'Sign in to continue'}
            </p>
          </div>

          <form onSubmit={submit} className="login-form">

            {isSignUp && (
              <div className="field-row login-field">
                <label>Name</label>
                <input
                  value={name}
                  onChange={e => setName(e.target.value)}
                  placeholder="Enter your name"
                  type="text"
                />
                {fieldErrors.name && <div className="field-error">{fieldErrors.name}</div>}
              </div>
            )}

            <div className="field-row login-field">
              <label>Email</label>
              <input
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="you@example.com"
                type="email"
              />
              {fieldErrors.email && <div className="field-error">{fieldErrors.email}</div>}
            </div>

            <div className="field-row login-field">
              <label>Password</label>
              <input
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="Enter password"
                type={showPassword ? 'text' : 'password'}
              />
              {fieldErrors.password && <div className="field-error">{fieldErrors.password}</div>}
            </div>

            {error && (
              <div className="alert alert-error login-alert">⚠️ {error}</div>
            )}

            <button className="login-btn" type="submit" disabled={loading}>
              {loading ? 'Please wait...' : isSignUp ? 'Create Account' : 'Sign In'}
            </button>

            <div className="login-toggle">
              <button
                type="button"
                onClick={() => {
                  setIsSignUp(!isSignUp)
                  setError('')
                  setFieldErrors({})
                }}
              >
                {isSignUp ? 'Already have an account? Sign in' : 'No account? Sign up'}
              </button>
            </div>
          </form>

        </div>
      </div>
    </div>
  )
}
