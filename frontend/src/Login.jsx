import React, { useState } from 'react'
import axios from 'axios'

// IMPORTANT: Use Vite API variable
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
        // REGISTER USER
        await axios.post(`${API}/api/auth/register`, { email, password, name })

        // Auto Login
        const res = await axios.post(`${API}/api/auth/login`, { email, password })
        onLoggedIn && onLoggedIn(res.data)

      } else {
        // LOGIN USER
        const res = await axios.post(`${API}/api/auth/login`, { email, password })
        onLoggedIn && onLoggedIn(res.data)
      }
    } catch (err) {
      const status = err?.response?.status

      if (!err.response) {
        setError('Network error: Unable to connect to server.')
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
      <div className="login-background">
        <div className="login-orb orb-left"></div>
        <div className="login-orb orb-right"></div>
        <div className="login-orb orb-center"></div>
        <div className="floating-shapes">
          <div className="shape shape-1"></div>
          <div className="shape shape-2"></div>
          <div className="shape shape-3"></div>
        </div>
      </div>

      <div className="login-container">
        <div className="login-card" data-tilt>

          <div className="login-header">
            <div className="login-icon-wrapper">
              <div className="login-icon">{isSignUp ? '✨' : '🔐'}</div>
            </div>
            <h1 className="login-title">
              <span className="title-highlight">
                {isSignUp ? 'Create Account' : 'Welcome Back'}
              </span>
            </h1>
            <p className="login-subtitle">
              {isSignUp
                ? 'Sign up with your email to get started'
                : 'Sign in to continue to your dashboard'}
            </p>
          </div>

          <form onSubmit={submit} className="login-form">
            {/* NAME FIELD — ONLY IN SIGNUP */}
            {isSignUp && (
              <div className="field-row login-field">
                <label htmlFor="login-name" className="field-label">
                  <span className="label-icon">👤</span>
                  Name
                </label>
                <div className="input-wrapper">
                  <input
                    id="login-name"
                    className={"login-input " + (fieldErrors.name ? 'input-error' : '')}
                    value={name}
                    onChange={e => setName(e.target.value)}
                    placeholder="Enter your name"
                    type="text"
                  />
                </div>
                {fieldErrors.name && <div className="field-error">{fieldErrors.name}</div>}
              </div>
            )}

            {/* EMAIL FIELD */}
            <div className="field-row login-field">
              <label htmlFor="login-email" className="field-label">
                <span className="label-icon">📧</span>
                Email
              </label>
              <div className="input-wrapper">
                <input
                  id="login-email"
                  className={"login-input " + (fieldErrors.email ? 'input-error' : '')}
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  type="email"
                />
              </div>
              {fieldErrors.email && <div className="field-error">{fieldErrors.email}</div>}
            </div>

            {/* PASSWORD FIELD */}
            <div className="field-row login-field">
              <label htmlFor="login-password" className="field-label">
                <span className="label-icon">🔒</span>
                Password
              </label>
              <div className="input-wrapper password-wrapper">
                <input
                  id="login-password"
                  className={"login-input " + (fieldErrors.password ? 'input-error' : '')}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  type={showPassword ? 'text' : 'password'}
                />

                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(s => !s)}
                >
                  {showPassword ? '🙈' : '👁️'}
                </button>
              </div>
              {fieldErrors.password && <div className="field-error">{fieldErrors.password}</div>}
            </div>

            {/* ERROR MESSAGE */}
            {error && (
              <div className="alert alert-error login-alert">
                <span className="alert-icon">⚠️</span>
                {error}
              </div>
            )}

            {/* SUBMIT BUTTON */}
            <div className="form-actions login-actions">
              <button className="login-btn" type="submit" disabled={loading}>
                {loading ? (
                  <span className="btn-loading">
                    <span className="spinner"></span>
                    {isSignUp ? 'Creating Account...' : 'Signing In...'}
                  </span>
                ) : (
                  <span>
                    {isSignUp ? 'Create Account' : 'Sign In'}
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                      <path d="M7.5 15L12.5 10L7.5 5" stroke="currentColor"
                        strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </span>
                )}
              </button>
            </div>

            {/* SIGNUP / LOGIN TOGGLE */}
            <div className="login-toggle">
              <button
                type="button"
                className="toggle-link"
                onClick={() => {
                  setIsSignUp(!isSignUp)
                  setError('')
                  setFieldErrors({})
                }}
              >
                {isSignUp
                  ? <>Already have an account? <span className="toggle-highlight">Sign in</span></>
                  : <>Don't have an account? <span className="toggle-highlight">Sign up</span></>}
              </button>
            </div>

          </form>
        </div>
      </div>
    </div>
  )
}
