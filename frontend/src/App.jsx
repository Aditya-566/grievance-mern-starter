import React, { useEffect, useState } from 'react'
import axios from 'axios'
import Dashboard from './Dashboard'
import Login from './Login'
import About from './About'
import { Activity, Shield, Zap, AlertCircle, Clock, CheckCircle, XCircle, Plus, LogOut, User, Filter, Search, Download, ChevronRight, TrendingUp, RefreshCw, Mail, Lock, Eye, EyeOff, BarChart3 } from 'lucide-react'

// 1. SET BASE URL
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000';
axios.defaults.baseURL = API_BASE;

// 2. Enhanced Interceptor with error handling
axios.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => {
  return Promise.reject(error);
});

// Add response interceptor for better error handling
axios.interceptors.response.use(
  response => response,
  error => {
    if (error.response?.status === 401) {
      localStorage.clear();
      window.location.href = '/';
    }
    return Promise.reject(error);
  }
);

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('token') || '')
  const [user, setUser] = useState(JSON.parse(localStorage.getItem('user') || 'null'))
  const [route, setRoute] = useState(window.location.pathname || '/')
  const [isLoading, setIsLoading] = useState(false)

  // Handle routing history
  useEffect(() => {
    const onPop = () => setRoute(window.location.pathname)
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  function navigate(path) {
    if (window.location.pathname !== path) {
      window.history.pushState({}, '', path)
      setRoute(path)
    }
  }

  function logout() {
    setIsLoading(true)
    setTimeout(() => {
      setToken('')
      setUser(null)
      localStorage.clear()
      navigate('/')
      setIsLoading(false)
    }, 300)
  }

  // Simple About component if not created yet
  const About = ({ onBack }) => (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-950 text-white font-sans">
      <div className="relative z-10 px-6 lg:px-8 py-8">
        <button
          onClick={onBack}
          className="mb-8 px-4 py-2 bg-white/10 hover:bg-white/20 rounded-lg transition-colors flex items-center gap-2"
        >
          <ChevronRight className="w-4 h-4 rotate-180" />
          Back
        </button>
        
        <div className="max-w-4xl mx-auto">
          <h1 className="text-4xl font-bold mb-8 text-center">About GrievancePortal</h1>
          
          <div className="bg-white/5 backdrop-blur-sm rounded-2xl p-8 border border-white/10">
            <h2 className="text-2xl font-bold mb-4">Our Mission</h2>
            <p className="text-slate-300 mb-6">
              To provide a transparent, efficient, and secure platform for grievance management 
              that bridges the gap between stakeholders and resolution authorities.
            </p>
            
            <h2 className="text-2xl font-bold mb-4">Key Features</h2>
            <ul className="space-y-3 mb-6">
              <li className="flex items-start gap-3">
                <CheckCircle className="w-5 h-5 text-emerald-400 mt-0.5 flex-shrink-0" />
                <span className="text-slate-300">Real-time tracking of grievance status</span>
              </li>
              <li className="flex items-start gap-3">
                <CheckCircle className="w-5 h-5 text-emerald-400 mt-0.5 flex-shrink-0" />
                <span className="text-slate-300">Role-based access control</span>
              </li>
              <li className="flex items-start gap-3">
                <CheckCircle className="w-5 h-5 text-emerald-400 mt-0.5 flex-shrink-0" />
                <span className="text-slate-300">Secure data encryption</span>
              </li>
              <li className="flex items-start gap-3">
                <CheckCircle className="w-5 h-5 text-emerald-400 mt-0.5 flex-shrink-0" />
                <span className="text-slate-300">Automated notifications</span>
              </li>
            </ul>
            
            <h2 className="text-2xl font-bold mb-4">Contact</h2>
            <p className="text-slate-300">
              For support or inquiries, please email: support@grievanceportal.com
            </p>
          </div>
        </div>
      </div>
    </div>
  )

  // --- UNAUTHENTICATED VIEWS ---
  if (!token) {
    if (route === '/about') return <About onBack={() => navigate('/')} />

    if (route === '/login') {
      return (
        <Login
          initialEmail={localStorage.getItem('rememberEmail') || ''}
          onLoggedIn={(data) => {
            setIsLoading(true)
            setToken(data.token)
            setUser(data.user)
            localStorage.setItem('token', data.token)
            localStorage.setItem('user', JSON.stringify(data.user))
            navigate('/dashboard')
            setIsLoading(false)
          }}
        />
      )
    }

    // Enhanced Landing Page
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-950 text-white font-sans">
        {/* Background Effects */}
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute -top-40 -right-40 w-80 h-80 bg-purple-500/10 rounded-full blur-3xl"></div>
          <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-blue-500/10 rounded-full blur-3xl"></div>
          <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-indigo-500/5 rounded-full blur-3xl"></div>
        </div>

        {/* Navigation */}
        <nav className="relative z-10 px-6 lg:px-8 py-6">
          <div className="max-w-7xl mx-auto flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="p-2 bg-gradient-to-br from-indigo-500 to-purple-500 rounded-lg">
                <Activity className="w-6 h-6" />
              </div>
              <span className="text-xl font-bold">GrievancePortal</span>
            </div>
            <div className="flex items-center gap-6">
              <button
                onClick={() => navigate('/about')}
                className="text-sm text-slate-300 hover:text-white transition-colors"
              >
                About
              </button>
              <button
                onClick={() => navigate('/login')}
                className="px-6 py-2.5 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 rounded-lg font-semibold transition-all shadow-lg hover:shadow-xl"
              >
                Get Started
              </button>
            </div>
          </div>
        </nav>

        {/* Hero Section */}
        <div className="relative z-10 px-6 lg:px-8 py-20 lg:py-32">
          <div className="max-w-7xl mx-auto text-center">
            <div className="inline-flex items-center gap-2 px-4 py-2 bg-white/10 backdrop-blur-sm rounded-full mb-8">
              <Zap className="w-4 h-4 text-yellow-400" />
              <span className="text-sm font-medium">Enterprise-Grade Solution</span>
            </div>

            <h1 className="text-5xl lg:text-7xl font-bold mb-6 leading-tight">
              Modern
              <span className="bg-gradient-to-r from-blue-400 to-emerald-400 bg-clip-text text-transparent"> Grievance </span>
              Management
            </h1>

            <p className="text-xl text-slate-300 max-w-3xl mx-auto mb-12 leading-relaxed">
              A streamlined platform for efficient issue tracking, transparent resolution,
              and enhanced stakeholder communication.
            </p>

            <div className="flex flex-col sm:flex-row gap-4 justify-center mb-20">
              <button
                onClick={() => navigate('/login')}
                className="px-8 py-4 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 rounded-xl font-bold text-lg transition-all shadow-2xl hover:shadow-3xl transform hover:-translate-y-1"
              >
                Start Free Trial
              </button>
              <button
                onClick={() => navigate('/about')}
                className="px-8 py-4 bg-white/10 hover:bg-white/20 backdrop-blur-sm rounded-xl font-bold text-lg transition-all border border-white/20"
              >
                Learn More
              </button>
            </div>

            {/* Features Grid - FIXED SECTION */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-5xl mx-auto">
              <div className="bg-white/5 backdrop-blur-sm rounded-2xl p-8 border border-white/10 hover:border-white/20 transition-all group">
                <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-cyan-400 rounded-xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                  <Activity className="w-6 h-6" />
                </div>
                <h3 className="text-xl font-bold mb-4 text-white">Real-time Tracking</h3>
                <p className="text-slate-300 leading-relaxed">
                  Monitor grievance status with live updates and notifications.
                </p>
              </div>

              <div className="bg-white/5 backdrop-blur-sm rounded-2xl p-8 border border-white/10 hover:border-white/20 transition-all group">
                <div className="w-12 h-12 bg-gradient-to-br from-purple-500 to-pink-400 rounded-xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                  <Shield className="w-6 h-6" />
                </div>
                <h3 className="text-xl font-bold mb-4 text-white">Secure & Private</h3>
                <p className="text-slate-300 leading-relaxed">
                  Enterprise-grade security with role-based access control.
                </p>
              </div>

              <div className="bg-white/5 backdrop-blur-sm rounded-2xl p-8 border border-white/10 hover:border-white/20 transition-all group">
                <div className="w-12 h-12 bg-gradient-to-br from-emerald-500 to-green-400 rounded-xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                  <Zap className="w-6 h-6" />
                </div>
                <h3 className="text-xl font-bold mb-4 text-white">Fast Resolution</h3>
                <p className="text-slate-300 leading-relaxed">
                  Streamlined workflows for quicker grievance resolution.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Loading Overlay */}
        {isLoading && (
          <div className="fixed inset-0 bg-slate-900/80 backdrop-blur-sm z-50 flex items-center justify-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-white"></div>
          </div>
        )}
      </div>
    )
  }

  // --- AUTHENTICATED ---
  if (route !== '/dashboard') navigate('/dashboard')

  return (
    <>
      <Dashboard user={user} onLogout={logout} />
      {isLoading && (
        <div className="fixed inset-0 bg-white/80 backdrop-blur-sm z-50 flex items-center justify-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
        </div>
      )}
    </>
  )
}