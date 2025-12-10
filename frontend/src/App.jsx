import React, {useEffect, useState} from 'react'
import axios from 'axios'
import Dashboard from './Dashboard'
import Login from './Login'
import About from './About'

// --- GLOBAL API CONFIGURATION ---
// Falls back to localhost if the env variable is missing
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000';
axios.defaults.baseURL = API_BASE;
// --------------------------------

export default function App(){
  const [token, setToken] = useState(localStorage.getItem('token') || '')
  const [user, setUser] = useState(JSON.parse(localStorage.getItem('user') || 'null'))
  const [route, setRoute] = useState(window.location.pathname || '/')

  // Maintain session headers
  useEffect(()=>{ 
    if(token) axios.defaults.headers.common.Authorization = `Bearer ${token}` 
  }, [token])

  // Browser back button support
  useEffect(()=>{
    const onPop = ()=> setRoute(window.location.pathname)
    window.addEventListener('popstate', onPop)
    return ()=> window.removeEventListener('popstate', onPop)
  }, [])

  function navigate(path){
    if(window.location.pathname !== path){
      window.history.pushState({}, '', path)
      setRoute(path)
    }
  }

  function logout(){
    setToken('')
    setUser(null)
    localStorage.clear() // Clear all auth data
    delete axios.defaults.headers.common.Authorization
    navigate('/')
  }

  // --- UNAUTHENTICATED VIEWS ---
  if(!token){
    if(route === '/about') return <About onBack={() => navigate('/')} />
    
    if(route === '/login'){
      return (
        <Login 
          initialEmail={localStorage.getItem('rememberEmail') || ''} 
          onLoggedIn={(data)=>{
            const { token, user } = data
            setToken(token)
            setUser(user)
            localStorage.setItem('token', token)
            localStorage.setItem('user', JSON.stringify(user))
            axios.defaults.headers.common.Authorization = `Bearer ${token}`
            navigate('/dashboard')
          }} 
        />
      )
    }

    // Modern Landing Page
    return (
      <div className="min-h-screen bg-slate-900 text-white font-sans selection:bg-indigo-500 selection:text-white">
        <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 brightness-100 contrast-150"></div>
        
        <nav className="relative z-10 container mx-auto px-6 py-6 flex justify-between items-center">
            <div className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-emerald-400">
                GrievancePortal
            </div>
            <button onClick={() => navigate('/login')} className="px-5 py-2 rounded-full border border-slate-700 hover:bg-slate-800 transition-all text-sm font-medium">
                Sign In
            </button>
        </nav>

        <div className="relative z-10 container mx-auto px-6 pt-20 flex flex-col items-center text-center">
          <div className="inline-block px-4 py-1 mb-6 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-sm font-semibold">
            🚀 Fast & Transparent Redressal
          </div>
          
          <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight mb-8 leading-tight">
            Resolve issues <br/>
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 via-purple-400 to-pink-400">
              without the friction.
            </span>
          </h1>
          
          <p className="text-lg text-slate-400 max-w-2xl mb-10">
             Submit grievances, track real-time status updates, and communicate with administrators in a secure, unified platform.
          </p>

          <div className="flex gap-4">
            <button onClick={() => navigate('/login')} className="px-8 py-4 bg-indigo-600 hover:bg-indigo-500 text-white font-bold rounded-xl shadow-lg shadow-indigo-500/25 transition-all hover:-translate-y-1">
                Submit a Grievance
            </button>
          </div>
        </div>
      </div>
    )
  }

  // --- AUTHENTICATED ---
  if(route !== '/dashboard') navigate('/dashboard')
  return <Dashboard user={user} onLogout={logout} />
}