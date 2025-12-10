import React, {useEffect, useState} from 'react'
import axios from 'axios'
import Dashboard from './Dashboard'
import Login from './Login'
import About from './About'

// 1. SET BASE URL
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000';
axios.defaults.baseURL = API_BASE;

// 2. SETUP INTERCEPTOR (The Fix for 401 Errors)
// This automatically adds the token to every single request
axios.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => {
  return Promise.reject(error);
});

export default function App(){
  const [token, setToken] = useState(localStorage.getItem('token') || '')
  const [user, setUser] = useState(JSON.parse(localStorage.getItem('user') || 'null'))
  const [route, setRoute] = useState(window.location.pathname || '/')

  // Handle routing history
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
    localStorage.clear()
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
            // Save data immediately
            setToken(data.token)
            setUser(data.user)
            localStorage.setItem('token', data.token)
            localStorage.setItem('user', JSON.stringify(data.user))
            navigate('/dashboard')
          }} 
        />
      )
    }

    // Landing Page
    return (
      <div className="min-h-screen bg-slate-900 text-white font-sans flex flex-col items-center justify-center p-4">
          <h1 className="text-5xl font-bold mb-4 bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-emerald-400">
            GrievancePortal
          </h1>
          <p className="text-xl text-slate-400 mb-8">Fast & Transparent Redressal System</p>
          <button onClick={() => navigate('/login')} className="px-8 py-3 bg-indigo-600 hover:bg-indigo-500 rounded-full font-bold transition-all">
             Login / Get Started
          </button>
      </div>
    )
  }

  // --- AUTHENTICATED ---
  if(route !== '/dashboard') navigate('/dashboard')
  return <Dashboard user={user} onLogout={logout} />
}