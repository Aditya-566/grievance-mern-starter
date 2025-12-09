import React, { useEffect, useState } from 'react';
import axios from 'axios';
import Dashboard from './Dashboard';
import Login from './Login';
import About from './About';

const API = import.meta.env.VITE_API_URL;

export default function App() {

  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [user, setUser] = useState(JSON.parse(localStorage.getItem("user") || "null"));
  const [route, setRoute] = useState(window.location.pathname || "/");

  useEffect(() => {
    if (token) axios.defaults.headers.common.Authorization = `Bearer ${token}`;
  }, [token]);

  // Handle browser back button
  useEffect(() => {
    const onPop = () => setRoute(window.location.pathname);
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  function navigate(path) {
    if (window.location.pathname !== path) {
      window.history.pushState({}, "", path);
      setRoute(path);
    }
  }

  function quickSignIn() {
    navigate("/login");
  }

  // =============================
  // 🔥 UNAUTHENTICATED USER LOGIC
  // =============================
  if (!token) {

    if (route === "/about") {
      return <About onBack={() => navigate("/")} />;
    }

    if (route !== "/login") {
      return (
        <div className="landing-page">
          <div className="hero-background">
            <div className="gradient-orb orb-1"></div>
            <div className="gradient-orb orb-2"></div>
            <div className="gradient-orb orb-3"></div>
          </div>

          <div className="container hero">
            <div className="hero-inner">
              <div className="hero-content">

                <div className="hero-badge">✨ Modern Grievance Management</div>

                <h1 className="hero-title">
                  <span className="title-gradient">Grievance Tracker</span><br />
                  Clear, Fast, Transparent
                </h1>

                <p className="hero-subtitle">
                  Submit issues, track progress, and resolve concerns easily.
                </p>

                <div className="cta-section">
                  <button className="cta-btn" onClick={quickSignIn}>
                    <span>Sign in — Get started</span>
                  </button>

                  <button className="cta-btn-secondary" onClick={() => navigate("/about")}>
                    <span>Learn More</span>
                  </button>
                </div>

              </div>
            </div>
          </div>
        </div>
      );
    }

    // Show login page
    return (
      <Login
        initialEmail={localStorage.getItem("rememberEmail") || ""}
        onLoggedIn={(data) => {
          const { token, user } = data;
          setToken(token);
          setUser(user);
          localStorage.setItem("token", token);
          localStorage.setItem("user", JSON.stringify(user));
          axios.defaults.headers.common.Authorization = `Bearer ${token}`;
          navigate("/dashboard");
        }}
      />
    );
  }

  // ============================
  // 🔥 AUTHENTICATED USER LOGIC
  // ============================
  if (route !== "/dashboard") navigate("/dashboard");

  return (
    <Dashboard
      user={user}
      onLogout={() => {
        setToken("");
        setUser(null);
        localStorage.removeItem("token");
        localStorage.removeItem("user");
        delete axios.defaults.headers.common.Authorization;
        navigate("/");
      }}
    />
  );
}
