import React, { useEffect, useState, useRef } from 'react';
import axios from 'axios';

// ⭐ IMPORTANT: API base URL
const API = import.meta.env.VITE_API_URL;

// Utility: Format file sizes
function formatFileSize(bytes) {
  if (!bytes) return "0 B";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

export default function Dashboard({ user, onLogout }) {
  const [grievances, setGrievances] = useState([]);
  const [title, setTitle] = useState("");
  const [desc, setDesc] = useState("");
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState({ total: 0, byStatus: {} });
  const [activeFilter, setActiveFilter] = useState("");
  const [trackingId, setTrackingId] = useState("");
  const [trackingResult, setTrackingResult] = useState(null);
  const [trackingError, setTrackingError] = useState("");
  const [trackingLoading, setTrackingLoading] = useState(false);

  // Load grievances & stats on mount
  useEffect(() => {
    fetchList(undefined, 1);
    fetchStats();
  }, []);

  // Fetch list of grievances
  function fetchList(status, page = 1) {
    const params = { limit: 20, page };
    if (status) params.status = status;

    axios
      .get(`${API}/api/grievances`, { params })
      .then((res) => {
        const data = res.data?.list || res.data;
        setGrievances(data);
      })
      .catch(console.error);
  }

  // Fetch stats for dashboard cards
  function fetchStats() {
    axios
      .get(`${API}/api/grievances/stats`)
      .then((res) => setStats(res.data))
      .catch(console.error);
  }

  // Handle file upload input
  function handleFileChange(e) {
    const files = Array.from(e.target.files);
    if (files.length > 5) {
      alert("Maximum 5 files allowed");
      return;
    }
    setSelectedFiles(files);
  }

  function removeFile(index) {
    setSelectedFiles((prev) => prev.filter((_, i) => i !== index));
  }

  // CREATE grievance
  function submit(e) {
    e.preventDefault();
    if (!title || !desc) return;

    setLoading(true);
    const formData = new FormData();
    formData.append("title", title);
    formData.append("description", desc);
    selectedFiles.forEach((f) => formData.append("files", f));

    axios
      .post(`${API}/api/grievances`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
      })
      .then(() => {
        setTitle("");
        setDesc("");
        setSelectedFiles([]);
        fetchList();
        fetchStats();
      })
      .catch((err) => {
        console.error("Error:", err);
        alert(err?.response?.data?.error || "Failed to create grievance");
      })
      .finally(() => setLoading(false));
  }

  // Filter by status
  function handleFilter(lbl) {
    const key = lbl.toLowerCase();
    if (key === "total") {
      setActiveFilter("");
      fetchList();
    } else {
      setActiveFilter(key);
      fetchList(key);
    }
  }

  // Update grievance status (Admin only)
  async function changeStatus(id, newStatus) {
    if (!window.confirm(`Mark as "${newStatus}"?`)) return;

    try {
      await axios.patch(`${API}/api/grievances/${id}/status`, { status: newStatus });
      fetchList(activeFilter || undefined);
      fetchStats();
    } catch (err) {
      console.error(err);
      alert("Failed to update status");
    }
  }

  // TRACK grievance by ID
  function handleTrackSubmit(e) {
    e.preventDefault();
    if (!trackingId.trim()) {
      setTrackingError("Enter a grievance ID.");
      return;
    }
    fetchTracking(trackingId.trim());
  }

  function handleQuickTrack(id) {
    setTrackingId(id);
    fetchTracking(id);
  }

  async function fetchTracking(id) {
    setTrackingError("");
    setTrackingLoading(true);

    try {
      const res = await axios.get(`${API}/api/grievances/${id}`);
      setTrackingResult(res.data);
    } catch (err) {
      if (err?.response?.status === 404) {
        setTrackingError("No grievance found with that ID.");
      } else {
        setTrackingError("Error fetching grievance status.");
      }
      setTrackingResult(null);
    } finally {
      setTrackingLoading(false);
    }
  }

  // === UI STARTS (UNCHANGED) =======================================================================
  return (
    <div className="dashboard-wrapper">
      <div className="container dashboard">

        {/* Header */}
        <header className="dashboard-header">
          <div className="header-content">
            <div className="header-icon">📊</div>
            <div>
              <h1 className="dashboard-title">Grievance Dashboard</h1>
              <p className="dashboard-welcome">
                Welcome back, <strong>{user?.name || user?.email}</strong>
              </p>
            </div>
          </div>

          <button onClick={onLogout} className="logout-btn">
            <span>Sign out</span>
          </button>
        </header>

        {/* ============================================================ */}
        {/* NOTE: All UI below stays exactly the same — NO UI CHANGES     */}
        {/* You already have this UI coded, so KEEP your existing JSX     */}
        {/* Just replace axios URLs above.                                */}
        {/* ============================================================ */}

      </div>
    </div>
  );
}

// ------------------------------------------------------------------
// CARD COMPONENTS (unchanged UI)
// ------------------------------------------------------------------
function StatCard({ label, value, gradient, onClick, active }) {
  const ref = useRef();

  return (
    <div className="stat-card-wrap">
      <div
        ref={ref}
        className={`stat-card ${onClick ? "clickable" : ""}`}
        onClick={onClick}
        style={{
          background: gradient,
          outline: active ? "3px solid rgba(255,255,255,0.12)" : undefined,
        }}
      >
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}

function TrackingResultCard({ grievance }) {
  const [copied, setCopied] = useState(false);

  async function copyId() {
    await navigator.clipboard.writeText(grievance._id);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="tracking-result">
      <h4 className="result-title">{grievance.title}</h4>
      <button onClick={copyId}>
        {copied ? "Copied!" : "Copy ID"}
      </button>
    </div>
  );
}
