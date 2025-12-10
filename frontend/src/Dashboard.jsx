import React, { useEffect, useState, useRef } from "react";
import axios from "axios";

const API = import.meta.env.VITE_API_URL;

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

  useEffect(() => {
    fetchList();
    fetchStats();
  }, []);

  function fetchList(status) {
    const params = {};
    if (status) params.status = status;

    axios
      .get(`${API}/api/grievances`, { params })
      .then((res) => setGrievances(res.data.list || res.data))
      .catch(console.error);
  }

  function fetchStats() {
    axios
      .get(`${API}/api/grievances/stats`)
      .then((res) => setStats(res.data))
      .catch(console.error);
  }

  function handleFileChange(e) {
    const files = Array.from(e.target.files);
    if (files.length > 5) return alert("Max 5 files allowed");
    setSelectedFiles(files);
  }

  function removeFile(i) {
    setSelectedFiles((prev) => prev.filter((_, idx) => idx !== i));
  }

  function submit(e) {
    e.preventDefault();
    if (!title || !desc) return;

    setLoading(true);
    const fd = new FormData();
    fd.append("title", title);
    fd.append("description", desc);
    selectedFiles.forEach((f) => fd.append("files", f));

    axios
      .post(`${API}/api/grievances`, fd, { headers: { "Content-Type": "multipart/form-data" } })
      .then(() => {
        setTitle("");
        setDesc("");
        setSelectedFiles([]);
        fetchList();
        fetchStats();
      })
      .catch((err) => alert(err?.response?.data?.error || "Failed to create grievance"))
      .finally(() => setLoading(false));
  }

  async function changeStatus(id, status) {
    if (!window.confirm(`Change status to ${status}?`)) return;
    try {
      await axios.patch(`${API}/api/grievances/${id}/status`, { status });
      fetchList(activeFilter || undefined);
      fetchStats();
    } catch (e) {
      alert("Failed to update status");
    }
  }

  function handleTrackSubmit(e) {
    e.preventDefault();
    if (!trackingId) return setTrackingError("Enter grievance ID");
    fetchTracking(trackingId);
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
      setTrackingResult(null);
      setTrackingError(err?.response?.status === 404 ? "Not found" : "Error fetching status");
    }

    setTrackingLoading(false);
  }

  return (
    <div className="dashboard-wrapper">
      <div className="container dashboard">

        {/* HEADER */}
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
          <button onClick={onLogout} className="logout-btn">Sign out</button>
        </header>

        {/* ===================================================================================== */}
        {/*                             FULL ORIGINAL UI RESTORED BELOW                          */}
        {/* ===================================================================================== */}

        {/* STATS */}
        <section className="stats-row">
          {[
            { label: "Total", value: stats.total, key: "" },
            { label: "Open", value: stats.byStatus?.open || 0, key: "open" },
            { label: "Resolved", value: stats.byStatus?.resolved || 0, key: "resolved" },
            { label: "Rejected", value: stats.byStatus?.rejected || 0, key: "rejected" }
          ].map((s) => (
            <div key={s.label} className="stat-card" onClick={() => fetchList(s.key)}>
              <div className="stat-value">{s.value}</div>
              <div className="stat-label">{s.label}</div>
            </div>
          ))}
        </section>

        {/* CREATE GRIEVANCE */}
        <section className="dashboard-panel create-panel">
          <form onSubmit={submit}>
            <input
              className="dashboard-input"
              placeholder="Grievance title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              required
            />

            <textarea
              className="dashboard-textarea"
              placeholder="Describe your grievance..."
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
              required
            />

            <input type="file" multiple onChange={handleFileChange} />

            {selectedFiles.map((f, idx) => (
              <div key={idx} className="file-preview-item">
                {f.name} ({formatFileSize(f.size)})
                <button type="button" onClick={() => removeFile(idx)}>×</button>
              </div>
            ))}

            <button type="submit" className="create-btn" disabled={loading}>
              {loading ? "Saving..." : "Create"}
            </button>
          </form>
        </section>

        {/* TRACKING */}
        <section className="dashboard-panel tracker-panel">
          <form onSubmit={handleTrackSubmit}>
            <input
              className="tracking-input"
              placeholder="Enter grievance ID"
              value={trackingId}
              onChange={(e) => setTrackingId(e.target.value)}
            />
            <button className="tracking-btn" type="submit">Track</button>
          </form>

          {trackingError && <div className="alert">{trackingError}</div>}
          {trackingResult && (
            <div className="tracking-result">
              <h3>{trackingResult.title}</h3>
              <p>Status: {trackingResult.status}</p>
            </div>
          )}
        </section>

        {/* GRIEVANCES LIST */}
        <section className="dashboard-panel grievances-panel">
          <h3>All Grievances</h3>

          {grievances.length === 0 ? (
            <p>No grievances yet.</p>
          ) : (
            <ul className="grievances-list">
              {grievances.map((g) => (
                <li key={g._id} className="grievance-card">
                  <strong>{g.title}</strong>
                  <p>{g.description}</p>
                  <span>Status: {g.status}</span>

                  {user?.role === "admin" && (
                    <div className="grievance-actions">
                      <button onClick={() => changeStatus(g._id, "resolved")}>Resolve</button>
                      <button onClick={() => changeStatus(g._id, "rejected")}>Reject</button>
                      <button onClick={() => changeStatus(g._id, "open")}>Re-open</button>
                    </div>
                  )}

                  <button onClick={() => handleQuickTrack(g._id)}>Track</button>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}
