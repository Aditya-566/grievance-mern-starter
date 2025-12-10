import React, { useEffect, useState } from "react";
import axios from "axios";

export default function Dashboard({ user, onLogout }) {
  // Initialize as empty array to prevent map errors
  const [grievances, setGrievances] = useState([]); 
  const [stats, setStats] = useState({ total: 0, byStatus: {} });
  const [title, setTitle] = useState("");
  const [desc, setDesc] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(""); // To show API errors in UI
  
  useEffect(() => { refreshData(); }, []);

  function refreshData(){
      setError("");
      axios.get('/api/grievances')
        .then((res) => {
            // CRITICAL SAFETY CHECK
            if(Array.isArray(res.data)) {
                setGrievances(res.data);
            } else if (res.data.list && Array.isArray(res.data.list)) {
                setGrievances(res.data.list); // Handle if backend wraps it in an object
            } else {
                setGrievances([]); // Fallback to empty
            }
        })
        .catch(err => {
            console.error("Fetch error:", err);
            if(err.response?.status === 401) onLogout(); // Auto logout if token invalid
            setError("Failed to load data.");
        });

      axios.get('/api/grievances/stats')
        .then((res) => setStats(res.data))
        .catch(console.error);
  }

  function submit(e) {
    e.preventDefault();
    setLoading(true);
    axios.post('/api/grievances', { title, description: desc })
      .then(() => { setTitle(""); setDesc(""); refreshData(); })
      .catch((err) => alert("Error creating grievance"))
      .finally(() => setLoading(false));
  }

  async function updateStatus(id, status) {
    if(!confirm(`Mark as ${status}?`)) return;
    try { await axios.patch(`/api/grievances/${id}/status`, { status }); refreshData(); } 
    catch(e) { console.error(e); }
  }

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col font-sans text-slate-900">
      {/* Header */}
      <header className="bg-white border-b border-slate-200 px-8 py-4 flex justify-between items-center sticky top-0 z-30 shadow-sm">
        <h1 className="text-xl font-bold text-slate-800">Dashboard</h1>
        <div className="flex items-center gap-4">
            <span className="text-sm">Hi, <b>{user?.name}</b></span>
            <button onClick={onLogout} className="text-sm text-red-600 font-medium px-4 py-2 border border-red-200 rounded-lg hover:bg-red-50">
                Sign Out
            </button>
        </div>
      </header>

      <div className="flex-1 p-8 max-w-7xl mx-auto w-full grid lg:grid-cols-12 gap-8">
        
        {/* Left Panel */}
        <div className="lg:col-span-4 space-y-6">
            {/* Stats */}
            <div className="grid grid-cols-2 gap-3">
                <div className="bg-white p-4 rounded-xl shadow-sm text-center border border-slate-100">
                    <div className="text-2xl font-bold text-indigo-600">{stats.total || 0}</div>
                    <div className="text-xs font-bold text-slate-400 uppercase">Total</div>
                </div>
                <div className="bg-white p-4 rounded-xl shadow-sm text-center border border-slate-100">
                    <div className="text-2xl font-bold text-emerald-600">{stats.byStatus?.resolved || 0}</div>
                    <div className="text-xs font-bold text-slate-400 uppercase">Resolved</div>
                </div>
            </div>

            {/* Form */}
            <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-100">
                <h3 className="text-lg font-bold text-slate-800 mb-4">New Grievance</h3>
                <form onSubmit={submit} className="space-y-4">
                    <input 
                        className="w-full p-3 bg-slate-50 border border-slate-200 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none text-sm"
                        placeholder="Subject"
                        value={title} onChange={e => setTitle(e.target.value)} required 
                    />
                    <textarea 
                        className="w-full p-3 bg-slate-50 border border-slate-200 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none text-sm h-32 resize-none"
                        placeholder="Describe the issue..."
                        value={desc} onChange={e => setDesc(e.target.value)} required 
                    />
                    <button disabled={loading} className="w-full py-3 bg-slate-900 hover:bg-slate-800 text-white font-semibold rounded-lg shadow-lg">
                        {loading ? 'Submitting...' : 'Submit Grievance'}
                    </button>
                </form>
            </div>
        </div>

        {/* Right Panel: List */}
        <div className="lg:col-span-8">
            <div className="bg-white rounded-xl shadow-sm border border-slate-100 min-h-[400px]">
                <div className="px-6 py-4 border-b border-slate-100 bg-slate-50/50">
                    <h3 className="font-bold text-slate-700">Recent Activity</h3>
                </div>
                
                {/* SAFETY CHECK FOR RENDERING */}
                {error ? (
                    <div className="p-12 text-center text-red-400">{error}</div>
                ) : !Array.isArray(grievances) || grievances.length === 0 ? (
                    <div className="p-12 text-center text-slate-400">No records found.</div>
                ) : (
                    <div className="divide-y divide-slate-100">
                        {grievances.map((g) => (
                            <div key={g._id} className="p-6 hover:bg-slate-50 transition-colors group">
                                <div className="flex justify-between items-start mb-2">
                                    <h4 className="font-semibold text-slate-800 text-lg">{g.title}</h4>
                                    <span className={`px-2 py-1 rounded text-xs font-bold capitalize ${g.status === 'resolved' ? 'bg-emerald-100 text-emerald-700' : 'bg-blue-100 text-blue-700'}`}>
                                        {g.status}
                                    </span>
                                </div>
                                <p className="text-slate-600 mb-4">{g.description}</p>
                                <div className="flex justify-between items-center">
                                    <span className="text-xs text-slate-400">ID: {g._id?.slice(-6)}</span>
                                    {user?.role === 'admin' && (
                                        <div className="flex gap-2">
                                            <button onClick={()=>updateStatus(g._id, 'resolved')} className="text-xs px-3 py-1 bg-emerald-50 text-emerald-600 rounded">Resolve</button>
                                            <button onClick={()=>updateStatus(g._id, 'rejected')} className="text-xs px-3 py-1 bg-red-50 text-red-600 rounded">Reject</button>
                                        </div>
                                    )}
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
      </div>
    </div>
  );
}