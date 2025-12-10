import React, { useEffect, useState } from "react";
import axios from "axios";

export default function Dashboard({ user, onLogout }) {
  const [grievances, setGrievances] = useState([]);
  const [stats, setStats] = useState({ total: 0, byStatus: {} });
  const [title, setTitle] = useState("");
  const [desc, setDesc] = useState("");
  const [loading, setLoading] = useState(false);
  
  useEffect(() => { refreshData(); }, []);

  function refreshData(){
      axios.get('/api/grievances').then((res) => setGrievances(res.data)).catch(console.error);
      axios.get('/api/grievances/stats').then((res) => setStats(res.data)).catch(console.error);
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
      {/* Navbar */}
      <header className="bg-white border-b border-slate-200 px-8 py-4 flex justify-between items-center sticky top-0 z-30 shadow-sm">
        <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center text-white font-bold">G</div>
            <h1 className="text-xl font-bold text-slate-800">Dashboard</h1>
        </div>
        <div className="flex items-center gap-4">
            <span className="text-sm text-slate-500">Welcome, <b>{user?.name}</b></span>
            <button onClick={onLogout} className="text-sm text-red-600 font-medium hover:bg-red-50 px-4 py-2 rounded-lg transition-colors border border-transparent hover:border-red-100">
                Sign Out
            </button>
        </div>
      </header>

      <div className="flex-1 p-8 max-w-7xl mx-auto w-full grid lg:grid-cols-12 gap-8">
        
        {/* LEFT SIDEBAR: Stats & Form (4 Cols) */}
        <div className="lg:col-span-4 space-y-6">
            <div className="grid grid-cols-2 gap-3">
                <div className="bg-white p-4 rounded-xl shadow-sm border border-slate-100 text-center">
                    <div className="text-2xl font-bold text-indigo-600">{stats.total}</div>
                    <div className="text-xs font-bold text-slate-400 uppercase">Total</div>
                </div>
                <div className="bg-white p-4 rounded-xl shadow-sm border border-slate-100 text-center">
                    <div className="text-2xl font-bold text-emerald-600">{stats.byStatus?.resolved || 0}</div>
                    <div className="text-xs font-bold text-slate-400 uppercase">Resolved</div>
                </div>
            </div>

            <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-100">
                <h3 className="text-lg font-bold text-slate-800 mb-4">New Grievance</h3>
                <form onSubmit={submit} className="space-y-4">
                    <input 
                        className="w-full p-3 bg-slate-50 border border-slate-200 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none text-sm transition-all"
                        placeholder="Subject"
                        value={title} onChange={e => setTitle(e.target.value)} required 
                    />
                    <textarea 
                        className="w-full p-3 bg-slate-50 border border-slate-200 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none text-sm h-32 resize-none transition-all"
                        placeholder="Describe the issue..."
                        value={desc} onChange={e => setDesc(e.target.value)} required 
                    />
                    <button 
                        disabled={loading}
                        className="w-full py-3 bg-slate-900 hover:bg-slate-800 text-white font-semibold rounded-lg transition-colors shadow-lg shadow-slate-900/20">
                        {loading ? 'Submitting...' : 'Submit Grievance'}
                    </button>
                </form>
            </div>
        </div>

        {/* RIGHT CONTENT: List (8 Cols) */}
        <div className="lg:col-span-8">
            <div className="bg-white rounded-xl shadow-sm border border-slate-100">
                <div className="px-6 py-4 border-b border-slate-100 bg-slate-50/50">
                    <h3 className="font-bold text-slate-700">Recent Activity</h3>
                </div>
                
                {grievances.length === 0 ? (
                    <div className="p-12 text-center text-slate-400">No records found.</div>
                ) : (
                    <div className="divide-y divide-slate-100">
                        {grievances.map((g) => (
                            <div key={g._id} className="p-6 hover:bg-slate-50 transition-colors group">
                                <div className="flex justify-between items-start mb-2">
                                    <h4 className="font-semibold text-slate-800 text-lg">{g.title}</h4>
                                    <span className={`px-3 py-1 rounded-full text-xs font-bold capitalize 
                                        ${g.status === 'resolved' ? 'bg-emerald-100 text-emerald-700' : 
                                          g.status === 'rejected' ? 'bg-red-100 text-red-700' : 'bg-blue-100 text-blue-700'}`}>
                                        {g.status}
                                    </span>
                                </div>
                                <p className="text-slate-600 mb-4">{g.description}</p>
                                
                                <div className="flex justify-between items-center pt-2">
                                    <span className="text-xs text-slate-400 font-mono">ID: {g._id.slice(-6)}</span>
                                    {user?.role === 'admin' && (
                                        <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                            <button onClick={()=>updateStatus(g._id, 'resolved')} className="text-xs px-3 py-1 border border-emerald-200 text-emerald-600 rounded-md hover:bg-emerald-50">Resolve</button>
                                            <button onClick={()=>updateStatus(g._id, 'rejected')} className="text-xs px-3 py-1 border border-red-200 text-red-600 rounded-md hover:bg-red-50">Reject</button>
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