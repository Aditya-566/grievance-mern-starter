import React, { useEffect, useState, useMemo } from "react";
import axios from "axios";
import {
  BarChart3, 
  CheckCircle, 
  Clock, 
  AlertCircle,
  XCircle,
  Plus,
  LogOut,
  User,
  Filter,
  Search,
  Download,
  ChevronRight,
  TrendingUp,
  RefreshCw
} from "lucide-react";

export default function Dashboard({ user, onLogout }) {
  const [grievances, setGrievances] = useState([]);
  const [stats, setStats] = useState({ 
    total: 0, 
    pending: 0, 
    inProgress: 0, 
    resolved: 0, 
    rejected: 0 
  });
  const [title, setTitle] = useState("");
  const [desc, setDesc] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [showNotification, setShowNotification] = useState(false);
  const [notificationMessage, setNotificationMessage] = useState("");
  const [isRefreshing, setIsRefreshing] = useState(false);

  useEffect(() => { 
    refreshData(); 
  }, []);

  function showNotificationMessage(message, type = "success") {
    setNotificationMessage(message);
    setShowNotification(true);
    setTimeout(() => setShowNotification(false), 3000);
  }

  async function refreshData() {
    setIsRefreshing(true);
    setError("");
    try {
      const [grievancesRes, statsRes] = await Promise.all([
        axios.get('/api/grievances'),
        axios.get('/api/grievances/stats')
      ]);
      
      if(Array.isArray(grievancesRes.data)) {
        setGrievances(grievancesRes.data);
      } else if (grievancesRes.data.list && Array.isArray(grievancesRes.data.list)) {
        setGrievances(grievancesRes.data.list);
      } else {
        setGrievances([]);
      }
      
      setStats(statsRes.data);
    } catch (err) {
      console.error("Fetch error:", err);
      if(err.response?.status === 401) onLogout();
      setError("Failed to load data. Please try again.");
      showNotificationMessage("Failed to load data", "error");
    } finally {
      setIsRefreshing(false);
    }
  }

  async function submit(e) {
    e.preventDefault();
    setLoading(true);
    try {
      await axios.post('/api/grievances', { title, description: desc });
      setTitle("");
      setDesc("");
      refreshData();
      showNotificationMessage("Grievance submitted successfully!");
    } catch (err) {
      showNotificationMessage("Error creating grievance", "error");
    } finally {
      setLoading(false);
    }
  }

  async function updateStatus(id, status) {
    if(!window.confirm(`Mark as ${status}?`)) return;
    try {
      await axios.patch(`/api/grievances/${id}/status`, { status });
      refreshData();
      showNotificationMessage(`Status updated to ${status}`);
    } catch(err) {
      console.error(err);
      showNotificationMessage("Failed to update status", "error");
    }
  }

  const filteredGrievances = useMemo(() => {
    return grievances.filter(g => {
      const matchesSearch = g.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           g.description.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesStatus = statusFilter === "all" || g.status === statusFilter;
      return matchesSearch && matchesStatus;
    });
  }, [grievances, searchTerm, statusFilter]);

  const getStatusIcon = (status) => {
    switch(status) {
      case 'resolved': return <CheckCircle className="w-4 h-4" />;
      case 'pending': return <Clock className="w-4 h-4" />;
      case 'inProgress': return <TrendingUp className="w-4 h-4" />;
      case 'rejected': return <XCircle className="w-4 h-4" />;
      default: return <AlertCircle className="w-4 h-4" />;
    }
  };

  const getStatusColor = (status) => {
    switch(status) {
      case 'resolved': return "bg-emerald-50 text-emerald-700 border-emerald-200";
      case 'pending': return "bg-amber-50 text-amber-700 border-amber-200";
      case 'inProgress': return "bg-blue-50 text-blue-700 border-blue-200";
      case 'rejected': return "bg-rose-50 text-rose-700 border-rose-200";
      default: return "bg-slate-50 text-slate-700 border-slate-200";
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 font-sans text-slate-900">
      {/* Notification Toast */}
      {showNotification && (
        <div className="fixed top-6 right-6 z-50 animate-slide-in">
          <div className="bg-white rounded-xl shadow-2xl border border-slate-200 px-6 py-4 flex items-center gap-3">
            <CheckCircle className="w-5 h-5 text-emerald-500" />
            <span className="text-sm font-medium text-slate-800">{notificationMessage}</span>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="sticky top-0 z-40 bg-white/80 backdrop-blur-xl border-b border-slate-200/60">
        <div className="px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-indigo-500 rounded-lg">
                <BarChart3 className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-slate-900">Dashboard</h1>
                <p className="text-xs text-slate-500">Welcome to Grievance Management System</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-3 px-4 py-2 bg-slate-50 rounded-lg">
                <div className="w-8 h-8 bg-gradient-to-br from-indigo-500 to-purple-500 rounded-full flex items-center justify-center">
                  <User className="w-4 h-4 text-white" />
                </div>
                <div>
                  <p className="text-sm font-medium text-slate-900">{user?.name}</p>
                  <p className="text-xs text-slate-500 capitalize">{user?.role}</p>
                </div>
              </div>
              
              <button 
                onClick={() => setShowNotification(true)}
                className="p-2 hover:bg-slate-100 rounded-lg transition-colors relative"
              >
                <AlertCircle className="w-5 h-5 text-slate-600" />
                <span className="absolute -top-1 -right-1 w-2 h-2 bg-rose-500 rounded-full"></span>
              </button>
              
              <button 
                onClick={onLogout}
                className="flex items-center gap-2 px-4 py-2 text-slate-600 hover:text-slate-900 hover:bg-slate-100 rounded-lg transition-all"
              >
                <LogOut className="w-4 h-4" />
                <span className="text-sm font-medium">Logout</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="px-6 lg:px-8 py-8">
        <div className="max-w-7xl mx-auto">
          {/* Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div className="bg-white rounded-2xl p-6 shadow-lg border border-slate-200/60">
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 bg-indigo-50 rounded-xl">
                  <BarChart3 className="w-6 h-6 text-indigo-600" />
                </div>
                <span className="text-sm text-slate-500">Total</span>
              </div>
              <div className="text-3xl font-bold text-slate-900">{stats.total || 0}</div>
              <div className="flex items-center gap-1 mt-2">
                <TrendingUp className="w-4 h-4 text-emerald-500" />
                <span className="text-xs text-slate-500">All time</span>
              </div>
            </div>

            <div className="bg-white rounded-2xl p-6 shadow-lg border border-slate-200/60">
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 bg-emerald-50 rounded-xl">
                  <CheckCircle className="w-6 h-6 text-emerald-600" />
                </div>
                <span className="text-sm text-slate-500">Resolved</span>
              </div>
              <div className="text-3xl font-bold text-slate-900">{stats.resolved || 0}</div>
              <div className="text-xs text-emerald-600 mt-2">
                {stats.total > 0 ? `${Math.round((stats.resolved / stats.total) * 100)}% resolved` : 'No data'}
              </div>
            </div>

            <div className="bg-white rounded-2xl p-6 shadow-lg border border-slate-200/60">
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 bg-amber-50 rounded-xl">
                  <Clock className="w-6 h-6 text-amber-600" />
                </div>
                <span className="text-sm text-slate-500">Pending</span>
              </div>
              <div className="text-3xl font-bold text-slate-900">{stats.pending || 0}</div>
              <div className="text-xs text-amber-600 mt-2">Requires attention</div>
            </div>

            <div className="bg-white rounded-2xl p-6 shadow-lg border border-slate-200/60">
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 bg-blue-50 rounded-xl">
                  <TrendingUp className="w-6 h-6 text-blue-600" />
                </div>
                <span className="text-sm text-slate-500">In Progress</span>
              </div>
              <div className="text-3xl font-bold text-slate-900">{stats.inProgress || 0}</div>
              <div className="text-xs text-blue-600 mt-2">Being processed</div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Left Panel - Form */}
            <div className="lg:col-span-1">
              <div className="bg-white rounded-2xl shadow-lg border border-slate-200/60 overflow-hidden sticky top-24">
                <div className="p-6 border-b border-slate-100">
                  <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                    <Plus className="w-5 h-5 text-indigo-600" />
                    New Grievance
                  </h3>
                  <p className="text-sm text-slate-500 mt-1">Submit a new issue for review</p>
                </div>
                
                <form onSubmit={submit} className="p-6 space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-2">
                      Subject
                    </label>
                    <input 
                      className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none transition-all text-sm"
                      placeholder="Enter subject..."
                      value={title} 
                      onChange={e => setTitle(e.target.value)} 
                      required 
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-2">
                      Description
                    </label>
                    <textarea 
                      className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none text-sm h-40 resize-none transition-all"
                      placeholder="Describe the issue in detail..."
                      value={desc} 
                      onChange={e => setDesc(e.target.value)} 
                      required 
                    />
                  </div>
                  
                  <button 
                    disabled={loading}
                    className="w-full py-3.5 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white font-semibold rounded-xl shadow-lg transition-all transform hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
                  >
                    {loading ? (
                      <div className="flex items-center justify-center gap-2">
                        <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                        Submitting...
                      </div>
                    ) : 'Submit Grievance'}
                  </button>
                </form>
              </div>
            </div>

            {/* Right Panel - List */}
            <div className="lg:col-span-2">
              <div className="bg-white rounded-2xl shadow-lg border border-slate-200/60 overflow-hidden">
                <div className="p-6 border-b border-slate-100">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div>
                      <h3 className="text-lg font-bold text-slate-900">Recent Grievances</h3>
                      <p className="text-sm text-slate-500 mt-1">Track and manage all submitted issues</p>
                    </div>
                    
                    <div className="flex items-center gap-3">
                      <div className="relative">
                        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
                        <input 
                          type="text"
                          placeholder="Search grievances..."
                          className="pl-10 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none w-full"
                          value={searchTerm}
                          onChange={e => setSearchTerm(e.target.value)}
                        />
                      </div>
                      
                      <select 
                        className="px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none"
                        value={statusFilter}
                        onChange={e => setStatusFilter(e.target.value)}
                      >
                        <option value="all">All Status</option>
                        <option value="pending">Pending</option>
                        <option value="inProgress">In Progress</option>
                        <option value="resolved">Resolved</option>
                        <option value="rejected">Rejected</option>
                      </select>
                      
                      <button 
                        onClick={refreshData}
                        className="p-2 hover:bg-slate-100 rounded-lg transition-colors"
                        disabled={isRefreshing}
                      >
                        <RefreshCw className={`w-4 h-4 text-slate-600 ${isRefreshing ? 'animate-spin' : ''}`} />
                      </button>
                    </div>
                  </div>
                </div>
                
                <div className="overflow-hidden">
                  {error ? (
                    <div className="p-12 text-center">
                      <AlertCircle className="w-12 h-12 text-rose-400 mx-auto mb-4" />
                      <p className="text-rose-400 font-medium">{error}</p>
                    </div>
                  ) : filteredGrievances.length === 0 ? (
                    <div className="p-12 text-center">
                      <div className="w-16 h-16 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-4">
                        <AlertCircle className="w-8 h-8 text-slate-400" />
                      </div>
                      <h4 className="text-lg font-medium text-slate-700 mb-2">No grievances found</h4>
                      <p className="text-slate-500">
                        {searchTerm || statusFilter !== "all" 
                          ? "Try adjusting your search or filter criteria" 
                          : "Submit your first grievance to get started"}
                      </p>
                    </div>
                  ) : (
                    <div className="divide-y divide-slate-100 max-h-[600px] overflow-y-auto">
                      {filteredGrievances.map((g) => (
                        <div key={g._id} className="p-6 hover:bg-slate-50/50 transition-colors group">
                          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 mb-4">
                            <div className="flex-1">
                              <div className="flex items-start gap-3">
                                <div className={`p-2 rounded-lg ${getStatusColor(g.status)}`}>
                                  {getStatusIcon(g.status)}
                                </div>
                                <div>
                                  <h4 className="font-semibold text-slate-900 text-base mb-1">{g.title}</h4>
                                  <p className="text-slate-600 text-sm line-clamp-2">{g.description}</p>
                                </div>
                              </div>
                            </div>
                            
                            <div className="flex items-center gap-3">
                              <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${getStatusColor(g.status)}`}>
                                {g.status}
                              </span>
                              <ChevronRight className="w-4 h-4 text-slate-400 group-hover:translate-x-1 transition-transform" />
                            </div>
                          </div>
                          
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                            <div className="flex items-center gap-4 text-sm text-slate-500">
                              <span>ID: {g._id?.slice(-8)}</span>
                              <span>•</span>
                              <span>{new Date(g.createdAt || Date.now()).toLocaleDateString()}</span>
                            </div>
                            
                            {user?.role === 'admin' && (
                              <div className="flex gap-2">
                                <button 
                                  onClick={() => updateStatus(g._id, 'inProgress')}
                                  className="px-4 py-2 bg-blue-50 text-blue-700 hover:bg-blue-100 text-sm font-medium rounded-lg transition-colors"
                                >
                                  In Progress
                                </button>
                                <button 
                                  onClick={() => updateStatus(g._id, 'resolved')}
                                  className="px-4 py-2 bg-emerald-50 text-emerald-700 hover:bg-emerald-100 text-sm font-medium rounded-lg transition-colors"
                                >
                                  Resolve
                                </button>
                                <button 
                                  onClick={() => updateStatus(g._id, 'rejected')}
                                  className="px-4 py-2 bg-rose-50 text-rose-700 hover:bg-rose-100 text-sm font-medium rounded-lg transition-colors"
                                >
                                  Reject
                                </button>
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
        </div>
      </main>
    </div>
  );
}