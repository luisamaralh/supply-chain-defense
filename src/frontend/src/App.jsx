import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, ShieldAlert, Activity, Server, AlertTriangle, Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer 
} from 'recharts';
import './index.css';

// In Docker Compose the Nginx proxy routes /api -> hunter-service, so the base is ''.
// For local Minikube port-forward, set VITE_API_URL=http://127.0.0.1:8000 in .env.local
const API_BASE = import.meta.env.VITE_API_URL ?? '';

function App() {
  const [recentMalware, setRecentMalware] = useState([]);
  const [stats, setStats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedRow, setExpandedRow] = useState(null);
  
  // Pagination & Filters State
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [pagination, setPagination] = useState({ total_pages: 1, total: 0 });

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(1); // Reset to page 1 on new search
    }, 500);
    return () => clearTimeout(timer);
  }, [search]);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const [recentRes, statsRes] = await Promise.all([
          axios.get(`${API_BASE}/api/vulnerabilities/recent?page=${page}&limit=10&search=${debouncedSearch}`),
          axios.get(`${API_BASE}/api/vulnerabilities/stats`)
        ]);
        setRecentMalware(recentRes.data.data);
        setPagination(recentRes.data.pagination);
        setStats(statsRes.data.data);
        setError(null);
      } catch (err) {
        setError('Failed to connect to Hunter Service API. In Docker Compose, ensure all services are running (docker compose ps). For Minikube, set VITE_API_URL=http://127.0.0.1:8000 in src/frontend/.env.local and rebuild.');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [page, debouncedSearch]);

  const handlePrevPage = () => {
    if (page > 1) setPage(page - 1);
  };

  const handleNextPage = () => {
    if (page < pagination.total_pages) setPage(page + 1);
  };

  return (
    <div className="dashboard">
      <header className="header">
        <h1 style={{ display: 'flex', alignItems: 'center' }}>
          <Shield style={{ marginRight: '10px' }} size={32} />
          OSINT Supply Chain Defense
        </h1>
        <div className="glow-text text-sm" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Activity size={18} /> Default Namespace (Minikube)
        </div>
      </header>

      {error && (
        <div className="glass-panel" style={{ padding: '1rem', borderColor: 'var(--danger)' }}>
          <p className="danger-text" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertTriangle /> {error}
          </p>
        </div>
      )}

      <div className="grid-container">
        {/* Statistics Chart Widget */}
        <div className="glass-panel widget">
          <h2 className="widget-title"><Server size={20} /> Ecosystem Compromises</h2>
          <div style={{ height: 350 }}>
            {stats.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" horizontal={false} />
                  <XAxis type="number" stroke="var(--text-secondary)" />
                  <YAxis dataKey="ecosystem" type="category" stroke="var(--text-secondary)" width={80} />
                  <Tooltip 
                    cursor={{fill: 'rgba(255,255,255,0.05)'}}
                    contentStyle={{ backgroundColor: 'var(--bg-color)', borderColor: 'var(--accent)', borderRadius: '8px' }}
                  />
                  <Bar dataKey="count" fill="var(--accent-secondary)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
               <div style={{ textAlign: 'center', color: 'var(--text-secondary)', marginTop: '2rem' }}>No generic stats to present.</div>
            )}
          </div>
        </div>

        {/* Recent Malware List Widget */}
        <div className="glass-panel widget" style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
            <h2 className="widget-title" style={{ marginBottom: 0 }}><ShieldAlert size={20} /> Malware Database</h2>
            <div style={{ display: 'flex', alignItems: 'center', background: 'var(--bg-color)', border: '1px solid var(--glass-border)', borderRadius: '8px', padding: '0.4rem 0.8rem' }}>
              <Search size={16} style={{ color: 'var(--text-secondary)', marginRight: '8px' }} />
              <input 
                type="text" 
                placeholder="Filter by package..." 
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-primary)', outline: 'none', width: '180px' }}
              />
            </div>
          </div>
          
          {loading && !recentMalware.length ? (
             <div className="loading glow-text" style={{ flex: 1, fontSize: '1.2rem' }}>Fetching Records...</div>
          ) : (
          <div style={{ flex: 1, overflowX: 'auto', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Vulnerability ID</th>
                  <th>Package Name</th>
                  <th>Date Recorded</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentMalware.map((item) => (
                  <React.Fragment key={item.id}>
                  <tr onClick={() => setExpandedRow(expandedRow === item.id ? null : item.id)} style={{ cursor: 'pointer' }}>
                    <td className="glow-text" style={{ fontSize: '0.85rem' }}>{item.id}</td>
                    <td style={{ fontWeight: 600 }}>{item.package_name}</td>
                    <td>{item.published ? new Date(item.published).toISOString().split('T')[0] : 'Unknown'}</td>
                    <td><span className="badge">MALICIOUS</span></td>
                    <td>
                      <button 
                        style={{
                          background: 'transparent', 
                          border: '1px solid var(--accent)', 
                          color: 'var(--accent)',
                          padding: '0.3rem 0.6rem',
                          borderRadius: '4px',
                          cursor: 'pointer',
                          fontWeight: '600',
                          fontSize: '0.8rem'
                        }}
                        onClick={(e) => { e.stopPropagation(); alert(`Webhook triggering hunt for ${item.package_name} disabled in preview!`); }}
                      >
                        Hunt
                      </button>
                    </td>
                  </tr>
                  {expandedRow === item.id && (
                    <tr style={{ background: 'rgba(0,0,0,0.2)' }}>
                      <td colSpan="5" style={{ padding: '1.5rem', borderBottom: '1px solid var(--glass-border)' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(200px, 1fr) 2fr', gap: '2rem' }}>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                                <strong style={{ color: 'var(--accent)' }}>Affected Ecosystem:</strong>
                                <span style={{ color: 'var(--text-primary)', background: 'var(--glass-bg)', padding: '4px 12px', borderRadius: '4px', width: 'fit-content' }}>{item.ecosystem}</span>
                                
                                <strong style={{ color: 'var(--accent)', marginTop: '1rem' }}>Affected Versions:</strong>
                                {item.affected_versions && item.affected_versions.length > 0 
                                  ? <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                                      {item.affected_versions.map(v => <span key={v} style={{ background: 'var(--glass-bg)', padding: '2px 8px', borderRadius: '4px', fontSize: '0.8rem' }}>{v}</span>)}
                                    </div>
                                  : <span style={{ color: 'var(--text-secondary)' }}>All versions (or unspecified)</span>
                                }
                            </div>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                                <strong style={{ color: 'var(--accent)' }}>Summary:</strong>
                                <p style={{ color: 'var(--text-secondary)', lineHeight: '1.5' }}>{item.summary}</p>
                            </div>
                        </div>
                      </td>
                    </tr>
                  )}
                  </React.Fragment>
                ))}
                {recentMalware.length === 0 && (
                  <tr>
                    <td colSpan="5" style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>No records matched your search.</td>
                  </tr>
                )}
              </tbody>
            </table>
            
            {/* Pagination Controls */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1.5rem', paddingTop: '1rem', borderTop: '1px solid var(--glass-border)', color: 'var(--text-secondary)' }}>
                <span style={{ fontSize: '0.85rem' }}>Total Results: <strong style={{ color: 'var(--text-primary)' }}>{pagination.total}</strong></span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <button 
                      onClick={handlePrevPage} 
                      disabled={page === 1}
                      style={{ background: 'transparent', border: 'none', color: page === 1 ? 'var(--text-secondary)' : 'var(--accent)', cursor: page === 1 ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center'}}
                    >
                        <ChevronLeft size={20} /> Prev
                    </button>
                    <span style={{ fontSize: '0.85rem' }}>
                        Page <strong style={{ color: 'var(--text-primary)' }}>{page}</strong> of {pagination.total_pages}
                    </span>
                    <button 
                      onClick={handleNextPage} 
                      disabled={page === pagination.total_pages || pagination.total_pages === 0}
                      style={{ background: 'transparent', border: 'none', color: page === pagination.total_pages || pagination.total_pages === 0 ? 'var(--text-secondary)' : 'var(--accent)', cursor: page === pagination.total_pages || pagination.total_pages === 0 ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center'}}
                    >
                        Next <ChevronRight size={20} />
                    </button>
                </div>
            </div>
          </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
