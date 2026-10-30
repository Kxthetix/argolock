import React, { useEffect, useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, Scan, FileText, Activity, Shield, Cpu, ShieldCheck, Crosshair, LogOut, LogIn
} from 'lucide-react';
import { authApi, clearAuthSession, getStoredToken } from '../lib/api';

const navItems: { to: string; label: string; icon: any; exact?: boolean }[] = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, exact: true },
  { to: '/scans', label: 'Scans', icon: Scan },
  { to: '/platform', label: 'Enterprise Platform', icon: Crosshair },
  { to: '/validation-center', label: 'VAPT Center', icon: ShieldCheck },
  { to: '/findings', label: 'Findings', icon: Shield },
  { to: '/reports', label: 'Reports', icon: FileText },
];

export function Sidebar() {
  const navigate = useNavigate();
  const [user, setUser] = useState<{ name?: string; email: string; role?: string; avatar_url?: string } | null>(null);

  useEffect(() => {
    const fetchUser = async () => {
      const token = getStoredToken();
      if (!token) {
        setUser(null);
        return;
      }
      try {
        const data = await authApi.me();
        setUser(data);
      } catch (err) {
        setUser(null);
      }
    };
    fetchUser();
  }, []);

  const token = getStoredToken();
  const email = user?.email || (token ? localStorage.getItem('auth_email') : null);
  const role = user?.role || (token ? localStorage.getItem('auth_role') : null) || 'viewer';
  const displayName = user?.name || (email ? email.split('@')[0] : 'Operator');
  const avatarUrl = user?.avatar_url;

  const handleLogout = () => {
    authApi.logout();
    setUser(null);
    navigate('/login');
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-logo" style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Shield style={{ width: 22, height: 22, color: 'var(--accent-cyan)', filter: 'drop-shadow(0 0 5px rgba(0, 212, 255, 0.3))' }} />
          <span className="logo-text" style={{ fontSize: '20px', fontWeight: 900, letterSpacing: '-0.5px' }}>ArgoLock</span>
        </div>
        <div className="logo-tagline" style={{ marginTop: '2px' }}>AI-Powered VAPT Platform</div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-label">Navigation</div>

        {navItems.map(({ to, label, icon: Icon, exact }) => (
          <NavLink
            key={to}
            to={to}
            end={exact}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <Icon className="nav-icon" />
            <span>{label}</span>
          </NavLink>
        ))}

        <div className="nav-section-label" style={{ marginTop: 16 }}>System</div>
        <NavLink
          to="/agents"
          className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
        >
          <Cpu className="nav-icon" />
          <span>AI Agents</span>
          <span className="badge badge-blue" style={{ marginLeft: 'auto', fontSize: 9 }}>4 Active</span>
        </NavLink>
        <NavLink
          to="/tool-status"
          className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
        >
          <Activity className="nav-icon" />
          <span>Tool Status</span>
        </NavLink>
      </nav>

      <div className="sidebar-footer">
        {/* Operator Profile */}
        <div style={{
          padding: '12px',
          background: 'rgba(255, 255, 255, 0.02)',
          border: '1px solid rgba(255, 255, 255, 0.05)',
          borderRadius: '8px',
          marginBottom: '12px',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div className="nav-section-label" style={{ margin: 0 }}>OPERATOR CONSOLE</div>
            {token && (
              <span style={{
                fontSize: '9px',
                padding: '2px 6px',
                borderRadius: '4px',
                fontWeight: 700,
                textTransform: 'uppercase',
                background: role === 'admin' ? 'rgba(239, 68, 68, 0.2)' : role === 'analyst' ? 'rgba(99, 102, 241, 0.2)' : 'rgba(255, 255, 255, 0.1)',
                color: role === 'admin' ? '#f87171' : role === 'analyst' ? '#818cf8' : '#cbd5e1',
                border: `1px solid ${role === 'admin' ? 'rgba(239, 68, 68, 0.3)' : role === 'analyst' ? 'rgba(99, 102, 241, 0.3)' : 'rgba(255, 255, 255, 0.2)'}`,
              }}>
                {role}
              </span>
            )}
          </div>

          {token ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {avatarUrl ? (
                  <img 
                    src={avatarUrl} 
                    alt="Avatar" 
                    style={{ 
                      width: '24px', 
                      height: '24px', 
                      borderRadius: '50%',
                      objectFit: 'cover' 
                    }} 
                  />
                ) : (
                  <div style={{
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    background: 'rgba(99, 102, 241, 0.15)',
                    color: '#818cf8',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '11px',
                    fontWeight: 600,
                    border: '1px solid rgba(99, 102, 241, 0.25)'
                  }}>
                    {displayName.substring(0, 2).toUpperCase()}
                  </div>
                )}
                <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                  <span style={{ fontWeight: 600, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>{displayName}</span>
                  <span style={{ fontSize: '10px', color: 'rgba(255,255,255,0.4)', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>{email}</span>
                </div>
              </div>

              <button
                type="button"
                onClick={handleLogout}
                style={{
                  background: 'rgba(239, 68, 68, 0.08)',
                  border: '1px solid rgba(239, 68, 68, 0.25)',
                  borderRadius: '6px',
                  padding: '6px 12px',
                  color: '#f87171',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '6px',
                  marginTop: '4px',
                  width: '100%',
                  transition: 'background-color 0.2s',
                }}
              >
                <LogOut style={{ width: 13, height: 13 }} />
                <span>Sign Out</span>
              </button>
            </>
          ) : (
            <NavLink
              to="/login"
              style={{
                background: 'rgba(99, 102, 241, 0.15)',
                border: '1px solid rgba(99, 102, 241, 0.3)',
                borderRadius: '6px',
                padding: '8px 12px',
                color: '#818cf8',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '6px',
                marginTop: '4px',
                textDecoration: 'none',
                width: '100%',
              }}
            >
              <LogIn style={{ width: 14, height: 14 }} />
              <span>Operator Sign In</span>
            </NavLink>
          )}

          <NavLink
            to="/"
            style={{
              background: 'rgba(255, 255, 255, 0.03)',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: '6px',
              padding: '6px 12px',
              color: 'rgba(255, 255, 255, 0.6)',
              fontSize: '11px',
              fontWeight: 500,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px',
              marginTop: '2px',
              textDecoration: 'none',
              width: '100%',
            }}
          >
            <span>🌐</span>
            <span>Landing Page</span>
          </NavLink>
        </div>

        <div className="system-status">
          <div className="status-dot" />
          <span>All systems operational</span>
        </div>
      </div>
    </aside>
  );
}
