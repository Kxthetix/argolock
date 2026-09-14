import React, { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Scan, FileText, Activity, Shield, Cpu, ShieldCheck
} from 'lucide-react';
import { authApi } from '../lib/api';

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
  { to: '/scans', label: 'Scans', icon: Scan },
  { to: '/validation-center', label: 'VAPT Center', icon: ShieldCheck },
  { to: '/findings', label: 'Findings', icon: Shield },
  { to: '/reports', label: 'Reports', icon: FileText },
];

export function Sidebar() {
  const [user, setUser] = useState<{ name?: string; email: string; avatar_url?: string } | null>(null);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const data = await authApi.me();
        setUser(data);
      } catch (err) {
        console.error('Failed to fetch user profile:', err);
      }
    };
    fetchUser();
  }, []);

  const email = user?.email || localStorage.getItem('auth_email') || 'User';
  const displayName = user?.name || email.split('@')[0];
  const avatarUrl = user?.avatar_url;

  const handleLogout = () => {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('auth_email');
    window.location.href = '/login';
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
        {/* User Session and Logout */}
        <div style={{
          paddingBottom: '12px',
          borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
          marginBottom: '12px',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px'
        }}>
          <div style={{
            fontSize: '10px',
            color: 'rgba(255, 255, 255, 0.4)',
            textTransform: 'uppercase',
            letterSpacing: '0.5px',
            fontWeight: 600
          }}>
            Authenticated User
          </div>
          <div style={{
            fontSize: '13px',
            color: 'rgba(255, 255, 255, 0.85)',
            fontWeight: 500,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }} title={email}>
            {avatarUrl ? (
              <img 
                src={avatarUrl} 
                alt={displayName} 
                style={{ 
                  width: '24px', 
                  height: '24px', 
                  borderRadius: '50%', 
                  objectFit: 'cover',
                  border: '1px solid rgba(255, 255, 255, 0.1)'
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
            onClick={handleLogout}
            style={{
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.25)',
              borderRadius: '6px',
              padding: '8px 12px',
              color: '#f87171',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px',
              marginTop: '4px',
              transition: 'background-color 0.2s, border-color 0.2s',
              width: '100%'
            }}
            onMouseOver={(e) => {
              e.currentTarget.style.backgroundColor = 'rgba(239, 68, 68, 0.2)';
              e.currentTarget.style.borderColor = 'rgba(239, 68, 68, 0.4)';
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
              e.currentTarget.style.borderColor = 'rgba(239, 68, 68, 0.25)';
            }}
          >
            <span>🚪</span>
            <span>Log Out</span>
          </button>
        </div>

        <div className="system-status">
          <div className="status-dot" />
          <span>All systems operational</span>
        </div>
      </div>
    </aside>
  );
}
