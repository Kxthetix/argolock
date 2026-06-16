import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Scan, FileText, Activity, Shield, Cpu
} from 'lucide-react';

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
  { to: '/scans', label: 'Scans', icon: Scan },
  { to: '/findings', label: 'Findings', icon: Shield },
  { to: '/reports', label: 'Reports', icon: FileText },
];

export function Sidebar() {
  const email = localStorage.getItem('auth_email') || 'User';

  const handleLogout = () => {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('auth_email');
    window.location.href = '/login';
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-text">🔒 ArgoLock</div>
        <div className="logo-tagline">AI-Powered VAPT Platform</div>
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
        <div className="nav-item" style={{ cursor: 'default' }}>
          <Cpu className="nav-icon" />
          <span>AI Agents</span>
          <span className="badge badge-blue" style={{ marginLeft: 'auto', fontSize: 9 }}>4 Active</span>
        </div>
        <div className="nav-item" style={{ cursor: 'default' }}>
          <Activity className="nav-icon" />
          <span>Tool Status</span>
        </div>
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
            gap: '6px'
          }} title={email}>
            <span>👤</span>
            <span>{email}</span>
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
