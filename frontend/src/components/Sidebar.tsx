import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, Scan, FileText, Activity,
  Shield, ChevronRight, Cpu
} from 'lucide-react';

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
  { to: '/scans', label: 'Scans', icon: Scan },
  { to: '/findings', label: 'Findings', icon: Shield },
  { to: '/reports', label: 'Reports', icon: FileText },
];

export function Sidebar() {
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
        <div className="system-status">
          <div className="status-dot" />
          <span>All systems operational</span>
        </div>
      </div>
    </aside>
  );
}
