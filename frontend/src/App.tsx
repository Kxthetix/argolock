import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { Dashboard } from './pages/Dashboard';
import { ScansPage } from './pages/ScansPage';
import { ScanDetailPage } from './pages/ScanDetailPage';
import { FindingsPage } from './pages/FindingsPage';
import { ReportsPage } from './pages/ReportsPage';
import { Login } from './pages/Login';
import { IS_DEMO } from './lib/api';

function AuthGuard({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('auth_token');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public Login Route */}
        <Route path="/login" element={<Login />} />

        {/* Protected Application Routes */}
        <Route
          path="/*"
          element={
            <AuthGuard>
              <div className="app-layout">
                {IS_DEMO && (
                  <div style={{
                    position: 'fixed',
                    top: 0,
                    left: 0,
                    right: 0,
                    zIndex: 1000,
                    background: 'linear-gradient(90deg, #7c3aed, #4f46e5)',
                    color: '#fff',
                    textAlign: 'center',
                    padding: '8px 16px',
                    fontSize: 12,
                    fontWeight: 600,
                    letterSpacing: 0.3,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 8,
                  }}>
                    <span style={{ fontSize: 14 }}>🔒</span>
                    <span>
                      <strong>DEMO MODE</strong> — All features are active with realistic sample data.
                      Deploy with a backend to run real scans.
                    </span>
                  </div>
                )}
                <div style={{ paddingTop: IS_DEMO ? 36 : 0, display: 'flex', flex: 1 }}>
                  <Sidebar />
                  <main className="main-content">
                    <Routes>
                      <Route path="/" element={<Dashboard />} />
                      <Route path="/scans" element={<ScansPage />} />
                      <Route path="/scans/:id" element={<ScanDetailPage />} />
                      <Route path="/findings" element={<FindingsPage />} />
                      <Route path="/reports" element={<ReportsPage />} />
                    </Routes>
                  </main>
                </div>
              </div>
            </AuthGuard>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
