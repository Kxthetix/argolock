import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { Dashboard } from './pages/Dashboard';
import { ScansPage } from './pages/ScansPage';
import { ScanDetailPage } from './pages/ScanDetailPage';
import { FindingsPage } from './pages/FindingsPage';
import { ReportsPage } from './pages/ReportsPage';
import { Login } from './pages/Login';
import { OAuthCallback } from './pages/OAuthCallback';
import { AgentsPage } from './pages/AgentsPage';
import { ToolStatusPage } from './pages/ToolStatusPage';
import { VaptValidationCenter } from './pages/VaptValidationCenter';
import { getStoredToken } from './lib/api';

function AuthGuard({ children }: { children: React.ReactNode }) {
  const token = getStoredToken();
  if (!token) {
    const currentPath = encodeURIComponent(window.location.pathname + window.location.search);
    return <Navigate to={`/login?redirect=${currentPath}`} replace />;
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public Routes */}
        <Route path="/login" element={<Login />} />
        <Route path="/auth/callback" element={<OAuthCallback />} />

        {/* Protected Application Routes */}
        <Route
          path="/*"
          element={
            <AuthGuard>
              <div className="app-layout">
                <Sidebar />
                <main className="main-content">
                  <Routes>
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/scans" element={<ScansPage />} />
                    <Route path="/scans/:id" element={<ScanDetailPage />} />
                    <Route path="/findings" element={<FindingsPage />} />
                    <Route path="/reports" element={<ReportsPage />} />
                    <Route path="/agents" element={<AgentsPage />} />
                    <Route path="/tool-status" element={<ToolStatusPage />} />
                    <Route path="/validation-center" element={<VaptValidationCenter />} />
                  </Routes>
                </main>
              </div>
            </AuthGuard>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
