import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { LandingPage } from './pages/LandingPage';
import { Dashboard } from './pages/Dashboard';
import { ScansPage } from './pages/ScansPage';
import { ScanDetailPage } from './pages/ScanDetailPage';
import { FindingsPage } from './pages/FindingsPage';
import { ReportsPage } from './pages/ReportsPage';
import { AgentsPage } from './pages/AgentsPage';
import { ToolStatusPage } from './pages/ToolStatusPage';
import { VaptValidationCenter } from './pages/VaptValidationCenter';
import { V17HubPage } from './pages/V17HubPage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Landing Page as Homepage */}
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<Navigate to="/" replace />} />

        {/* Application Workspace Routes (No Auth Barrier) */}
        <Route
          path="/*"
          element={
            <div className="app-layout">
              <Sidebar />
              <main className="main-content">
                <Routes>
                  <Route path="/dashboard" element={<Dashboard />} />
                  <Route path="/scans" element={<ScansPage />} />
                  <Route path="/scans/:id" element={<ScanDetailPage />} />
                  <Route path="/findings" element={<FindingsPage />} />
                  <Route path="/reports" element={<ReportsPage />} />
                  <Route path="/agents" element={<AgentsPage />} />
                  <Route path="/tool-status" element={<ToolStatusPage />} />
                  <Route path="/validation-center" element={<VaptValidationCenter />} />
                  <Route path="/platform" element={<V17HubPage />} />
                  <Route path="/v17" element={<Navigate to="/platform" replace />} />
                  <Route path="*" element={<Navigate to="/dashboard" replace />} />
                </Routes>
              </main>
            </div>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
