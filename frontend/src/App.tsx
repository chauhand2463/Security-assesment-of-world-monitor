import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { DashboardLayout } from './layouts/DashboardLayout';
import { Dashboard } from './pages/Dashboard';
import { NewScan } from './pages/NewScan';
import { Scans } from './pages/Scans';
import { ScanDetail } from './pages/ScanDetail';
import { Findings } from './pages/Findings';
import { Assets } from './pages/Assets';
import { Reports } from './pages/Reports';
import { AIChat } from './pages/AIChat';
import { KnowledgeBase } from './pages/KnowledgeBase';
import { Settings } from './pages/Settings';
import { ToolHealth } from './pages/ToolHealth';
import { WorldMonitor } from './pages/WorldMonitor';
import { Auth } from './pages/Auth';
import Landing from './pages/Landing';
import { NotFound } from './pages/NotFound';
import { getToken, clearToken, onUnauthorized, apiFetch } from './api';
import { ErrorBoundary } from './components/ErrorBoundary';

const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return getToken() !== null;
  });

  const endSession = () => {
    window.history.replaceState(null, '', '/');
    setIsAuthenticated(false);
  };

  useEffect(() => {
    onUnauthorized(endSession);
    return () => onUnauthorized(() => {});
  }, []);

  const handleLoginSuccess = () => {
    window.history.replaceState(null, '', '/');
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    const token = getToken();
    clearToken();
    endSession();
    if (token) {
      apiFetch('/auth/logout', { method: 'POST' }).catch(() => {});
    }
  };

  /* ---- PUBLIC GATE: real public router for visitors ---- */
  if (!isAuthenticated) {
    return (
      <Router key="public">
        <Routes>
          <Route
            path="/"
            element={
              <ErrorBoundary>
                <Landing />
              </ErrorBoundary>
            }
          />
          <Route
            path="/auth"
            element={
              <ErrorBoundary>
                <Auth onLoginSuccess={handleLoginSuccess} />
              </ErrorBoundary>
            }
          />
          <Route
            path="*"
            element={
              <ErrorBoundary>
                <NotFound />
              </ErrorBoundary>
            }
          />
        </Routes>
      </Router>
    );
  }

  /* ---- AUTHENTICATED GATE: product unchanged ---- */
  return (
    <Router key="authed">
      <DashboardLayout onLogout={handleLogout}>
        <ErrorBoundary>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan/new" element={<NewScan />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/chat" element={<AIChat />} />
            <Route path="/knowledge" element={<KnowledgeBase />} />
            <Route path="/tools" element={<ToolHealth />} />
            <Route path="/world-monitor" element={<WorldMonitor />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </ErrorBoundary>
      </DashboardLayout>
    </Router>
  );
};

export default App;
