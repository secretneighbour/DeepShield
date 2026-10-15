import { useState, useEffect } from 'react';
import {
  Routes,
  Route,
  Navigate,
  useNavigate,
  useLocation,
  Link,
} from 'react-router-dom';
import {
  Shield,
  Activity,
  FileText,
  Link as LinkIcon,
  Image as ImageIcon,
  Video,
  Mic,
  History,
  Settings,
  Lock,
  Menu,
  X,
  Home,
  Globe,
  AlertCircle,
  ExternalLink,
  Copy,
  Check,
} from 'lucide-react';
import { DeepShieldLogo } from './components/DeepShieldLogo';

import type {
  StatsResponse,
  AnalysisRecordSummary,
  SystemCapabilitiesResponse,
  HealthResponse,
  TunnelStatusResponse,
} from './types';
import { fetchStats, fetchCapabilities, fetchAnalyses, fetchHealth, fetchTunnelStatus } from './api';

import { LandingPageView } from './components/LandingPageView';
import { OverviewView } from './components/OverviewView';
import { TextAnalyzerView } from './components/TextAnalyzerView';
import { UrlAnalyzerView } from './components/UrlAnalyzerView';
import { ImageAnalyzerView } from './components/ImageAnalyzerView';
import { VideoAnalyzerView } from './components/VideoAnalyzerView';
import { AudioAnalyzerView } from './components/AudioAnalyzerView';
import { HistoryView } from './components/HistoryView';
import { SettingsView } from './components/SettingsView';

export function App() {
  const navigate = useNavigate();
  const location = useLocation();

  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [capabilities, setCapabilities] = useState<SystemCapabilitiesResponse | null>(null);
  const [recentAnalyses, setRecentAnalyses] = useState<AnalysisRecordSummary[]>([]);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [tunnel, setTunnel] = useState<TunnelStatusResponse | null>(null);
  const [backendOffline, setBackendOffline] = useState(false);
  const [copiedTunnel, setCopiedTunnel] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Cross-component quick scan navigation states
  const [quickScanText, setQuickScanText] = useState<string>('');
  const [quickScanUrl, setQuickScanUrl] = useState<string>('');
  const [selectedRecordId, setSelectedRecordId] = useState<string | null>(null);

  const loadDashboardData = async () => {
    try {
      const [healthData, tunnelData, statsData, capData, analysesData] = await Promise.all([
        fetchHealth().catch(() => null),
        fetchTunnelStatus().catch(() => null),
        fetchStats().catch(() => null),
        fetchCapabilities().catch(() => null),
        fetchAnalyses(50, 0).catch(() => ({ records: [] })),
      ]);
      if (healthData) {
        setHealth(healthData);
        setBackendOffline(false);
      } else {
        setBackendOffline(true);
      }
      if (tunnelData) setTunnel(tunnelData);
      if (statsData) setStats(statsData);
      if (capData) setCapabilities(capData);
      if (analysesData) setRecentAnalyses(analysesData.records);
    } catch (e) {
      console.error('Failed to load initial metrics:', e);
      setBackendOffline(true);
    }
  };

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 12000);
    return () => clearInterval(interval);
  }, []);

  const handleQuickAnalyzeText = (text: string) => {
    setQuickScanText(text);
    navigate('/analyze/text');
  };

  const handleQuickAnalyzeUrl = (url: string) => {
    setQuickScanUrl(url);
    navigate('/analyze/url');
  };

  const handleSelectRecord = (id: string) => {
    setSelectedRecordId(id);
    navigate('/history');
  };

  const handleNavigateTab = (tabId: string) => {
    switch (tabId) {
      case 'overview':
        navigate('/dashboard');
        break;
      case 'text':
        navigate('/analyze/text');
        break;
      case 'url':
        navigate('/analyze/url');
        break;
      case 'image':
        navigate('/analyze/image');
        break;
      case 'video':
        navigate('/analyze/video');
        break;
      case 'audio':
        navigate('/analyze/audio');
        break;
      case 'history':
        navigate('/history');
        break;
      case 'settings':
        navigate('/settings');
        break;
      default:
        navigate('/dashboard');
    }
  };

  const navItems = [
    { id: 'overview', path: '/dashboard', label: 'Command Center', icon: Activity },
    { id: 'text', path: '/analyze/text', label: 'Scam Text', icon: FileText },
    { id: 'url', path: '/analyze/url', label: 'URL & Phishing', icon: LinkIcon },
    { id: 'image', path: '/analyze/image', label: 'Image Deepfake', icon: ImageIcon },
    { id: 'video', path: '/analyze/video', label: 'Video Deepfake', icon: Video },
    { id: 'audio', path: '/analyze/audio', label: 'Voice Authenticity', icon: Mic },
    { id: 'history', path: '/history', label: 'Forensic Audit Log', icon: History },
    { id: 'settings', path: '/settings', label: 'Threat Intel & Privacy', icon: Settings },
  ];

  // If on landing page route "/", render full cinematic LandingPageView
  if (location.pathname === '/') {
    return (
      <LandingPageView
        onEnterDashboard={() => navigate('/dashboard')}
        onNavigateAnalyze={(type) => navigate(`/analyze/${type}`)}
      />
    );
  }

  // Dashboard Application Layout (for /dashboard, /analyze/*, /history, /settings)
  return (
    <div className="min-h-screen bg-[#070a12] text-slate-100 flex flex-col font-sans">
      {/* Top Navbar */}
      <header className="sticky top-0 z-40 bg-[#090d16]/90 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Logo & Brand */}
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => navigate('/dashboard')}>
            <DeepShieldLogo size={24} showText={true} />
          </div>

          {/* Desktop Status Badges & Back to Home */}
          <div className="hidden md:flex items-center gap-3">
            <Link
              to="/"
              className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-xs text-slate-300 hover:text-white transition"
              title="Return to Public Presentation Page"
            >
              <Home size={13} className="text-cyan-400" />
              <span>Public Site</span>
            </Link>

            {/* ngrok Public Tunnel Live Indicator */}
            {tunnel?.status === 'online' && tunnel?.public_url ? (
              <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-950/80 border border-emerald-700/80 text-xs text-emerald-300">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                </span>
                <Globe size={12} className="text-emerald-400" />
                <span className="font-mono text-[11px] truncate max-w-[170px]" title={tunnel.public_url}>
                  {tunnel.public_url.replace('https://', '')}
                </span>
                <a
                  href={tunnel.public_url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-emerald-400 hover:text-white ml-0.5"
                  title="Open live public URL"
                >
                  <ExternalLink size={11} />
                </a>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(tunnel.public_url!);
                    setCopiedTunnel(true);
                    setTimeout(() => setCopiedTunnel(false), 2000);
                  }}
                  className="text-emerald-400 hover:text-white cursor-pointer ml-0.5"
                  title="Copy public URL"
                >
                  {copiedTunnel ? <Check size={11} className="text-white" /> : <Copy size={11} />}
                </button>
              </div>
            ) : (
              <div
                className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs text-slate-400"
                title="Laptop-hosted locally. Run ./run_ngrok.sh or ./start_all.sh to expose publicly."
              >
                <span className="w-2 h-2 rounded-full bg-slate-500"></span>
                <span className="text-[11px]">Laptop (Local Only)</span>
              </div>
            )}

            {/* Ollama local model indicator */}
            <div
              className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs text-slate-300"
              title={
                health?.ollama?.status === 'online'
                  ? 'Ollama running locally with Gemma 3 4B'
                  : 'Ollama offline, running with local calibrated heuristic baseline'
              }
            >
              <span
                className={`w-2 h-2 rounded-full ${
                  health?.ollama?.status === 'online' && health?.ollama?.target_model_installed
                    ? 'bg-cyan-400'
                    : 'bg-amber-400'
                }`}
              ></span>
              <span className="font-mono text-[11px]">
                {health?.ollama?.status === 'online' && health?.ollama?.target_model_installed
                  ? 'Gemma 3 4B Local'
                  : 'Heuristic Baseline'}
              </span>
            </div>

            <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs text-slate-400">
              <Lock size={12} className="text-cyan-400" />
              <span>Zero-Leakage</span>
            </div>
          </div>

          {/* Mobile Menu Button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-2 rounded-lg bg-slate-900 text-slate-300 hover:text-white border border-slate-800"
          >
            {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>

        {/* Navigation Tabs (Desktop) */}
        <div className="hidden md:block max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <nav className="flex space-x-1 -mb-px overflow-x-auto py-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <button
                  key={item.id}
                  onClick={() => navigate(item.path)}
                  className={`flex items-center gap-2 py-2.5 px-3.5 text-xs font-medium rounded-lg transition shrink-0 ${
                    isActive
                      ? 'bg-slate-800/90 text-cyan-400 shadow-sm border border-slate-700/60'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                  }`}
                >
                  <Icon size={15} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Mobile Navigation Dropdown */}
        {mobileMenuOpen && (
          <div className="md:hidden bg-slate-950 border-b border-slate-800 px-4 py-3 space-y-1">
            <Link
              to="/"
              onClick={() => setMobileMenuOpen(false)}
              className="w-full flex items-center gap-2.5 py-2.5 px-3 text-xs font-medium rounded-lg text-cyan-400 hover:bg-slate-900"
            >
              <Home size={16} />
              <span>Return to Public Site</span>
            </Link>
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    navigate(item.path);
                    setMobileMenuOpen(false);
                  }}
                  className={`w-full flex items-center gap-2.5 py-2.5 px-3 text-xs font-medium rounded-lg transition ${
                    isActive
                      ? 'bg-slate-800 text-cyan-400 border border-slate-700'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Icon size={16} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>
        )}
      </header>

      {/* Backend Offline Warning Banner */}
      {backendOffline && (
        <div className="bg-red-950/90 border-b border-red-500/50 px-4 py-3 text-red-200 text-xs flex items-center justify-between gap-3 sticky top-16 z-30 backdrop-blur-md">
          <div className="flex items-center gap-2">
            <AlertCircle size={16} className="text-red-400 shrink-0" />
            <span>
              <strong>Laptop Backend Service Offline:</strong> Unable to connect to the FastAPI Security Core at <code className="bg-red-900/60 px-1 py-0.5 rounded font-mono">/api</code> (port 8000). Ensure <code className="bg-red-900/60 px-1 py-0.5 rounded font-mono">./run_backend.sh</code> or <code className="bg-red-900/60 px-1 py-0.5 rounded font-mono">./start_all.sh</code> is running on your laptop.
            </span>
          </div>
          <button
            type="button"
            onClick={loadDashboardData}
            className="px-3 py-1 rounded-md bg-red-900 hover:bg-red-800 text-white font-medium transition cursor-pointer shrink-0"
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* Main Content View Container with React Router */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Routes>
          <Route
            path="/dashboard"
            element={
              <OverviewView
                stats={stats}
                recentAnalyses={recentAnalyses}
                capabilities={capabilities}
                onNavigateTab={handleNavigateTab}
                onQuickAnalyzeText={handleQuickAnalyzeText}
                onQuickAnalyzeUrl={handleQuickAnalyzeUrl}
                onSelectRecord={handleSelectRecord}
              />
            }
          />
          <Route
            path="/analyze/text"
            element={
              <TextAnalyzerView
                initialText={quickScanText}
                onAnalysisComplete={loadDashboardData}
              />
            }
          />
          <Route
            path="/analyze/url"
            element={
              <UrlAnalyzerView
                initialUrl={quickScanUrl}
                onAnalysisComplete={loadDashboardData}
              />
            }
          />
          <Route
            path="/analyze/image"
            element={<ImageAnalyzerView onAnalysisComplete={loadDashboardData} />}
          />
          <Route
            path="/analyze/video"
            element={<VideoAnalyzerView onAnalysisComplete={loadDashboardData} />}
          />
          <Route
            path="/analyze/audio"
            element={<AudioAnalyzerView onAnalysisComplete={loadDashboardData} />}
          />
          <Route
            path="/history"
            element={
              <HistoryView
                records={recentAnalyses}
                onRefresh={loadDashboardData}
                selectedRecordId={selectedRecordId}
                onClearSelectedRecord={() => setSelectedRecordId(null)}
              />
            }
          />
          <Route
            path="/settings"
            element={
              <SettingsView
                capabilities={capabilities}
                onRefreshCapabilities={loadDashboardData}
              />
            }
          />
          {/* Catch-all redirect to / */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>

      {/* Cybersecurity Operational Footer */}
      <footer className="mt-auto border-t border-slate-800/80 bg-[#090d16] py-6 px-4">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <Shield size={16} className="text-cyan-400" />
            <span className="font-semibold text-slate-200">DeepShield</span>
            <span className="text-cyan-400 font-mono hidden sm:inline">• See Beyond the Surface. Detect Deception.</span>
          </div>

          <div className="flex items-center gap-4 text-[11px] font-mono">
            <span>FastAPI Backend (Port 8000)</span>
            <span>•</span>
            <span>React + TypeScript Vite Frontend</span>
            <span>•</span>
            <span className="text-emerald-400">SQLite WAL Active</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
