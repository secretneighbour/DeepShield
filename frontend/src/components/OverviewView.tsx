import React, { useState } from 'react';
import {
  ShieldAlert,
  Activity,
  FileText,
  Link,
  Image as ImageIcon,
  Video,
  Mic,
  Database,
  ArrowRight,
  Zap,
  MessageSquare,
  Download,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from 'recharts';
import type { StatsResponse, AnalysisRecordSummary, SystemCapabilitiesResponse, FeedbackStatsResponse } from '../types';
import { fetchFeedbackStats } from '../api';
import { RiskBadge } from './RiskBadge';

interface OverviewViewProps {
  stats: StatsResponse | null;
  recentAnalyses: AnalysisRecordSummary[];
  capabilities: SystemCapabilitiesResponse | null;
  onNavigateTab: (tab: string) => void;
  onQuickAnalyzeText: (text: string) => void;
  onQuickAnalyzeUrl: (url: string) => void;
  onSelectRecord: (id: string) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  stats,
  recentAnalyses,
  capabilities,
  onNavigateTab,
  onQuickAnalyzeText,
  onQuickAnalyzeUrl,
  onSelectRecord,
}) => {
  const [quickInput, setQuickInput] = useState('');
  const [fbStats, setFbStats] = useState<FeedbackStatsResponse | null>(null);

  React.useEffect(() => {
    fetchFeedbackStats().then(setFbStats).catch(() => {});
  }, []);

  const handleQuickSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = quickInput.trim();
    if (!trimmed) return;
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://') || trimmed.includes('.com') || trimmed.includes('.net') || trimmed.includes('.org') || trimmed.includes('.top') || trimmed.includes('.xyz')) {
      onQuickAnalyzeUrl(trimmed);
      onNavigateTab('url');
    } else {
      onQuickAnalyzeText(trimmed);
      onNavigateTab('text');
    }
  };

  // Prepare chart data from real database stats
  const mediaTypeData = [
    { name: 'Text', count: stats?.by_type?.text || 0, color: '#38bdf8' },
    { name: 'URL', count: stats?.by_type?.url || 0, color: '#6366f1' },
    { name: 'Image', count: stats?.by_type?.image || 0, color: '#a855f7' },
    { name: 'Video', count: stats?.by_type?.video || 0, color: '#ec4899' },
    { name: 'Audio', count: stats?.by_type?.audio || 0, color: '#f59e0b' },
  ];

  const riskLevelData = [
    { name: 'High Risk', count: stats?.by_risk?.HIGH_RISK || 0, color: '#ef4444' },
    { name: 'Medium Risk', count: stats?.by_risk?.MEDIUM_RISK || 0, color: '#f59e0b' },
    { name: 'Low Risk', count: stats?.by_risk?.LOW_RISK || 0, color: '#10b981' },
    { name: 'Inconclusive', count: stats?.by_risk?.INCONCLUSIVE || 0, color: '#64748b' },
  ];

  return (
    <div className="space-y-8">
      {/* Top Welcome / Hero Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-slate-800 p-6 md:p-8">
        <div className="relative z-10 max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/80 border border-cyan-800/50 text-cyan-300 text-xs font-mono mb-4">
            <Zap size={14} className="text-cyan-400" />
            <span>Multi-Vector Synthetic Media & Phishing Detection Engine</span>
          </div>
          <h1 className="text-2xl md:text-3xl font-bold text-white tracking-tight mb-3">
            See Beyond the Surface. <span className="bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">Detect Deception.</span>
          </h1>
          <p className="text-slate-400 text-sm leading-relaxed mb-6">
            DeepShield inspects suspicious SMS messages, emails, phishing URLs, synthetic voice cloning,
            and manipulated images/videos through transparent, evidence-based ML heuristics without fabricating certitude.
          </p>

          {/* Quick Omnibar Form */}
          <form onSubmit={handleQuickSubmit} className="flex gap-2 max-w-xl">
            <div className="relative flex-1">
              <input
                type="text"
                placeholder="Paste suspicious text message, scam claim, or URL..."
                value={quickInput}
                onChange={(e) => setQuickInput(e.target.value)}
                className="w-full bg-slate-950/90 border border-slate-700 rounded-xl px-4 py-3 text-sm text-slate-100 placeholder-slate-400 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition"
              />
            </div>
            <button
              type="submit"
              disabled={!quickInput.trim()}
              className="px-5 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-medium text-sm flex items-center gap-2 disabled:opacity-50 transition shadow-lg shadow-cyan-950"
            >
              <span>Scan Now</span>
              <ArrowRight size={16} />
            </button>
          </form>
        </div>
      </div>

      {/* KPI Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-medium">Total Forensics Scans</span>
            <Activity size={18} className="text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">
            {stats?.total_analyses ?? 0}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Real-time database audits</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-medium">Threats Intercepted</span>
            <ShieldAlert size={18} className="text-red-400" />
          </div>
          <div className="text-2xl font-bold text-red-400 font-mono">
            {stats?.high_risk_count ?? 0}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Classified High-Risk or Phishing</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-medium">Threat Intel Feeds</span>
            <Database size={18} className="text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-indigo-400 font-mono">
            {capabilities?.threat_intel_status?.local_reputation_engine?.signatures_loaded ?? 9}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Local curated threat signatures</div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-medium">Privacy Guard</span>
            <Zap size={18} className="text-emerald-400" />
          </div>
          <div className="text-lg font-bold text-emerald-400 font-mono mt-1">
            Zero-Retention Ready
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Configurable storage minimization</div>
        </div>
      </div>

      {/* Real Database Analytics Charts */}
      <div className="grid md:grid-cols-2 gap-6">
        <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800">
          <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center justify-between">
            <span>Analysis Volume by Vector</span>
            <span className="text-xs font-normal text-slate-400">Live DB Distribution</span>
          </h3>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={mediaTypeData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={12} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                  itemStyle={{ color: '#38bdf8' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {mediaTypeData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800">
          <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center justify-between">
            <span>Risk Severity Breakdown</span>
            <span className="text-xs font-normal text-slate-400">Calibrated Outcomes</span>
          </h3>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskLevelData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={12} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {riskLevelData.map((entry, index) => (
                    <Cell key={`cell-risk-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Forensic Modules Quick Launch Grid */}
      <div>
        <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">
          Forensic Inspection Pipelines
        </h3>
        <div className="grid md:grid-cols-5 gap-4">
          <button
            onClick={() => onNavigateTab('text')}
            className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-850 text-left transition group"
          >
            <div className="p-2.5 rounded-lg bg-cyan-950/60 border border-cyan-800/40 text-cyan-400 w-fit mb-3 group-hover:scale-105 transition">
              <FileText size={20} />
            </div>
            <h4 className="text-sm font-semibold text-slate-200 mb-1">Scam Text</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              SMS, emails, OTP solicitation, wire fraud, urgency tactics.
            </p>
          </button>

          <button
            onClick={() => onNavigateTab('url')}
            className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-indigo-500/50 hover:bg-slate-850 text-left transition group"
          >
            <div className="p-2.5 rounded-lg bg-indigo-950/60 border border-indigo-800/40 text-indigo-400 w-fit mb-3 group-hover:scale-105 transition">
              <Link size={20} />
            </div>
            <h4 className="text-sm font-semibold text-slate-200 mb-1">URL & Phishing</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Homoglyphs, lookalike domains, Shannon entropy, SSRF validation.
            </p>
          </button>

          <button
            onClick={() => onNavigateTab('image')}
            className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-purple-500/50 hover:bg-slate-850 text-left transition group"
          >
            <div className="p-2.5 rounded-lg bg-purple-950/60 border border-purple-800/40 text-purple-400 w-fit mb-3 group-hover:scale-105 transition">
              <ImageIcon size={20} />
            </div>
            <h4 className="text-sm font-semibold text-slate-200 mb-1">Image Deepfake</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Error Level Analysis (ELA), 2D FFT spectral grids, EXIF tampering.
            </p>
          </button>

          <button
            onClick={() => onNavigateTab('video')}
            className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-pink-500/50 hover:bg-slate-850 text-left transition group"
          >
            <div className="p-2.5 rounded-lg bg-pink-950/60 border border-pink-800/40 text-pink-400 w-fit mb-3 group-hover:scale-105 transition">
              <Video size={20} />
            </div>
            <h4 className="text-sm font-semibold text-slate-200 mb-1">Video Deepfake</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Temporal jitter, frame sampling anomaly timeline, face smoothing.
            </p>
          </button>

          <button
            onClick={() => onNavigateTab('audio')}
            className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-amber-500/50 hover:bg-slate-850 text-left transition group"
          >
            <div className="p-2.5 rounded-lg bg-amber-950/60 border border-amber-800/40 text-amber-400 w-fit mb-3 group-hover:scale-105 transition">
              <Mic size={20} />
            </div>
            <h4 className="text-sm font-semibold text-slate-200 mb-1">Audio Authenticity</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Pitch micro-jitter, vocoder spectral cutoff, dual-verdict transcript intent.
            </p>
          </button>
        </div>
      </div>

      {/* Continuous Learning & Feedback Driven Improvement */}
      <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
              <MessageSquare size={20} />
            </div>
            <div>
              <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <span>Feedback-Driven Model Improvement & Dataset Curation</span>
                <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
                  {fbStats?.active_detector_version || 'v1.2.0'}
                </span>
              </h3>
              <p className="text-xs text-slate-400">
                User corrections are reviewed and converted into regression tests and curated evaluation splits.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <a
              href="/api/feedback/export?format=jsonl"
              download="curated_deepshield_dataset.jsonl"
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono flex items-center gap-1.5 transition"
              title="Export approved and PII-redacted examples in JSONL format"
            >
              <Download size={14} className="text-cyan-400" />
              <span>Export JSONL</span>
            </a>
            <a
              href="/api/feedback/export?format=json"
              target="_blank"
              rel="noreferrer"
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono flex items-center gap-1.5 transition"
              title="View JSON format export"
            >
              <span>View JSON</span>
            </a>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800/80">
            <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">Total Submissions</span>
            <div className="text-xl font-bold font-mono text-slate-100">{fbStats?.total_feedback ?? 0}</div>
            <span className="text-[10px] text-slate-500">Across all 5 detectors</span>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800/80">
            <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">Reported False Positives</span>
            <div className="text-xl font-bold font-mono text-amber-400">{fbStats?.false_positives_count ?? 0}</div>
            <span className="text-[10px] text-slate-500">Safe items flagged</span>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800/80">
            <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">Reported False Negatives</span>
            <div className="text-xl font-bold font-mono text-rose-400">{fbStats?.false_negatives_count ?? 0}</div>
            <span className="text-[10px] text-slate-500">Missed scam vectors</span>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800/80">
            <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">Curated Training Samples</span>
            <div className="text-xl font-bold font-mono text-emerald-400">{fbStats?.dataset_eligible_count ?? 0}</div>
            <span className="text-[10px] text-slate-500">Accepted & PII redacted</span>
          </div>
        </div>
      </div>

      {/* Recent Investigations Feed */}
      <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-slate-200">Recent Forensic Investigations</h3>
          <button
            onClick={() => onNavigateTab('history')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 transition"
          >
            <span>View All Records</span>
            <ArrowRight size={14} />
          </button>
        </div>

        {recentAnalyses.length === 0 ? (
          <div className="py-8 text-center text-slate-400 text-sm">
            No forensic investigations recorded yet. Run your first analysis above.
          </div>
        ) : (
          <div className="divide-y divide-slate-800/60">
            {recentAnalyses.slice(0, 5).map((rec) => (
              <div
                key={rec.id}
                onClick={() => onSelectRecord(rec.id)}
                className="py-3 flex items-center justify-between gap-4 hover:bg-slate-800/40 px-2 rounded-lg cursor-pointer transition"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    {rec.analysis_type}
                  </span>
                  <span className="text-sm text-slate-200 truncate">{rec.target_summary}</span>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <RiskBadge level={rec.risk_level} confidence={rec.confidence} size="sm" />
                  <span className="text-xs text-slate-400 font-mono hidden md:inline">
                    {new Date(rec.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
