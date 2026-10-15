import React, { useState, useEffect } from 'react';
import {
  Settings,
  Lock,
  Cpu,
  Play,
  Loader2,
  Cloud,
  CheckCircle,
  AlertTriangle,
  Info,
  Server,
  Zap,
  Globe,
  ExternalLink,
  Copy,
  Check,
} from 'lucide-react';
import type {
  SystemCapabilitiesResponse,
  EvaluationResponse,
  CloudAnalysisSettingsResponse,
  LLMStatusResponse,
  TunnelStatusResponse,
} from '../types';
import {
  toggleZeroRetention,
  runEvaluation,
  fetchCloudAnalysisSetting,
  updateCloudAnalysisSetting,
  fetchLLMStatus,
  fetchTunnelStatus,
} from '../api';

interface SettingsViewProps {
  capabilities: SystemCapabilitiesResponse | null;
  onRefreshCapabilities: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  capabilities,
  onRefreshCapabilities,
}) => {
  const [zeroRetention, setZeroRetention] = useState(false);
  const [evalLoading, setEvalLoading] = useState(false);
  const [evalResults, setEvalResults] = useState<EvaluationResponse | null>(null);
  const [evalError, setEvalError] = useState<string | null>(null);

  // Cloud Analysis & LLM pipeline states
  const [cloudSetting, setCloudSetting] = useState<CloudAnalysisSettingsResponse | null>(null);
  const [cloudLoading, setCloudLoading] = useState(false);
  const [llmStatus, setLlmStatus] = useState<LLMStatusResponse | null>(null);
  const [llmLoading, setLlmLoading] = useState(false);

  // ngrok Tunnel & Laptop Hosting states
  const [tunnelStatus, setTunnelStatus] = useState<TunnelStatusResponse | null>(null);
  const [tunnelLoading, setTunnelLoading] = useState(false);
  const [copiedTunnelUrl, setCopiedTunnelUrl] = useState(false);

  const loadCloudSettings = async () => {
    try {
      const res = await fetchCloudAnalysisSetting();
      setCloudSetting(res);
    } catch {
      // Non-fatal, use default
    }
  };

  const loadLLMDiagnostics = async () => {
    setLlmLoading(true);
    try {
      const res = await fetchLLMStatus();
      setLlmStatus(res);
    } catch {
      // Non-fatal
    } finally {
      setLlmLoading(false);
    }
  };

  const loadTunnelDiagnostics = async () => {
    setTunnelLoading(true);
    try {
      const res = await fetchTunnelStatus();
      setTunnelStatus(res);
    } catch {
      // Non-fatal
    } finally {
      setTunnelLoading(false);
    }
  };

  useEffect(() => {
    loadCloudSettings();
    loadLLMDiagnostics();
    loadTunnelDiagnostics();
  }, []);

  const handleToggleCloudAnalysis = async (enabled: boolean) => {
    setCloudLoading(true);
    try {
      const updated = await updateCloudAnalysisSetting(enabled);
      setCloudSetting(updated);
      await loadLLMDiagnostics();
    } catch (err: any) {
      alert(`Could not update cloud analysis setting: ${err.message}`);
    } finally {
      setCloudLoading(false);
    }
  };

  const handleToggleZeroRetention = async (enabled: boolean) => {
    setZeroRetention(enabled);
    try {
      await toggleZeroRetention(enabled);
      onRefreshCapabilities();
    } catch (err: any) {
      alert(`Could not toggle privacy mode: ${err.message}`);
    }
  };

  const handleRunEvaluation = async () => {
    setEvalLoading(true);
    setEvalError(null);
    try {
      const res = await runEvaluation();
      setEvalResults(res);
    } catch (err: any) {
      setEvalError(err.message || 'Evaluation run failed.');
    } finally {
      setEvalLoading(false);
    }
  };

  const threatIntel = capabilities?.threat_intel_status;

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Settings className="text-cyan-400" size={22} />
          <span>Security Architecture, AI Pipeline & Privacy Settings</span>
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Configure two-stage LLM inference policies, manage cloud privacy disclosures, inspect threat-intel adapters, and run independent benchmark evaluations.
        </p>
      </div>

      {/* SECTION 7: USER-CONTROLLED CLOUD PRIVACY SETTING */}
      <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900/90 to-slate-950/90 border border-indigo-900/40 shadow-xl space-y-5">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-2 max-w-2xl">
            <div className="flex items-center gap-2.5 flex-wrap">
              <Cloud className="text-indigo-400" size={20} />
              <h3 className="text-base font-semibold text-slate-100">
                Enable Gemini cloud analysis
              </h3>
              {cloudSetting?.server_allowed === false && (
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800/80 flex items-center gap-1">
                  <AlertTriangle size={11} />
                  Server Policy Override (Admin Disabled)
                </span>
              )}
              {cloudSetting?.effective_enabled ? (
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800/80 flex items-center gap-1">
                  <CheckCircle size={11} />
                  Stage 2 Review Active
                </span>
              ) : (
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 flex items-center gap-1">
                  Local Stage Only
                </span>
              )}
            </div>

            {/* MANDATORY EXACT SECTION 7 EXPLANATION */}
            <p className="text-xs text-slate-300 leading-relaxed font-sans bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
              When enabled, your submitted text and the local model&apos;s findings are sent to Google&apos;s Gemini service for additional analysis. Avoid submitting passwords, OTPs, private credentials, or other sensitive information.
            </p>

            <div className="flex items-center gap-4 text-[11px] text-slate-400 pt-1">
              <span className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${cloudSetting?.user_enabled ? 'bg-indigo-400' : 'bg-slate-600'}`}></span>
                User Preference: <strong className="text-slate-200">{cloudSetting?.user_enabled ? 'Enabled' : 'Disabled'}</strong>
              </span>
              <span className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${cloudSetting?.server_allowed ? 'bg-emerald-400' : 'bg-red-400'}`}></span>
                Server Allowed: <strong className="text-slate-200">{cloudSetting?.server_allowed ? 'Allowed (LLM_CLOUD_ENABLED=true)' : 'Blocked by Admin Policy'}</strong>
              </span>
            </div>
          </div>

          <label className="relative inline-flex items-center cursor-pointer shrink-0 mt-1">
            <input
              type="checkbox"
              checked={cloudSetting?.user_enabled ?? true}
              disabled={cloudLoading}
              onChange={(e) => handleToggleCloudAnalysis(e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-12 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600 peer-disabled:opacity-50"></div>
          </label>
        </div>

        <div className="grid sm:grid-cols-2 gap-3 pt-3 border-t border-slate-800/80 text-xs text-slate-400">
          <div className="flex items-start gap-2 bg-slate-950/40 p-2.5 rounded-lg border border-slate-900">
            <Zap size={14} className="text-cyan-400 shrink-0 mt-0.5" />
            <span><strong>Strict Order Enforced:</strong> Stage 1 Local LLM is always executed first. Gemini is never called first or as a silent bypass.</span>
          </div>
          <div className="flex items-start gap-2 bg-slate-950/40 p-2.5 rounded-lg border border-slate-900">
            <Lock size={14} className="text-indigo-400 shrink-0 mt-0.5" />
            <span><strong>Privacy Boundary:</strong> When cloud is disabled or blocked, Gemini receives zero payload and stage status is marked <code className="text-indigo-300">not_run_cloud_disabled</code>.</span>
          </div>
        </div>
      </div>

      {/* TWO-STAGE LLM INFERENCE STATUS & HARDWARE SPECS */}
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-5">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Cpu className="text-cyan-400" size={18} />
              <span>Two-Stage LLM Pipeline Diagnostics & Telemetry</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Real-time connectivity and configuration status for the local model candidate and cloud review service.
            </p>
          </div>
          <button
            onClick={loadLLMDiagnostics}
            disabled={llmLoading}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 flex items-center gap-1.5 disabled:opacity-50"
          >
            {llmLoading ? <Loader2 size={12} className="animate-spin" /> : <Server size={12} />}
            <span>Refresh Providers</span>
          </button>
        </div>

        <div className="grid md:grid-cols-2 gap-4">
          {/* Stage 1: Local Ollama / Heuristic Fallback */}
          <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs uppercase font-mono tracking-wider font-semibold text-cyan-400">
                Stage 1: Local LLM (Ollama)
              </span>
              <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded ${
                llmStatus?.ollama?.status === 'online'
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  : 'bg-amber-950 text-amber-300 border border-amber-800'
              }`}>
                {llmStatus?.ollama?.status === 'online' ? 'ONLINE (OLLAMA)' : 'FALLBACK HEURISTIC'}
              </span>
            </div>

            <div className="space-y-1.5 text-xs font-mono">
              <div className="flex justify-between text-slate-400">
                <span>Target Model:</span>
                <span className="text-slate-200">{llmStatus?.ollama?.target_model || 'gemma3:4b'}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Base Endpoint:</span>
                <span className="text-slate-200 truncate max-w-[200px]">{llmStatus?.ollama?.base_url || 'http://127.0.0.1:11434'}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Model Installed:</span>
                <span className={llmStatus?.ollama?.target_model_installed ? 'text-emerald-400' : 'text-slate-400'}>
                  {llmStatus?.ollama?.target_model_installed ? 'Yes' : 'Not Detected'}
                </span>
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800/80 text-[11px] text-slate-400 leading-relaxed">
              {llmStatus?.ollama?.instruction || 'To run the local stage with Gemma 3 4B, execute `ollama run gemma3:4b` locally.'}
            </div>
          </div>

          {/* Stage 2: Google Gemini Reviewer */}
          <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs uppercase font-mono tracking-wider font-semibold text-indigo-400">
                Stage 2: Gemini Cloud Reviewer
              </span>
              <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded ${
                llmStatus?.gemini?.api_key_configured
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  : 'bg-slate-800 text-slate-400 border border-slate-700'
              }`}>
                {llmStatus?.gemini?.api_key_configured ? 'KEY CONFIGURED' : 'API KEY UNSET'}
              </span>
            </div>

            <div className="space-y-1.5 text-xs font-mono">
              <div className="flex justify-between text-slate-400">
                <span>Configured Model:</span>
                <span className="text-slate-200">{llmStatus?.gemini?.configured_model || 'gemini-2.5-flash'}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Timeout Limit:</span>
                <span className="text-slate-200">{llmStatus?.gemini?.timeout_seconds || 45}s</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Max Output Tokens:</span>
                <span className="text-slate-200">{llmStatus?.gemini?.max_output_tokens || 1024}</span>
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800/80 text-[11px] text-slate-400 leading-relaxed">
              Provides adversarial critique of local findings, evidence verification, and safety recommendations via official Google GenAI SDK.
            </div>
          </div>
        </div>
      </div>

      {/* LAPTOP-HOSTED ARCHITECTURE & NGROK REVERSE PROXY */}
      <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900/90 to-slate-950/90 border border-cyan-900/40 shadow-xl space-y-5">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Globe className="text-cyan-400" size={18} />
              <span>Laptop-Hosted Architecture & ngrok Reverse Proxy</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Zero cloud infrastructure dependency. All processing, models, and databases run locally on your laptop, exposed securely via ngrok HTTPS.
            </p>
          </div>
          <button
            onClick={loadTunnelDiagnostics}
            disabled={tunnelLoading}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 flex items-center gap-1.5 disabled:opacity-50 cursor-pointer"
          >
            {tunnelLoading ? <Loader2 size={12} className="animate-spin" /> : <Server size={12} />}
            <span>Refresh Tunnel</span>
          </button>
        </div>

        {/* Public Tunnel Status Callout */}
        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <span className={`w-2.5 h-2.5 rounded-full ${tunnelStatus?.status === 'online' ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`}></span>
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                Public Tunnel: {tunnelStatus?.status === 'online' ? 'ACTIVE & EXPOSED' : 'OFFLINE (LOCAL ONLY)'}
              </span>
            </div>
            {tunnelStatus?.persistent_domain_configured && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                Persistent Domain Active
              </span>
            )}
          </div>

          {tunnelStatus?.public_url ? (
            <div className="flex items-center justify-between gap-3 p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/60 flex-wrap">
              <div className="flex items-center gap-2">
                <Globe size={16} className="text-emerald-400 shrink-0" />
                <span className="text-xs font-mono font-semibold text-emerald-300 select-all">
                  {tunnelStatus.public_url}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <a
                  href={tunnelStatus.public_url}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2.5 py-1 rounded bg-emerald-900/80 hover:bg-emerald-800 text-white text-xs font-mono flex items-center gap-1 transition"
                >
                  <ExternalLink size={12} />
                  <span>Open URL</span>
                </a>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(tunnelStatus.public_url!);
                    setCopiedTunnelUrl(true);
                    setTimeout(() => setCopiedTunnelUrl(false), 2000);
                  }}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono flex items-center gap-1 transition cursor-pointer"
                >
                  {copiedTunnelUrl ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                  <span>{copiedTunnelUrl ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-400 bg-slate-900/80 p-3 rounded-lg border border-slate-800 leading-relaxed font-mono">
              {tunnelStatus?.message || "Tunnel offline. Run './run_ngrok.sh' or './start_all.sh' to establish public HTTPS tunnel."}
            </p>
          )}
        </div>

        {/* Local Services & Reverse Proxy Port Mapping Grid */}
        <div className="grid sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
            <div className="text-[10px] text-cyan-400 uppercase tracking-wider font-semibold">1. Web Reverse Proxy</div>
            <div className="text-slate-200 font-bold">Port 5173 (Single Entry)</div>
            <div className="text-[11px] text-slate-400">Serves React SPA & proxies /api/* to FastAPI backend</div>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
            <div className="text-[10px] text-cyan-400 uppercase tracking-wider font-semibold">2. Security Core Backend</div>
            <div className="text-slate-200 font-bold">Port 8000 (FastAPI)</div>
            <div className="text-[11px] text-slate-400">Forensics, SQLite WAL, rate limits, MIME magic verification</div>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
            <div className="text-[10px] text-emerald-400 uppercase tracking-wider font-semibold">3. Local Ollama Daemon</div>
            <div className="text-slate-200 font-bold">Port 11434 (Loopback)</div>
            <div className="text-[11px] text-slate-400">Strictly 127.0.0.1; NEVER exposed to the public internet</div>
          </div>
        </div>
      </div>

      {/* Zero Retention Ephemeral Privacy Mode */}
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Lock className="text-emerald-400" size={18} />
              <h3 className="text-base font-semibold text-slate-100">Zero-Retention Ephemeral Mode</h3>
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                Privacy Standard
              </span>
            </div>
            <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
              When enabled, DeepShield executes all analyses strictly in-memory. Zero message content, full results,
              or forensic summaries are committed to the local database or disk. Ideal for processing sensitive enterprise communications.
            </p>
          </div>

          <label className="relative inline-flex items-center cursor-pointer shrink-0">
            <input
              type="checkbox"
              checked={zeroRetention}
              onChange={(e) => handleToggleZeroRetention(e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-500"></div>
          </label>
        </div>
      </div>

      {/* Threat Intelligence Providers Grid */}
      <div className="space-y-4">
        <h3 className="text-sm uppercase tracking-wider font-semibold text-slate-400">
          Integrated Threat Intelligence Adapters
        </h3>

        <div className="grid md:grid-cols-3 gap-4">
          {/* Local Curated Feed */}
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-slate-200">Local Signature Feed</span>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                ACTIVE (OFFLINE)
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Curated local threat database providing zero-latency phishing domain checking without network transmission.
            </p>
            <div className="text-xs font-mono text-cyan-400 pt-2 border-t border-slate-800">
              Signatures Loaded: {threatIntel?.local_reputation_engine?.signatures_loaded ?? 9}
            </div>
          </div>

          {/* Google Safe Browsing */}
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-slate-200">Google Safe Browsing</span>
              <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded ${
                threatIntel?.google_safe_browsing?.api_key_configured
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  : 'bg-slate-800 text-slate-400 border border-slate-700'
              }`}>
                {threatIntel?.google_safe_browsing?.api_key_configured ? 'CONFIGURED' : 'OPTIONAL (UNSET)'}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Cross-references Google&apos;s global list of suspected phishing, malware, and unwanted software URLs.
            </p>
            <div className="text-[11px] font-mono text-slate-400 pt-2 border-t border-slate-800">
              Env: SAFE_BROWSING_API_KEY
            </div>
          </div>

          {/* VirusTotal */}
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-slate-200">VirusTotal v3</span>
              <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded ${
                threatIntel?.virustotal?.api_key_configured
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  : 'bg-slate-800 text-slate-400 border border-slate-700'
              }`}>
                {threatIntel?.virustotal?.api_key_configured ? 'CONFIGURED' : 'OPTIONAL (UNSET)'}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Aggregates results from 70+ antivirus and URL scanners. Targets sent only with explicit configuration.
            </p>
            <div className="text-[11px] font-mono text-slate-400 pt-2 border-t border-slate-800">
              Env: VIRUSTOTAL_API_KEY
            </div>
          </div>
        </div>
      </div>

      {/* Held-out Benchmark Evaluator */}
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Cpu className="text-cyan-400" size={20} />
              <h3 className="text-base font-semibold text-slate-100">
                Independent Held-Out Benchmark & Model Evaluation
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-xl">
              Execute live validation against a held-out evaluation corpus (isolated from model training weights) to calculate
              actual precision, recall, confusion matrix, and false-positive rates without data leakage.
            </p>
          </div>

          <button
            onClick={handleRunEvaluation}
            disabled={evalLoading}
            className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white text-xs font-semibold flex items-center gap-2 disabled:opacity-50 transition shadow-lg shadow-cyan-950 self-start sm:self-center"
          >
            {evalLoading ? (
              <>
                <Loader2 size={14} className="animate-spin" />
                <span>Running Benchmark Suite...</span>
              </>
            ) : (
              <>
                <Play size={14} />
                <span>Run Evaluation Suite</span>
              </>
            )}
          </button>
        </div>

        {evalError && (
          <div className="p-3 rounded-lg bg-red-950/40 border border-red-500/40 text-red-300 text-xs">
            {evalError}
          </div>
        )}

        {evalResults && (
          <div className="space-y-6 pt-4 border-t border-slate-800 animate-in fade-in duration-200">
            {/* Metric KPI Cards */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[11px] text-slate-400 uppercase font-medium">Accuracy</span>
                <div className="text-xl font-bold font-mono text-cyan-400 mt-1">
                  {(evalResults.metrics.accuracy * 100).toFixed(1)}%
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[11px] text-slate-400 uppercase font-medium">Precision</span>
                <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
                  {(evalResults.metrics.precision * 100).toFixed(1)}%
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[11px] text-slate-400 uppercase font-medium">Recall (Sensitivity)</span>
                <div className="text-xl font-bold font-mono text-indigo-400 mt-1">
                  {(evalResults.metrics.recall * 100).toFixed(1)}%
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[11px] text-slate-400 uppercase font-medium">F1 Score</span>
                <div className="text-xl font-bold font-mono text-purple-400 mt-1">
                  {(evalResults.metrics.f1_score * 100).toFixed(1)}%
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-[11px] text-slate-400 uppercase font-medium">False Positive Rate</span>
                <div className="text-xl font-bold font-mono text-amber-400 mt-1">
                  {(evalResults.metrics.false_positive_rate * 100).toFixed(1)}%
                </div>
              </div>
            </div>

            {/* Confusion Matrix Table */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
              <h4 className="text-xs uppercase tracking-wider text-slate-300 font-semibold mb-3">
                Confusion Matrix (Held-out Benchmark Dataset)
              </h4>
              <div className="grid grid-cols-2 gap-3 max-w-md mx-auto text-center font-mono text-xs">
                <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/40 text-emerald-300">
                  <div className="text-[11px] text-emerald-400/80 mb-0.5">True Positives (Scam Detected)</div>
                  <div className="text-lg font-bold">{evalResults.confusion_matrix.true_positives}</div>
                </div>
                <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-800/40 text-amber-300">
                  <div className="text-[11px] text-amber-400/80 mb-0.5">False Positives (Benign Flagged)</div>
                  <div className="text-lg font-bold">{evalResults.confusion_matrix.false_positives}</div>
                </div>
                <div className="p-3 rounded-lg bg-red-950/40 border border-red-800/40 text-red-300">
                  <div className="text-[11px] text-red-400/80 mb-0.5">False Negatives (Scam Missed)</div>
                  <div className="text-lg font-bold">{evalResults.confusion_matrix.false_negatives}</div>
                </div>
                <div className="p-3 rounded-lg bg-cyan-950/40 border border-cyan-800/40 text-cyan-300">
                  <div className="text-[11px] text-cyan-400/80 mb-0.5">True Negatives (Benign Passed)</div>
                  <div className="text-lg font-bold">{evalResults.confusion_matrix.true_negatives}</div>
                </div>
              </div>
            </div>

            {/* Observations */}
            <div className="space-y-1.5 text-xs text-slate-400">
              <span className="font-semibold text-slate-300">Evaluation Observations:</span>
              <ul className="list-disc list-inside space-y-1">
                {evalResults.observations.map((obs, idx) => (
                  <li key={idx}>{obs}</li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>

      {/* Security Best Practices Notice */}
      <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/80 flex items-start gap-3 text-xs text-slate-400">
        <Info className="text-cyan-400 shrink-0 mt-0.5" size={16} />
        <div>
          <span className="font-semibold text-slate-300">Operational Security Notice:</span>
          <p className="mt-0.5 leading-relaxed">
            DeepShield employs strict SSRF mitigations, bound-checked frame buffers, input token limits, and dual-layer schema validation.
            Under no circumstances does DeepShield execute LLM tool operations, arbitrary shell scripts, or unchecked network fetches.
          </p>
        </div>
      </div>
    </div>
  );
};
