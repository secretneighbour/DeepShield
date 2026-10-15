import React, { useState } from 'react';
import {
  Link as LinkIcon,
  ShieldCheck,
  ShieldAlert,
  Loader2,
  AlertCircle,
  Sparkles,
  Lock,
  Globe,
  Radio,
  MessageSquare,
} from 'lucide-react';
import type { URLAnalysisResponse } from '../types';
import { analyzeUrl } from '../api';
import { RiskBadge } from './RiskBadge';
import { EvidenceList } from './EvidenceList';
import { FeedbackModal } from './FeedbackModal';

const PRESET_URLS = [
  {
    label: 'Homoglyph Lookalike (pаypal Cyrillic)',
    url: 'http://pаypal-security-login.top/account/verify',
    note: 'Uses Cyrillic "а" (U+0430) disguised as Latin "a"',
  },
  {
    label: 'Credential Harvester (chase-security-verify.net)',
    url: 'https://chase-security-verify.net/signin/index.php',
    note: 'Brand spoofing and active in threat feed',
  },
  {
    label: 'Internal SSRF Attack Attempt (192.168.1.1)',
    url: 'http://192.168.1.1/admin-control-panel',
    note: 'Private RFC-1918 internal destination blocked',
  },
  {
    label: 'Suspicious TLD & High Entropy Token',
    url: 'http://secure-auth-39x81f.xyz/login/session-update',
    note: 'Excessive Shannon entropy and high-abuse TLD',
  },
  {
    label: 'Benign Official Wikipedia Page',
    url: 'https://en.wikipedia.org/wiki/Phishing',
    note: 'Legitimate domain and clean structure',
  },
];

interface UrlAnalyzerViewProps {
  initialUrl?: string;
  onAnalysisComplete?: () => void;
}

export const UrlAnalyzerView: React.FC<UrlAnalyzerViewProps> = ({
  initialUrl = '',
  onAnalysisComplete,
}) => {
  const [url, setUrl] = useState(initialUrl);
  const [checkThreatIntel, setCheckThreatIntel] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<URLAnalysisResponse | null>(null);
  const [feedbackOpen, setFeedbackOpen] = useState(false);

  const handleAnalyze = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!url.trim() || url.length < 4) {
      setError('Please provide a valid URL or hostname to inspect.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await analyzeUrl(url, checkThreatIntel);
      setResult(res);
      if (onAnalysisComplete) onAnalysisComplete();
    } catch (err: any) {
      setError(err.message || 'URL inspection failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <LinkIcon className="text-indigo-400" size={22} />
          <span>URL & Phishing Inspector</span>
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Perform multi-layered lexical heuristics, IDN homoglyph lookalike detection, Shannon entropy calculations,
          SSRF defense, and cross-reference threat intelligence feeds.
        </p>
      </div>

      {/* Preset Buttons */}
      <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
        <div className="flex items-center gap-2 mb-2.5 text-xs text-slate-400 font-medium">
          <Sparkles size={14} className="text-indigo-400" />
          <span>Test Security Scenarios:</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {PRESET_URLS.map((preset, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => {
                setUrl(preset.url);
                setError(null);
              }}
              className="text-xs px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/60 transition"
              title={preset.note}
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleAnalyze} className="space-y-4">
        <div>
          <label className="block text-xs uppercase tracking-wider text-slate-400 font-semibold mb-1.5">
            Target URL or Hostname
          </label>
          <div className="relative">
            <input
              type="text"
              placeholder="e.g. http://chase-security-verify.net/login or http://pаypal.top"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-3.5 text-sm font-mono text-slate-200 placeholder-slate-400 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition"
            />
          </div>
        </div>

        <div className="flex items-center justify-between flex-wrap gap-4">
          <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={checkThreatIntel}
              onChange={(e) => setCheckThreatIntel(e.target.checked)}
              className="rounded bg-slate-900 border-slate-700 text-indigo-500 focus:ring-0"
            />
            <span>Query Threat Intelligence Reputation Feeds (Local + API Feeds)</span>
          </label>

          <div className="flex gap-3">
            <button
              type="button"
              onClick={() => {
                setUrl('');
                setResult(null);
                setError(null);
              }}
              className="px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition"
            >
              Clear
            </button>
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="px-6 py-2.5 rounded-lg bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-400 hover:to-purple-500 text-white text-sm font-semibold flex items-center gap-2 disabled:opacity-50 transition shadow-lg shadow-indigo-950"
            >
              {loading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  <span>Inspecting URL...</span>
                </>
              ) : (
                <>
                  <Globe size={16} />
                  <span>Analyze URL</span>
                </>
              )}
            </button>
          </div>
        </div>

        {error && (
          <div className="p-3.5 rounded-lg bg-red-950/50 border border-red-500/40 text-red-300 text-sm flex items-center gap-2">
            <AlertCircle size={16} className="text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </form>

      {/* Analysis Result */}
      {result && (
        <div className="mt-8 rounded-xl bg-slate-900/90 border border-slate-800 p-6 md:p-7 space-y-6 animate-in fade-in duration-200">
          {/* Verdict Banner */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-3 mb-2 flex-wrap">
                <RiskBadge level={result.risk_level} confidence={result.confidence} size="lg" />
                <span className="text-xs font-mono px-3 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                  Entropy: {result.domain_entropy.toFixed(2)} bits
                </span>
                {result.is_ip_address && (
                  <span className="text-xs font-mono px-3 py-1 rounded-full bg-amber-950 text-amber-300 border border-amber-800">
                    Raw IP Address
                  </span>
                )}
                {result.has_homoglyphs && (
                  <span className="text-xs font-mono px-3 py-1 rounded-full bg-red-950 text-red-300 border border-red-800 animate-pulse">
                    Punycode Homoglyphs Detected
                  </span>
                )}
              </div>
              <div className="text-sm font-mono text-slate-300 break-all bg-slate-950/80 p-2.5 rounded-lg border border-slate-800">
                {result.normalized_url}
              </div>
            </div>

            <button
              onClick={() => setFeedbackOpen(true)}
              className="px-3.5 py-1.5 rounded-lg bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-xs font-mono flex items-center gap-1.5 self-start md:self-center transition cursor-pointer"
              title="Report false positive, false negative, or confirm accuracy"
            >
              <MessageSquare size={14} />
              <span>Feedback</span>
            </button>
          </div>

          {/* Homoglyph Analysis Card if present */}
          {result.has_homoglyphs && (
            <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/50 space-y-2">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-red-300 flex items-center gap-2">
                <ShieldAlert size={16} className="text-red-400" />
                <span>Punycode / Homograph Impersonation Details</span>
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed">
                The domain utilizes Unicode homoglyphs (e.g. Cyrillic or Greek characters that appear visually indistinguishable from Latin letters in standard browser address bars) to impersonate a legitimate brand.
              </p>
              <div className="mt-2 space-y-1">
                {result.homoglyph_details.map((detail, idx) => (
                  <div key={idx} className="text-xs font-mono text-red-300 bg-red-950/60 p-2 rounded border border-red-800/40">
                    {detail}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Threat Intelligence Feed Status */}
          <div className="grid md:grid-cols-3 gap-4">
            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">
                Threat Feed Verdict
              </span>
              <div className="flex items-center gap-2">
                {result.threat_intel_result.is_flagged ? (
                  <>
                    <ShieldAlert size={18} className="text-red-400" />
                    <span className="text-sm font-bold text-red-400 font-mono">
                      {result.threat_intel_result.threat_type || 'FLAGGED MALICIOUS'}
                    </span>
                  </>
                ) : (
                  <>
                    <ShieldCheck size={18} className="text-emerald-400" />
                    <span className="text-sm font-semibold text-emerald-400 font-mono">
                      {result.threat_intel_result.verdict}
                    </span>
                  </>
                )}
              </div>
            </div>

            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">
                Reputation Sources
              </span>
              <div className="text-xs text-slate-300 font-mono flex items-center gap-1.5">
                <Radio size={14} className="text-indigo-400" />
                <span>{result.threat_intel_result.sources_consulted.join(', ')}</span>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">
                Transport Layer
              </span>
              <div className="flex items-center gap-1.5 text-xs text-slate-300 font-mono">
                <Lock size={14} className={result.structure.scheme === 'https' ? 'text-emerald-400' : 'text-amber-400'} />
                <span>{result.structure.scheme.toUpperCase()} (Note: HTTPS does not guarantee legitimacy)</span>
              </div>
            </div>
          </div>

          {/* Evidence List */}
          <EvidenceList
            evidence={result.evidence}
            recommendedActions={result.recommended_actions}
            limitations={result.limitations}
          />

          <FeedbackModal
            isOpen={feedbackOpen}
            onClose={() => setFeedbackOpen(false)}
            analysisId={result.id}
            detectionModule="url"
            predictedVerdict={result.risk_level === 'HIGH_RISK' || result.risk_level === 'MEDIUM_RISK' ? 'SCAM' : 'BENIGN'}
            predictedRiskLevel={result.risk_level}
            targetSummary={result.normalized_url}
          />
        </div>
      )}
    </div>
  );
};
