import React, { useState, useEffect } from 'react';
import {
  FileText,
  Send,
  Loader2,
  CheckCircle,
  Copy,
  Hash,
  AlertCircle,
  Sparkles,
  Cpu,
  HelpCircle,
  MessageSquare,
} from 'lucide-react';
import type { TextAnalysisResponse, LLMStatusResponse, CloudAnalysisSettingsResponse } from '../types';
import {
  analyzeText,
  fetchLLMStatus,
  fetchCloudAnalysisSetting,
  updateCloudAnalysisSetting,
} from '../api';
import { RiskBadge } from './RiskBadge';
import { EvidenceList } from './EvidenceList';
import { FeedbackModal } from './FeedbackModal';

const PRESET_TEXT_SAMPLES = [
  {
    label: 'Chase OTP & Account Suspension',
    category: 'Phishing / OTP Theft',
    channel: 'sms',
    text: 'CHASE FRAUD ALERT: Your debit card ending in 4102 has been suspended due to an unauthorized transaction of $489.12. Text your 6-digit one-time passcode back immediately to restore your account, or call (888) 555-0199.',
  },
  {
    label: 'CEO Urgent Gift Card Request',
    category: 'Executive Impersonation',
    channel: 'email',
    text: 'Hi, are you at your desk right now? I am stuck in an unexpected board meeting and need an urgent confidential favor. Please purchase five $100 Apple gift cards immediately and reply with clear photos of the scratched-off codes.',
  },
  {
    label: 'IRS Final Arrest Warrant Notice',
    category: 'Authority Extortion',
    channel: 'sms',
    text: 'FINAL NOTICE: An arrest warrant has been issued in your name by the Department of Justice for tax evasion. Federal marshals will arrive within 2 hours unless you resolve this legal action. Call immediately at 800-555-8921.',
  },
  {
    label: 'Crypto Multiplier Giveaway',
    category: 'Financial Ponzi',
    channel: 'social',
    text: 'Official Elon Musk Tesla Giveaway: Send between 0.1 BTC to 5.0 BTC to our verified promotional wallet and receive 2x back instantly. Guaranteed profit compounded daily. Over 800 BTC already distributed!',
  },
  {
    label: 'Legitimate Flight Confirmation',
    category: 'Benign Transaction',
    channel: 'email',
    text: 'Your Delta Airlines e-ticket confirmation #DT9281. Flight DL142 from JFK to SFO is confirmed for departure at 08:30 AM on Thursday, Oct 24. Check-in opens 24 hours prior.',
  },
];

interface TextAnalyzerViewProps {
  initialText?: string;
  onAnalysisComplete?: () => void;
}

export const TextAnalyzerView: React.FC<TextAnalyzerViewProps> = ({
  initialText = '',
  onAnalysisComplete,
}) => {
  const [text, setText] = useState(initialText);
  const [channel, setChannel] = useState('auto');
  const [senderContext, setSenderContext] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<TextAnalysisResponse | null>(null);
  const [copied, setCopied] = useState(false);
  const [feedbackOpen, setFeedbackOpen] = useState(false);

  // Cloud Analysis Setting State
  const [cloudEnabled, setCloudEnabled] = useState(true);
  const [llmStatus, setLlmStatus] = useState<LLMStatusResponse | null>(null);

  useEffect(() => {
    fetchCloudAnalysisSetting()
      .then((s: CloudAnalysisSettingsResponse) => setCloudEnabled(s.user_enabled))
      .catch(() => {});
    fetchLLMStatus()
      .then((st: LLMStatusResponse) => setLlmStatus(st))
      .catch(() => {});
  }, []);

  const handleToggleCloudAnalysis = async (checked: boolean) => {
    setCloudEnabled(checked);
    try {
      const updated = await updateCloudAnalysisSetting(checked);
      setCloudEnabled(updated.user_enabled);
    } catch (err: any) {
      alert(`Could not update cloud setting: ${err.message}`);
    }
  };

  const handleAnalyze = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!text.trim() || text.length < 5) {
      setError('Please provide at least 5 characters of message text to analyze.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await analyzeText(text, senderContext, channel);
      setResult(res);
      if (onAnalysisComplete) onAnalysisComplete();
    } catch (err: any) {
      setError(err.message || 'Analysis failed. Please check backend status.');
    } finally {
      setLoading(false);
    }
  };

  const handleApplyPreset = (preset: typeof PRESET_TEXT_SAMPLES[0]) => {
    setText(preset.text);
    setChannel(preset.channel);
    setError(null);
  };

  const handleCopySummary = () => {
    if (!result) return;
    const summaryText = `[DeepShield Analysis] Risk: ${result.risk_level} | Status: ${result.overall_status || 'Completed'} | Category: ${result.scam_category}\nSummary: ${result.summary || result.primary_reason}\nConfidence: ${Math.round(result.confidence * 100)}%`;
    navigator.clipboard.writeText(summaryText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <FileText className="text-cyan-400" size={22} />
          <span>Two-Stage Scam Intelligence & Text Forensics</span>
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Inspect SMS texts, emails, chat messages, or call transcripts. DeepShield enforces an asymmetric
          Two-Stage verification pipeline: Stage 1 on-device local model, followed by Stage 2 Google Gemini cross-examination.
        </p>
      </div>

      {/* Two-Stage Cloud Privacy Setting Banner (Mandated Section 7) */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-2.5">
            <Cpu size={16} className="text-cyan-400" />
            <span className="text-xs font-semibold text-slate-200">
              Two-Stage LLM Cloud Analysis Gate
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
              Stage 1: {llmStatus?.ollama?.target_model || 'gemma3:4b'} • Stage 2: {llmStatus?.gemini?.configured_model || 'gemini-2.5-flash'}
            </span>
          </div>

          <label className="flex items-center gap-2 cursor-pointer text-xs font-medium text-slate-300">
            <input
              type="checkbox"
              checked={cloudEnabled}
              onChange={(e) => handleToggleCloudAnalysis(e.target.checked)}
              className="rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-0"
            />
            <span>Enable Gemini cloud analysis</span>
          </label>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          &quot;When enabled, your submitted text and the local model&apos;s findings are sent to Google&apos;s Gemini service for additional analysis. Avoid submitting passwords, OTPs, private credentials, or other sensitive information.&quot;
        </p>
      </div>

      {/* Preset Buttons */}
      <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
        <div className="flex items-center gap-2 mb-2.5 text-xs text-slate-400 font-medium">
          <Sparkles size={14} className="text-amber-400" />
          <span>Quick Evaluation Presets:</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {PRESET_TEXT_SAMPLES.map((preset, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleApplyPreset(preset)}
              className="text-xs px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/60 transition cursor-pointer"
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleAnalyze} className="space-y-4">
        <div className="grid md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs uppercase tracking-wider text-slate-400 font-semibold mb-1.5">
              Communication Channel
            </label>
            <select
              value={channel}
              onChange={(e) => setChannel(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3.5 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="auto">Auto Detect Channel</option>
              <option value="sms">SMS / Text Message</option>
              <option value="email">Email Body</option>
              <option value="social">Social Media DM / Comment</option>
              <option value="chat">Messaging App (WhatsApp / Telegram)</option>
              <option value="voice_transcript">Spoken Phone Call Transcript</option>
            </select>
          </div>
          <div>
            <label className="block text-xs uppercase tracking-wider text-slate-400 font-semibold mb-1.5">
              Sender Context (Optional)
            </label>
            <input
              type="text"
              placeholder="e.g. +1 (800) 555-0199 or alerts@chase-verify.com"
              value={senderContext}
              onChange={(e) => setSenderContext(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3.5 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 placeholder-slate-400"
            />
          </div>
        </div>

        <div>
          <label className="block text-xs uppercase tracking-wider text-slate-400 font-semibold mb-1.5">
            Message Text or Conversation Script
          </label>
          <textarea
            rows={5}
            placeholder="Paste complete message content here (passwords, OTPs, wire claims, or suspicious links)..."
            value={text}
            onChange={(e) => setText(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-xl p-4 text-sm text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition leading-relaxed font-sans"
          />
          <div className="flex justify-between items-center text-xs text-slate-400 mt-1">
            <span>Character count: {text.length} / 10,000</span>
            <span>Zero-retention compliant</span>
          </div>
        </div>

        {error && (
          <div className="p-3.5 rounded-lg bg-red-950/50 border border-red-500/40 text-red-300 text-sm flex items-center gap-2">
            <AlertCircle size={16} className="text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="flex justify-end gap-3">
          <button
            type="button"
            onClick={() => {
              setText('');
              setResult(null);
              setError(null);
            }}
            className="px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition cursor-pointer"
          >
            Clear
          </button>
          <button
            type="submit"
            disabled={loading || !text.trim()}
            className="px-6 py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white text-sm font-semibold flex items-center gap-2 disabled:opacity-50 transition shadow-lg shadow-cyan-950 cursor-pointer"
          >
            {loading ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                <span>Running Two-Stage Pipeline...</span>
              </>
            ) : (
              <>
                <Send size={16} />
                <span>Analyze Message</span>
              </>
            )}
          </button>
        </div>
      </form>

      {/* Analysis Result Display */}
      {result && (
        <div className="mt-8 rounded-xl bg-slate-900/90 border border-slate-800 p-6 md:p-7 space-y-6 animate-in fade-in duration-200">
          {/* Verdict Banner */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-3 mb-2 flex-wrap">
                <RiskBadge level={result.risk_level} confidence={result.confidence} size="lg" />
                
                {/* Standardized Overall Status Pill */}
                <span className="text-xs font-mono uppercase tracking-wider px-3 py-1 rounded-full bg-slate-800 text-slate-200 border border-slate-700">
                  Status: {result.overall_status || 'Completed'}
                </span>

                <span className="text-xs uppercase tracking-wider font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-3 py-1 rounded-full">
                  {result.scam_category}
                </span>
              </div>
              <h3 className="text-base font-semibold text-slate-100">
                {result.summary || result.primary_reason}
              </h3>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <button
                onClick={() => setFeedbackOpen(true)}
                className="px-3.5 py-1.5 rounded-lg bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-xs font-mono flex items-center gap-1.5 self-start md:self-center transition cursor-pointer"
                title="Report false positive, false negative, or confirm accuracy"
              >
                <MessageSquare size={14} />
                <span>Feedback</span>
              </button>

              <button
                onClick={handleCopySummary}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center gap-2 self-start md:self-center transition cursor-pointer"
              >
                {copied ? <CheckCircle size={14} className="text-emerald-400" /> : <Copy size={14} />}
                <span>{copied ? 'Summary Copied' : 'Copy Verdict'}</span>
              </button>
            </div>
          </div>

          {/* Two-Stage Protocol Execution Telemetry Status Bar */}
          <div className="grid sm:grid-cols-2 gap-3 p-4 rounded-xl bg-slate-950 border border-slate-800/80 font-mono text-xs">
            <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-slate-400">Stage 1 (Local Model):</span>
              <span className="text-cyan-400 font-semibold">{result.local_stage_status || 'completed'}</span>
            </div>
            <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-slate-400">Stage 2 (Gemini Review):</span>
              <span className={result.gemini_stage_status === 'completed' ? 'text-emerald-400 font-semibold' : 'text-amber-400 font-semibold'}>
                {result.gemini_stage_status || 'not_run_cloud_disabled'}
              </span>
            </div>
          </div>

          {/* Plausible Alternative Explanations & Uncertainties (Mandated Section 8) */}
          {result.alternative_explanations && result.alternative_explanations.length > 0 && (
            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
              <h4 className="text-xs uppercase tracking-wider text-slate-300 font-semibold mb-2 flex items-center gap-1.5">
                <HelpCircle size={14} className="text-amber-400" />
                <span>Plausible Legitimate Interpretations & Context</span>
              </h4>
              <ul className="space-y-1 text-xs text-slate-400">
                {result.alternative_explanations.map((alt, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="text-slate-400">•</span>
                    <span>{alt}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Highlighted Tokens / Phrasing */}
          {result.highlighted_tokens.length > 0 && (
            <div>
              <h4 className="text-xs uppercase tracking-wider text-slate-400 font-semibold mb-2 flex items-center gap-1.5">
                <Hash size={14} className="text-cyan-400" />
                Deceptive Keywords & Trigger Spans
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {result.highlighted_tokens.map((token, idx) => (
                  <span
                    key={idx}
                    className="text-xs font-mono bg-red-950/60 text-red-300 border border-red-800/60 px-2.5 py-1 rounded-md"
                  >
                    {token}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Detected Entities */}
          {result.detected_entities.length > 0 && (
            <div>
              <h4 className="text-xs uppercase tracking-wider text-slate-400 font-semibold mb-2">
                Extracted Contact & Destination Entities
              </h4>
              <div className="flex flex-wrap gap-2">
                {result.detected_entities.map((ent, idx) => (
                  <span
                    key={idx}
                    className="text-xs font-mono bg-slate-800/90 text-cyan-300 border border-slate-700 px-3 py-1 rounded-md"
                  >
                    {ent}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Detailed Evidence & Safeguards */}
          <EvidenceList
            evidence={result.evidence}
            recommendedActions={result.recommended_actions}
            limitations={result.limitations}
            modelAttribution={result.model_attribution}
          />

          <FeedbackModal
            isOpen={feedbackOpen}
            onClose={() => setFeedbackOpen(false)}
            analysisId={result.id || result.analysis_id}
            detectionModule="text"
            predictedVerdict={result.risk_level === 'HIGH_RISK' || result.risk_level === 'MEDIUM_RISK' ? 'SCAM' : 'BENIGN'}
            predictedRiskLevel={result.risk_level}
            targetSummary={text.slice(0, 150)}
          />
        </div>
      )}
    </div>
  );
};
