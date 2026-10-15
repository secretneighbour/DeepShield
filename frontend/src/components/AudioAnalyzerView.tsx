import React, { useState, useRef } from 'react';
import {
  Mic as MicIcon,
  Upload,
  Loader2,
  AlertCircle,
  Activity,
  Volume2,
  FileText,
  Clock,
  MessageSquare,
} from 'lucide-react';
import type { AudioAnalysisResponse } from '../types';
import { analyzeAudio } from '../api';
import { RiskBadge } from './RiskBadge';
import { EvidenceList } from './EvidenceList';
import { FeedbackModal } from './FeedbackModal';

export const AudioAnalyzerView: React.FC<{ onAnalysisComplete?: () => void }> = ({
  onAnalysisComplete,
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [transcript, setTranscript] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AudioAnalysisResponse | null>(null);
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (selectedFile: File) => {
    if (!selectedFile) return;
    if (selectedFile.size > 30 * 1024 * 1024) {
      setError('Audio file exceeds maximum 30MB limit.');
      return;
    }
    setFile(selectedFile);
    setError(null);
    setResult(null);
  };

  const handleAnalyze = async () => {
    if (!file) {
      setError('Please select an audio recording to inspect.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await analyzeAudio(file, transcript);
      setResult(res);
      if (onAnalysisComplete) onAnalysisComplete();
    } catch (err: any) {
      setError(err.message || 'Audio authenticity inspection failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <MicIcon className="text-amber-400" size={22} />
          <span>Audio Authenticity & Voice Cloning Analyzer</span>
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Perform acoustic signal forensics (vocal micro-jitter, vocoder frequency truncation, digital silence detection)
          alongside dual-verdict spoken semantic scam intent analysis.
        </p>
      </div>

      {/* Upload Dropzone */}
      <div
        onClick={() => fileInputRef.current?.click()}
        className="border-2 border-dashed border-slate-800 hover:border-amber-500/60 rounded-2xl p-8 text-center cursor-pointer transition bg-slate-900/40 hover:bg-slate-900/80 group"
      >
        <input
          ref={fileInputRef}
          type="file"
          accept="audio/wav,audio/mpeg,audio/mp3,audio/m4a,audio/ogg"
          className="hidden"
          onChange={(e) => e.target.files && handleFileSelect(e.target.files[0])}
        />
        <div className="p-4 rounded-full bg-amber-950/60 border border-amber-800/40 text-amber-400 w-fit mx-auto mb-3 group-hover:scale-110 transition">
          <Upload size={24} />
        </div>
        <p className="text-sm font-semibold text-slate-200">
          {file ? file.name : 'Drag and drop audio file or click to browse'}
        </p>
        <p className="text-xs text-slate-400 mt-1">
          Supports WAV, MP3, M4A • Max 120s duration • Max 30MB
        </p>
      </div>

      {/* Optional Transcript Input for Dual-Verdict Analysis */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
        <label className="block text-xs uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-1.5">
          <FileText size={14} className="text-amber-400" />
          <span>Optional Spoken Transcript (For Semantic Intent Scanning)</span>
        </label>
        <textarea
          rows={3}
          placeholder="Paste or type what was said in the audio (e.g., 'Dad, I was in an accident, wire $2000 immediately to this lawyer')..."
          value={transcript}
          onChange={(e) => setTranscript(e.target.value)}
          className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-amber-500 font-sans"
        />
        <p className="text-[11px] text-slate-400 italic">
          DeepShield independently evaluates whether the acoustic signal is synthetic and whether the spoken message contains criminal scam indicators.
        </p>
      </div>

      {/* Selected File Bar */}
      {file && (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-800/40 text-amber-400">
              <Volume2 size={20} />
            </div>
            <div>
              <div className="text-sm font-medium text-slate-200">{file.name}</div>
              <div className="text-xs text-slate-400 font-mono">
                {(file.size / (1024 * 1024)).toFixed(2)} MB • {file.type || 'audio/wav'}
              </div>
            </div>
          </div>

          <div className="flex gap-3">
            <button
              onClick={() => {
                setFile(null);
                setResult(null);
              }}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition"
            >
              Remove
            </button>
            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="px-6 py-2 rounded-lg bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 text-white text-xs font-semibold flex items-center gap-2 disabled:opacity-50 transition shadow-lg shadow-amber-950"
            >
              {loading ? (
                <>
                  <Loader2 size={14} className="animate-spin" />
                  <span>Analyzing Acoustic Spectrum...</span>
                </>
              ) : (
                <>
                  <Activity size={14} />
                  <span>Execute Acoustic Analysis</span>
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {error && (
        <div className="p-3.5 rounded-lg bg-red-950/50 border border-red-500/40 text-red-300 text-sm flex items-center gap-2">
          <AlertCircle size={16} className="text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Results Display */}
      {result && (
        <div className="mt-8 rounded-xl bg-slate-900/90 border border-slate-800 p-6 md:p-7 space-y-6 animate-in fade-in duration-200">
          {/* Verdict Banner */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-3 mb-2 flex-wrap">
                <RiskBadge level={result.risk_level} confidence={result.confidence} size="lg" />
                <span className="text-xs font-mono px-3 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-700 flex items-center gap-1.5">
                  <Clock size={12} />
                  {result.duration_seconds}s
                </span>
                <span className="text-xs font-mono px-3 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                  {result.sample_rate} Hz
                </span>
              </div>
              <h3 className="text-sm font-semibold text-slate-200">
                Voice Clone Classification: <span className="font-mono text-amber-300">{result.voice_clone_likelihood}</span>
              </h3>
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

          {/* Dual Verdict Explanatory Callout */}
          <div className="grid md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">
                Verdict A: Acoustic Voice Cloning
              </span>
              <div className="text-sm font-semibold text-slate-200 mb-1">
                {result.voice_clone_likelihood === 'HIGH_LIKELIHOOD'
                  ? 'Acoustic Signal Exhibits Synthetic Vocoder Characteristics'
                  : result.voice_clone_likelihood === 'SUSPICIOUS_INDICATORS'
                  ? 'Elevated Pitch Rigidity or Spectral Cutoff Observed'
                  : 'Natural Micro-Tremor & Acoustic Ambience Consistent with Human Speech'}
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Evaluated from mathematical pitch period stability and high-frequency energy distribution.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">
                Verdict B: Spoken Message Scam Intent
              </span>
              <div className="text-sm font-semibold text-slate-200 mb-1">
                {transcript
                  ? 'Transcript Intent Evaluated by DeepShield NLP Engine'
                  : 'No Spoken Transcript Provided for Intent Analysis'}
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                A suspicious request does not prove cloned audio, and cloned audio does not inherently prove fraud.
              </p>
            </div>
          </div>

          {/* Acoustic Forensic Gauges */}
          <div className="grid md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">
                Pitch Jitter (Perturbation)
              </span>
              <div className="text-lg font-bold font-mono text-amber-300 mb-1">
                {(result.pitch_jitter * 100).toFixed(2)}%
              </div>
              <p className="text-[11px] text-slate-400">
                Natural human vocal jitter is 0.5% - 2.0%. Values &lt;0.3% indicate robotic TTS; &gt;3.5% indicate synthesis phase errors.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">
                Spectral Rolloff Anomaly
              </span>
              <div className="text-lg font-bold font-mono text-cyan-300 mb-1">
                {result.spectral_rolloff_anomaly.toFixed(3)}
              </div>
              <p className="text-[11px] text-slate-400">
                Measures abrupt cutoff above 7.5kHz typical of 16kHz neural vocoders (e.g. HiFi-GAN, Tacotron).
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block mb-1">
                Silence Ratio
              </span>
              <div className="text-lg font-bold font-mono text-purple-300 mb-1">
                {(result.silence_ratio * 100).toFixed(1)}%
              </div>
              <p className="text-[11px] text-slate-400">
                Evaluates mathematical zero amplitude runs vs natural microphone background room floor.
              </p>
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
            analysisId={result.id || result.analysis_id}
            detectionModule="audio"
            predictedVerdict={result.risk_level === 'HIGH_RISK' || result.risk_level === 'MEDIUM_RISK' ? 'SCAM' : 'BENIGN'}
            predictedRiskLevel={result.risk_level}
            targetSummary={`Audio: ${result.filename} (${result.duration_seconds}s)`}
          />
        </div>
      )}
    </div>
  );
};
