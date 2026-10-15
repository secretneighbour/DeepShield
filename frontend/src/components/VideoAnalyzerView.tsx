import React, { useState, useRef } from 'react';
import {
  Video as VideoIcon,
  Upload,
  Loader2,
  AlertCircle,
  Activity,
  Film,
  Clock,
  MessageSquare,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ReferenceLine,
} from 'recharts';
import type { VideoAnalysisResponse } from '../types';
import { analyzeVideo } from '../api';
import { RiskBadge } from './RiskBadge';
import { EvidenceList } from './EvidenceList';
import { FeedbackModal } from './FeedbackModal';

export const VideoAnalyzerView: React.FC<{ onAnalysisComplete?: () => void }> = ({
  onAnalysisComplete,
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<VideoAnalysisResponse | null>(null);
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (selectedFile: File) => {
    if (!selectedFile) return;
    if (selectedFile.size > 50 * 1024 * 1024) {
      setError('Video file exceeds maximum 50MB limit.');
      return;
    }
    setFile(selectedFile);
    setError(null);
    setResult(null);
  };

  const handleAnalyze = async () => {
    if (!file) {
      setError('Please select a video file (.mp4, .webm) to inspect.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await analyzeVideo(file);
      setResult(res);
      if (onAnalysisComplete) onAnalysisComplete();
    } catch (err: any) {
      setError(err.message || 'Video analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <VideoIcon className="text-pink-400" size={22} />
          <span>Video Deepfake & Temporal Consistency Analyzer</span>
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Detect face swaps, synthetic facial flickering, boundary warping, and temporal discontinuities through
          controlled frame sampling and inter-frame difference telemetry.
        </p>
      </div>

      {/* Upload Dropzone */}
      <div
        onClick={() => fileInputRef.current?.click()}
        className="border-2 border-dashed border-slate-800 hover:border-pink-500/60 rounded-2xl p-8 text-center cursor-pointer transition bg-slate-900/40 hover:bg-slate-900/80 group"
      >
        <input
          ref={fileInputRef}
          type="file"
          accept="video/mp4,video/webm,video/quicktime"
          className="hidden"
          onChange={(e) => e.target.files && handleFileSelect(e.target.files[0])}
        />
        <div className="p-4 rounded-full bg-pink-950/60 border border-pink-800/40 text-pink-400 w-fit mx-auto mb-3 group-hover:scale-110 transition">
          <Upload size={24} />
        </div>
        <p className="text-sm font-semibold text-slate-200">
          {file ? file.name : 'Drag and drop video clip or click to select'}
        </p>
        <p className="text-xs text-slate-400 mt-1">
          Supports MP4, WebM • Max 60s duration • Max 50MB
        </p>
      </div>

      {/* Selected File Bar */}
      {file && (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-lg bg-pink-950/40 border border-pink-800/40 text-pink-400">
              <Film size={20} />
            </div>
            <div>
              <div className="text-sm font-medium text-slate-200">{file.name}</div>
              <div className="text-xs text-slate-400 font-mono">
                {(file.size / (1024 * 1024)).toFixed(2)} MB • {file.type || 'video/mp4'}
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
              className="px-6 py-2 rounded-lg bg-gradient-to-r from-pink-500 to-indigo-600 hover:from-pink-400 hover:to-indigo-500 text-white text-xs font-semibold flex items-center gap-2 disabled:opacity-50 transition shadow-lg shadow-pink-950"
            >
              {loading ? (
                <>
                  <Loader2 size={14} className="animate-spin" />
                  <span>Sampling Video Frames...</span>
                </>
              ) : (
                <>
                  <Activity size={14} />
                  <span>Execute Temporal Inspection</span>
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
                  {result.duration_seconds}s Duration
                </span>
                <span className="text-xs font-mono px-3 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                  {result.total_frames_sampled} Sampled Frames
                </span>
              </div>
              <h3 className="text-sm font-semibold text-slate-200">
                Temporal Inconsistency Index: {(result.temporal_inconsistency_score * 100).toFixed(1)}%
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

          {/* Frame-by-Frame Anomaly Timeline Chart */}
          {result.frame_timeline.length > 0 && (
            <div className="p-5 rounded-xl bg-slate-950 border border-slate-800">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Frame-by-Frame Synthetic Anomaly Timeline
                </h4>
                <div className="flex items-center gap-3 text-xs">
                  <span className="flex items-center gap-1.5 text-pink-400">
                    <span className="w-2.5 h-2.5 rounded-full bg-pink-500" />
                    Anomaly Metric
                  </span>
                  <span className="text-slate-400">Threshold: 0.65</span>
                </div>
              </div>

              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={result.frame_timeline}
                    margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                  >
                    <defs>
                      <linearGradient id="anomalyGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ec4899" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="#ec4899" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis
                      dataKey="timestamp_sec"
                      tickFormatter={(v) => `${v}s`}
                      stroke="#64748b"
                      fontSize={11}
                    />
                    <YAxis
                      domain={[0, 1]}
                      stroke="#64748b"
                      fontSize={11}
                      tickFormatter={(v) => `${(v * 100).toFixed(0)}%`}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        borderColor: '#334155',
                        borderRadius: '8px',
                        fontSize: '12px',
                      }}
                      labelFormatter={(v) => `Timestamp: ${v}s`}
                      formatter={(v: any) => [`${(Number(v) * 100).toFixed(1)}%`, 'Anomaly Score']}
                    />
                    <ReferenceLine y={0.65} stroke="#ef4444" strokeDasharray="3 3" />
                    <Area
                      type="monotone"
                      dataKey="anomaly_score"
                      stroke="#ec4899"
                      strokeWidth={2}
                      fillOpacity={1}
                      fill="url(#anomalyGradient)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* Sampled Frames Table */}
          <div className="overflow-x-auto">
            <h4 className="text-xs uppercase tracking-wider text-slate-400 font-semibold mb-2">
              Sampled Frame Audit Log ({result.frame_timeline.length} checkpoints)
            </h4>
            <table className="w-full text-xs font-mono text-left border border-slate-800 rounded-lg overflow-hidden">
              <thead className="bg-slate-950 text-slate-400">
                <tr>
                  <th className="py-2.5 px-3">Frame Index</th>
                  <th className="py-2.5 px-3">Time</th>
                  <th className="py-2.5 px-3">Score</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Forensic Notes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 bg-slate-900/60">
                {result.frame_timeline.map((frame, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40">
                    <td className="py-2 px-3 text-slate-300">#{frame.frame_index}</td>
                    <td className="py-2 px-3 text-slate-300">{frame.timestamp_sec}s</td>
                    <td className="py-2 px-3">
                      <span className={frame.anomaly_score > 0.65 ? 'text-red-400 font-bold' : 'text-slate-300'}>
                        {(frame.anomaly_score * 100).toFixed(1)}%
                      </span>
                    </td>
                    <td className="py-2 px-3">
                      {frame.is_anomaly ? (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800">
                          ANOMALY
                        </span>
                      ) : (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                          CLEAN
                        </span>
                      )}
                    </td>
                    <td className="py-2 px-3 text-slate-400">{frame.notes || 'Normal pixel metrics'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
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
            detectionModule="video"
            predictedVerdict={result.risk_level === 'HIGH_RISK' || result.risk_level === 'MEDIUM_RISK' ? 'SCAM' : 'BENIGN'}
            predictedRiskLevel={result.risk_level}
            targetSummary={`Video: ${result.filename} (${result.duration_seconds}s)`}
          />
        </div>
      )}
    </div>
  );
};
