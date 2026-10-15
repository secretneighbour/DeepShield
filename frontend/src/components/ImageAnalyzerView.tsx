import React, { useState, useRef } from 'react';
import {
  Image as ImageIcon,
  Upload,
  Loader2,
  AlertCircle,
  Eye,
  Camera,
  Activity,
  Layers,
  MessageSquare,
} from 'lucide-react';
import type { ImageAnalysisResponse } from '../types';
import { analyzeImage } from '../api';
import { RiskBadge } from './RiskBadge';
import { EvidenceList } from './EvidenceList';
import { FeedbackModal } from './FeedbackModal';

export const ImageAnalyzerView: React.FC<{ onAnalysisComplete?: () => void }> = ({
  onAnalysisComplete,
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ImageAnalysisResponse | null>(null);
  const [activeImageTab, setActiveImageTab] = useState<'original' | 'ela'>('original');
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (selectedFile: File) => {
    if (!selectedFile) return;
    if (selectedFile.size > 30 * 1024 * 1024) {
      setError('Selected image exceeds maximum 30MB limit.');
      return;
    }
    setFile(selectedFile);
    setError(null);
    setResult(null);

    const url = URL.createObjectURL(selectedFile);
    setPreviewUrl(url);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const handleAnalyze = async () => {
    if (!file) {
      setError('Please select an image file to analyze.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await analyzeImage(file);
      setResult(res);
      if (res.annotated_heatmap_base64) {
        setActiveImageTab('ela');
      }
      if (onAnalysisComplete) onAnalysisComplete();
    } catch (err: any) {
      setError(err.message || 'Image forensic analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <ImageIcon className="text-purple-400" size={22} />
          <span>Image Deepfake & Forensic Splicing Analyzer</span>
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Detect synthetic AI-generated content (GAN / Latent Diffusion grids), composite splicing, and localized
          modifications using Error Level Analysis (ELA), 2D Fast Fourier Transforms, and EXIF tampering analysis.
        </p>
      </div>

      {/* Upload Dropzone */}
      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className="border-2 border-dashed border-slate-800 hover:border-purple-500/60 rounded-2xl p-8 text-center cursor-pointer transition bg-slate-900/40 hover:bg-slate-900/80 group"
      >
        <input
          ref={fileInputRef}
          type="file"
          accept="image/jpeg,image/png,image/webp"
          className="hidden"
          onChange={(e) => e.target.files && handleFileSelect(e.target.files[0])}
        />
        <div className="p-4 rounded-full bg-purple-950/60 border border-purple-800/40 text-purple-400 w-fit mx-auto mb-3 group-hover:scale-110 transition">
          <Upload size={24} />
        </div>
        <p className="text-sm font-semibold text-slate-200">
          {file ? file.name : 'Drag and drop image or click to browse'}
        </p>
        <p className="text-xs text-slate-400 mt-1">
          Supports JPEG, PNG, WEBP • Max 30MB • Strict magic-byte validation
        </p>
      </div>

      {/* Preview & Action Bar */}
      {previewUrl && (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center gap-3">
            <img src={previewUrl} alt="Preview" className="w-14 h-14 object-cover rounded-lg border border-slate-700" />
            <div>
              <div className="text-sm font-medium text-slate-200">{file?.name}</div>
              <div className="text-xs text-slate-400 font-mono">
                {(file?.size ? file.size / (1024 * 1024) : 0).toFixed(2)} MB
              </div>
            </div>
          </div>

          <div className="flex gap-3">
            <button
              onClick={() => {
                setFile(null);
                setPreviewUrl(null);
                setResult(null);
              }}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition"
            >
              Remove
            </button>
            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="px-6 py-2 rounded-lg bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-400 hover:to-indigo-500 text-white text-xs font-semibold flex items-center gap-2 disabled:opacity-50 transition shadow-lg shadow-purple-950"
            >
              {loading ? (
                <>
                  <Loader2 size={14} className="animate-spin" />
                  <span>Computing Forensics...</span>
                </>
              ) : (
                <>
                  <Activity size={14} />
                  <span>Run Forensic Analysis</span>
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

      {/* Forensic Results Display */}
      {result && (
        <div className="mt-8 rounded-xl bg-slate-900/90 border border-slate-800 p-6 md:p-7 space-y-6 animate-in fade-in duration-200">
          {/* Verdict Banner */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-3 mb-2 flex-wrap">
                <RiskBadge level={result.risk_level} confidence={result.confidence} size="lg" />
                <span className="text-xs font-mono px-3 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                  {result.dimensions[0]} × {result.dimensions[1]} px
                </span>
                <span className="text-xs font-mono px-3 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                  Format: {result.format}
                </span>
              </div>
              <h3 className="text-sm font-semibold text-slate-200">
                Error Level Analysis (ELA): {(result.ela_score * 100).toFixed(1)}% • FFT Spectral Anomaly: {(result.fft_frequency_anomaly * 100).toFixed(1)}%
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

          {/* Visual Forensics & ELA Heatmap Viewer */}
          <div className="grid md:grid-cols-2 gap-6 items-start">
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Eye size={14} className="text-purple-400" />
                  <span>Forensic Visual Comparison</span>
                </h4>
                <div className="flex rounded-lg bg-slate-900 p-0.5 border border-slate-800 text-xs">
                  <button
                    onClick={() => setActiveImageTab('original')}
                    className={`px-3 py-1 rounded-md transition ${
                      activeImageTab === 'original'
                        ? 'bg-purple-600 text-white font-medium'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Original
                  </button>
                  <button
                    onClick={() => setActiveImageTab('ela')}
                    className={`px-3 py-1 rounded-md transition ${
                      activeImageTab === 'ela'
                        ? 'bg-purple-600 text-white font-medium'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    ELA Heatmap
                  </button>
                </div>
              </div>

              <div className="aspect-video w-full flex items-center justify-center bg-slate-900/60 rounded-lg overflow-hidden border border-slate-800">
                {activeImageTab === 'original' && previewUrl && (
                  <img src={previewUrl} alt="Original" className="max-h-full max-w-full object-contain" />
                )}
                {activeImageTab === 'ela' && result.annotated_heatmap_base64 && (
                  <img
                    src={result.annotated_heatmap_base64}
                    alt="Error Level Analysis Heatmap"
                    className="max-h-full max-w-full object-contain"
                  />
                )}
              </div>
              <p className="text-[11px] text-slate-400 mt-2 text-center">
                {activeImageTab === 'ela'
                  ? 'Bright patches indicate differing JPEG compression rates, characteristic of splicing or localized AI in-painting.'
                  : 'Source image under forensic inspection.'}
              </p>
            </div>

            {/* Metrics Breakdown Cards */}
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
                <h4 className="text-xs uppercase tracking-wider text-slate-400 font-semibold mb-3 flex items-center gap-1.5">
                  <Layers size={14} className="text-cyan-400" />
                  Mathematical Forensic Indicators
                </h4>
                <div className="space-y-3">
                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-300">2D FFT High-Frequency Anomaly</span>
                      <span className="font-mono text-cyan-400">{result.fft_frequency_anomaly.toFixed(3)}</span>
                    </div>
                    <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className="h-full bg-cyan-500 rounded-full"
                        style={{ width: `${Math.min(100, result.fft_frequency_anomaly * 100)}%` }}
                      />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-300">Spatial Noise Inconsistency</span>
                      <span className="font-mono text-purple-400">{result.noise_inconsistency.toFixed(3)}</span>
                    </div>
                    <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className="h-full bg-purple-500 rounded-full"
                        style={{ width: `${Math.min(100, result.noise_inconsistency * 100)}%` }}
                      />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-300">Error Level Analysis (ELA) Gradient</span>
                      <span className="font-mono text-pink-400">{result.ela_score.toFixed(3)}</span>
                    </div>
                    <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className="h-full bg-pink-500 rounded-full"
                        style={{ width: `${Math.min(100, result.ela_score * 100)}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* EXIF Metadata Card */}
              <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
                <h4 className="text-xs uppercase tracking-wider text-slate-400 font-semibold mb-2 flex items-center gap-1.5">
                  <Camera size={14} className="text-amber-400" />
                  EXIF & Generation Header Signatures
                </h4>
                {result.exif_tampering_clues.length > 0 ? (
                  <div className="space-y-1 mb-2">
                    {result.exif_tampering_clues.map((clue, idx) => (
                      <div key={idx} className="text-xs text-amber-300 bg-amber-950/40 p-2 rounded border border-amber-800/40">
                        {clue}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-slate-400 italic mb-2">
                    {Object.keys(result.metadata_summary).length > 0
                      ? 'Camera hardware headers present without known AI generator strings.'
                      : 'No EXIF metadata found (typical for web downloads or social media uploads).'}
                  </div>
                )}

                {Object.keys(result.metadata_summary).length > 0 && (
                  <div className="text-[11px] font-mono text-slate-400 bg-slate-900 p-2 rounded max-h-24 overflow-y-auto">
                    {Object.entries(result.metadata_summary).map(([k, v]) => (
                      <div key={k}>{k}: {String(v)}</div>
                    ))}
                  </div>
                )}
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
            analysisId={result.id || result.analysis_id}
            detectionModule="image"
            predictedVerdict={result.risk_level === 'HIGH_RISK' || result.risk_level === 'MEDIUM_RISK' ? 'SCAM' : 'BENIGN'}
            predictedRiskLevel={result.risk_level}
            targetSummary={`Image: ${result.filename} (${result.dimensions[0]}x${result.dimensions[1]})`}
          />
        </div>
      )}
    </div>
  );
};
