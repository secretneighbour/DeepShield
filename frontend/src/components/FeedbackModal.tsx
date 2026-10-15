import React, { useState } from 'react';
import type { RiskLevel, FeedbackCreateRequest } from '../types';
import { submitFeedback } from '../api';

interface FeedbackModalProps {
  isOpen: boolean;
  onClose: () => void;
  analysisId?: string;
  detectionModule: 'text' | 'url' | 'image' | 'video' | 'audio';
  predictedVerdict?: string;
  predictedRiskLevel?: RiskLevel;
  targetSummary?: string;
}

export const FeedbackModal: React.FC<FeedbackModalProps> = ({
  isOpen,
  onClose,
  analysisId,
  detectionModule,
  predictedVerdict,
  predictedRiskLevel,
  targetSummary,
}) => {
  const [correction, setCorrection] = useState<FeedbackCreateRequest['user_correction']>('false_positive');
  const [correctedRisk, setCorrectedRisk] = useState<RiskLevel | ''>('');
  const [explanation, setExplanation] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (submitting) return;

    setSubmitting(true);
    setErrorMsg(null);

    try {
      await submitFeedback({
        analysis_id: analysisId,
        detection_module: detectionModule,
        predicted_verdict: predictedVerdict || (predictedRiskLevel === 'HIGH_RISK' || predictedRiskLevel === 'MEDIUM_RISK' ? 'SCAM' : 'BENIGN'),
        predicted_risk_level: predictedRiskLevel,
        user_correction: correction,
        corrected_risk_level: correctedRisk ? (correctedRisk as RiskLevel) : undefined,
        explanation: explanation.trim() || undefined,
        target_content: targetSummary ? targetSummary.slice(0, 300) : undefined,
      });

      setSubmitted(true);
      setTimeout(() => {
        // Reset and close after 2.2 seconds
        setSubmitted(false);
        setExplanation('');
        onClose();
      }, 2200);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to submit feedback. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-lg bg-zinc-900 border border-zinc-700/80 rounded-2xl shadow-2xl overflow-hidden p-6 text-zinc-100">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-zinc-800">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
              </svg>
            </div>
            <div>
              <h3 className="font-semibold text-lg text-white">Detection Feedback</h3>
              <p className="text-xs text-zinc-400">Help refine DeepShield accuracy & verification</p>
            </div>
          </div>
          <button
            onClick={onClose}
            disabled={submitting}
            className="text-zinc-400 hover:text-zinc-200 p-1.5 rounded-lg hover:bg-zinc-800 transition"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {submitted ? (
          <div className="py-8 text-center space-y-3">
            <div className="w-12 h-12 mx-auto rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center">
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <h4 className="text-base font-medium text-emerald-400">Feedback Recorded</h4>
            <p className="text-xs text-zinc-400 max-w-xs mx-auto">
              Your report will be queued for forensic review. Approved samples become regression benchmarks to improve detector prompts and rules.
            </p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="mt-4 space-y-4">
            {/* Context Summary */}
            <div className="bg-zinc-950/60 rounded-xl p-3 border border-zinc-800/80 text-xs space-y-1">
              <div className="flex justify-between text-zinc-400">
                <span>Module: <strong className="text-zinc-200 uppercase">{detectionModule}</strong></span>
                {analysisId && <span>ID: <code className="text-indigo-300">{analysisId.slice(0, 16)}</code></span>}
              </div>
              {predictedRiskLevel && (
                <div className="text-zinc-400">
                  Predicted Level: <span className="font-medium text-zinc-200">{predictedRiskLevel}</span>
                </div>
              )}
              {targetSummary && (
                <div className="text-zinc-500 truncate pt-1 border-t border-zinc-800/50">
                  Target: <span className="text-zinc-400 italic">{targetSummary}</span>
                </div>
              )}
            </div>

            {errorMsg && (
              <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">
                {errorMsg}
              </div>
            )}

            {/* Correction selector */}
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                Assessment / Error Type <span className="text-rose-400">*</span>
              </label>
              <select
                value={correction}
                onChange={(e) => setCorrection(e.target.value as any)}
                className="w-full bg-zinc-950 border border-zinc-700/80 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-indigo-500 transition"
              >
                <option value="false_positive">False Positive (Safe content incorrectly flagged)</option>
                <option value="false_negative">False Negative (Scam or manipulated media missed)</option>
                <option value="correct">Accurate Verdict (Confirmed genuine detection)</option>
                <option value="wrong_risk_category">Incorrect Risk Severity or Category</option>
                <option value="incorrect_evidence">Inaccurate Evidence or Explanation</option>
                <option value="inconclusive">Inconclusive / Insufficient Evidence</option>
                <option value="other">Other issue</option>
              </select>
            </div>

            {/* Optional Corrected Risk Level */}
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                Corrected Risk Level (Optional)
              </label>
              <div className="grid grid-cols-4 gap-2 text-xs">
                {(['LOW_RISK', 'MEDIUM_RISK', 'HIGH_RISK', 'INCONCLUSIVE'] as RiskLevel[]).map((level) => (
                  <button
                    key={level}
                    type="button"
                    onClick={() => setCorrectedRisk(correctedRisk === level ? '' : level)}
                    className={`py-1.5 px-2 rounded-lg border text-center transition font-medium ${
                      correctedRisk === level
                        ? 'border-indigo-500 bg-indigo-500/20 text-indigo-300'
                        : 'border-zinc-800 bg-zinc-950/80 text-zinc-400 hover:border-zinc-700'
                    }`}
                  >
                    {level.replace('_RISK', '')}
                  </button>
                ))}
              </div>
            </div>

            {/* Explanation textarea */}
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                Context / Forensic Rationale (Optional)
              </label>
              <textarea
                value={explanation}
                onChange={(e) => setExplanation(e.target.value)}
                maxLength={1000}
                rows={3}
                placeholder="Why is this incorrect? (e.g. routine company newsletter, testing phishing simulator, authentic sender domain)"
                className="w-full bg-zinc-950 border border-zinc-700/80 rounded-lg p-2.5 text-xs text-zinc-200 focus:outline-none focus:border-indigo-500 transition placeholder:text-zinc-600"
              />
              <div className="text-right text-[10px] text-zinc-500 mt-0.5">
                {explanation.length}/1000
              </div>
            </div>

            {/* Footer Buttons */}
            <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-zinc-800">
              <button
                type="button"
                onClick={onClose}
                disabled={submitting}
                className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="px-4 py-1.5 rounded-lg text-xs font-medium bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white shadow-md shadow-indigo-500/20 transition disabled:opacity-50 flex items-center gap-1.5"
              >
                {submitting ? (
                  <>
                    <svg className="w-3.5 h-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
                    </svg>
                    Submitting...
                  </>
                ) : (
                  'Submit Feedback'
                )}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
