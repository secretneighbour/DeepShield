import React from 'react';
import { AlertCircle, CheckCircle2, Info, AlertTriangle, ArrowRight } from 'lucide-react';
import type { EvidenceItem } from '../types';

interface EvidenceListProps {
  evidence: EvidenceItem[];
  recommendedActions?: string[];
  limitations?: string[];
  modelAttribution?: string;
}

export const EvidenceList: React.FC<EvidenceListProps> = ({
  evidence,
  recommendedActions,
  limitations,
  modelAttribution,
}) => {
  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'high':
        return <AlertCircle className="text-red-400 shrink-0 mt-0.5" size={18} />;
      case 'medium':
        return <AlertTriangle className="text-amber-400 shrink-0 mt-0.5" size={18} />;
      case 'low':
        return <Info className="text-blue-400 shrink-0 mt-0.5" size={18} />;
      default:
        return <CheckCircle2 className="text-emerald-400 shrink-0 mt-0.5" size={18} />;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'high':
        return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'medium':
        return 'bg-amber-500/10 text-amber-300 border-amber-500/30';
      case 'low':
        return 'bg-blue-500/10 text-blue-300 border-blue-500/30';
      default:
        return 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30';
    }
  };

  return (
    <div className="space-y-6">
      {/* Evidence Items Section */}
      <div>
        <h4 className="text-xs uppercase tracking-wider text-slate-400 font-semibold mb-3">
          Observed Forensic Indicators ({evidence.length})
        </h4>
        {evidence.length === 0 ? (
          <p className="text-sm text-slate-400 italic">No adverse indicators observed.</p>
        ) : (
          <div className="grid gap-3">
            {evidence.map((item, idx) => (
              <div
                key={idx}
                className="p-3.5 rounded-lg bg-slate-900/80 border border-slate-800 flex items-start gap-3 hover:border-slate-700 transition"
              >
                {getSeverityIcon(item.severity)}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="font-medium text-slate-200 text-sm">{item.title}</span>
                    <span
                      className={`text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border font-mono ${getSeverityBadge(
                        item.severity
                      )}`}
                    >
                      {item.severity}
                    </span>
                    <span className="text-xs text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded">
                      {item.category}
                    </span>
                    {item.metric_value !== undefined && item.metric_value !== null && (
                      <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/50 px-2 py-0.5 rounded">
                        metric: {item.metric_value}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{item.description}</p>
                  {item.snippet && (
                    <div className="mt-2 text-xs font-mono bg-slate-950 px-2.5 py-1.5 rounded border border-slate-800 text-amber-200/90 break-all">
                      &quot;{item.snippet}&quot;
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recommended Actions */}
      {recommendedActions && recommendedActions.length > 0 && (
        <div className="p-4 rounded-lg bg-indigo-950/20 border border-indigo-900/50">
          <h4 className="text-xs uppercase tracking-wider text-indigo-400 font-semibold mb-2.5 flex items-center gap-1.5">
            <ArrowRight size={14} />
            Recommended Defensive Actions
          </h4>
          <ul className="space-y-1.5 text-xs text-slate-300">
            {recommendedActions.map((action, idx) => (
              <li key={idx} className="flex items-start gap-2">
                <span className="text-indigo-400 font-bold">•</span>
                <span>{action}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* System Limitations & Calibrated Caveats */}
      {limitations && limitations.length > 0 && (
        <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800/80">
          <h4 className="text-[11px] uppercase tracking-wider text-slate-400 font-medium mb-1.5">
            Model Limitations & Forensic Uncertainty
          </h4>
          <ul className="space-y-1 text-xs text-slate-400">
            {limitations.map((lim, idx) => (
              <li key={idx} className="flex items-start gap-1.5">
                <span className="text-slate-400">-</span>
                <span>{lim}</span>
              </li>
            ))}
          </ul>
          {modelAttribution && (
            <div className="mt-2 pt-2 border-t border-slate-800 text-[11px] font-mono text-slate-400">
              Pipeline: {modelAttribution}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
