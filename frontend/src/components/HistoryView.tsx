import React, { useState } from 'react';
import {
  History,
  Trash2,
  Download,
  Filter,
  Eye,
  X,
} from 'lucide-react';
import type { AnalysisRecordSummary } from '../types';
import { RiskBadge } from './RiskBadge';
import { deleteAnalysis, clearAllAnalyses, fetchAnalysisDetail } from '../api';

interface HistoryViewProps {
  records: AnalysisRecordSummary[];
  onRefresh: () => void;
  selectedRecordId?: string | null;
  onClearSelectedRecord: () => void;
}

export const HistoryView: React.FC<HistoryViewProps> = ({
  records,
  onRefresh,
  selectedRecordId,
  onClearSelectedRecord,
}) => {
  const [filterType, setFilterType] = useState<string>('all');
  const [filterRisk, setFilterRisk] = useState<string>('all');
  const [detailModalData, setDetailModalData] = useState<any | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const handleViewDetail = async (id: string) => {
    try {
      const data = await fetchAnalysisDetail(id);
      setDetailModalData(data);
    } catch (err: any) {
      alert(`Could not load record: ${err.message}`);
    }
  };

  // If selectedRecordId passed from outside, automatically open it
  React.useEffect(() => {
    if (selectedRecordId) {
      handleViewDetail(selectedRecordId);
    }
  }, [selectedRecordId]);

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to permanently delete this forensic audit record?')) return;
    setDeletingId(id);
    try {
      await deleteAnalysis(id);
      if (detailModalData?.id === id) setDetailModalData(null);
      onRefresh();
    } catch (err: any) {
      alert(`Delete error: ${err.message}`);
    } finally {
      setDeletingId(null);
    }
  };

  const handleClearAll = async () => {
    if (!confirm('Permanently wipe ALL forensic analysis history from the local database?')) return;
    try {
      await clearAllAnalyses();
      setDetailModalData(null);
      onRefresh();
    } catch (err: any) {
      alert(`Clear error: ${err.message}`);
    }
  };

  const handleExportJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(records, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute('href', dataStr);
    dlAnchor.setAttribute('download', `deepshield_forensics_export_${new Date().toISOString().slice(0, 10)}.json`);
    dlAnchor.click();
  };

  const filteredRecords = records.filter((rec) => {
    if (filterType !== 'all' && rec.analysis_type !== filterType) return false;
    if (filterRisk !== 'all' && rec.risk_level !== filterRisk) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <History className="text-cyan-400" size={22} />
            <span>Forensic Audit Records & Case History</span>
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Browse persistent database records of previous scam and synthetic media investigations.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={handleExportJSON}
            disabled={records.length === 0}
            className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition disabled:opacity-50"
          >
            <Download size={14} />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handleClearAll}
            disabled={records.length === 0}
            className="px-3.5 py-2 rounded-lg bg-red-950/60 hover:bg-red-900/60 text-red-300 border border-red-800/60 text-xs font-medium flex items-center gap-1.5 transition disabled:opacity-50"
          >
            <Trash2 size={14} />
            <span>Clear History</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-1.5 text-xs text-slate-400 font-medium">
            <Filter size={14} />
            <span>Filter:</span>
          </div>

          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none"
          >
            <option value="all">All Media Types</option>
            <option value="text">Text Messages</option>
            <option value="url">URLs & Phishing</option>
            <option value="image">Images</option>
            <option value="video">Videos</option>
            <option value="audio">Audio</option>
          </select>

          <select
            value={filterRisk}
            onChange={(e) => setFilterRisk(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none"
          >
            <option value="all">All Risk Levels</option>
            <option value="HIGH_RISK">High Risk Only</option>
            <option value="MEDIUM_RISK">Medium Risk Only</option>
            <option value="LOW_RISK">Low Risk Only</option>
          </select>
        </div>

        <div className="text-xs text-slate-400 font-mono">
          Showing {filteredRecords.length} of {records.length} records
        </div>
      </div>

      {/* Records Table */}
      {filteredRecords.length === 0 ? (
        <div className="p-12 text-center rounded-2xl bg-slate-900/40 border border-slate-800/80 text-slate-400 text-sm">
          No matching forensic investigations found.
        </div>
      ) : (
        <div className="overflow-x-auto border border-slate-800 rounded-xl bg-slate-900/60">
          <table className="w-full text-xs text-left">
            <thead className="bg-slate-950 text-slate-400 font-mono uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Subject / Snippet</th>
                <th className="py-3 px-4">Risk Level</th>
                <th className="py-3 px-4">Details</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 text-slate-200">
              {filteredRecords.map((rec) => (
                <tr
                  key={rec.id}
                  onClick={() => handleViewDetail(rec.id)}
                  className="hover:bg-slate-800/50 cursor-pointer transition"
                >
                  <td className="py-3 px-4 font-mono">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 uppercase text-[11px]">
                      {rec.analysis_type}
                    </span>
                  </td>
                  <td className="py-3 px-4 max-w-xs truncate font-medium">
                    {rec.target_summary}
                  </td>
                  <td className="py-3 px-4">
                    <RiskBadge level={rec.risk_level} confidence={rec.confidence} size="sm" />
                  </td>
                  <td className="py-3 px-4 text-slate-400 max-w-xs truncate">
                    {rec.category_or_detail}
                  </td>
                  <td className="py-3 px-4 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                    {new Date(rec.timestamp).toLocaleString()}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => handleViewDetail(rec.id)}
                        className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
                        title="View Full Case Report"
                      >
                        <Eye size={14} />
                      </button>
                      <button
                        onClick={(e) => handleDelete(rec.id, e)}
                        disabled={deletingId === rec.id}
                        className="p-1.5 rounded-lg bg-red-950/60 hover:bg-red-900/60 text-red-300 border border-red-800/50 transition"
                        title="Delete Record"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Forensic Report Modal */}
      {detailModalData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-2xl p-6 md:p-8 space-y-6 shadow-2xl">
            <button
              onClick={() => {
                setDetailModalData(null);
                onClearSelectedRecord();
              }}
              className="absolute top-5 right-5 p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
            >
              <X size={18} />
            </button>

            <div>
              <div className="flex items-center gap-3 mb-2 flex-wrap">
                <RiskBadge
                  level={detailModalData.risk_level}
                  confidence={detailModalData.confidence}
                  size="md"
                />
                <span className="text-xs font-mono text-slate-400 bg-slate-800 px-2.5 py-1 rounded">
                  ID: {detailModalData.id}
                </span>
                <span className="text-xs font-mono text-slate-400">
                  {detailModalData.timestamp}
                </span>
              </div>
              <h3 className="text-lg font-bold text-slate-100">
                Detailed Forensic Case Report
              </h3>
            </div>

            {/* Evidence items if any */}
            {detailModalData.evidence && (
              <div className="space-y-2">
                <h4 className="text-xs uppercase font-semibold text-slate-400 tracking-wider">
                  Documented Evidence Spans ({detailModalData.evidence.length})
                </h4>
                <div className="space-y-2">
                  {detailModalData.evidence.map((ev: any, idx: number) => (
                    <div key={idx} className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs">
                      <div className="flex justify-between items-center mb-1">
                        <span className="font-semibold text-slate-200">{ev.title}</span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300">
                          {ev.category}
                        </span>
                      </div>
                      <p className="text-slate-400">{ev.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Raw Forensic JSON */}
            <div>
              <h4 className="text-xs uppercase font-semibold text-slate-400 tracking-wider mb-2">
                Raw Forensic Telemetry JSON
              </h4>
              <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-slate-300 font-mono text-xs overflow-x-auto max-h-60 leading-relaxed">
                {JSON.stringify(detailModalData, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
