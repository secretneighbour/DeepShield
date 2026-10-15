import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, HelpCircle } from 'lucide-react';
import type { RiskLevel } from '../types';

interface RiskBadgeProps {
  level: RiskLevel;
  confidence?: number;
  size?: 'sm' | 'md' | 'lg';
  showConfidence?: boolean;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({
  level,
  confidence,
  size = 'md',
  showConfidence = true,
}) => {
  const configs = {
    HIGH_RISK: {
      label: 'HIGH RISK / MALICIOUS',
      bg: 'bg-red-950/70 border-red-500/60 text-red-400',
      glow: 'shadow-[0_0_15px_rgba(239,68,68,0.25)]',
      icon: ShieldAlert,
      iconColor: 'text-red-400',
    },
    MEDIUM_RISK: {
      label: 'SUSPICIOUS / ELEVATED RISK',
      bg: 'bg-amber-950/70 border-amber-500/60 text-amber-300',
      glow: 'shadow-[0_0_15px_rgba(245,158,11,0.2)]',
      icon: AlertTriangle,
      iconColor: 'text-amber-400',
    },
    LOW_RISK: {
      label: 'LOW RISK / BENIGN',
      bg: 'bg-emerald-950/70 border-emerald-500/60 text-emerald-300',
      glow: 'shadow-[0_0_15px_rgba(16,185,129,0.2)]',
      icon: ShieldCheck,
      iconColor: 'text-emerald-400',
    },
    INCONCLUSIVE: {
      label: 'INCONCLUSIVE EVIDENCE',
      bg: 'bg-slate-900 border-slate-600 text-slate-300',
      glow: '',
      icon: HelpCircle,
      iconColor: 'text-slate-400',
    },
  };

  const config = configs[level] || configs.INCONCLUSIVE;
  const Icon = config.icon;

  const sizeClasses = {
    sm: 'text-xs px-2.5 py-1 gap-1.5',
    md: 'text-sm px-3.5 py-1.5 gap-2',
    lg: 'text-base px-5 py-2.5 gap-2.5 font-semibold',
  };

  const iconSizes = {
    sm: 14,
    md: 16,
    lg: 20,
  };

  return (
    <div
      className={`inline-flex items-center rounded-full border ${config.bg} ${config.glow} ${sizeClasses[size]} tracking-wide`}
    >
      <Icon size={iconSizes[size]} className={config.iconColor} />
      <span>{config.label}</span>
      {showConfidence && confidence !== undefined && (
        <span className="opacity-75 font-mono text-xs border-l border-current/30 pl-2">
          {Math.round(confidence * 100)}% conf
        </span>
      )}
    </div>
  );
};
