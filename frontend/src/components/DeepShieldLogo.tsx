import React from 'react';

interface DeepShieldLogoProps {
  size?: number;
  className?: string;
  showText?: boolean;
  tagline?: boolean;
}

export const DeepShieldLogo: React.FC<DeepShieldLogoProps> = ({
  size = 32,
  className = '',
  showText = false,
  tagline = false,
}) => {
  return (
    <div className={`inline-flex items-center gap-3 ${className}`}>
      {/* Precision Shield Icon with Layered Optical Sensor */}
      <div 
        className="relative flex items-center justify-center shrink-0 rounded-xl bg-gradient-to-tr from-cyan-500 via-indigo-600 to-violet-600 p-[1.5px] shadow-lg shadow-cyan-950/50"
        style={{ width: size + 8, height: size + 8 }}
      >
        <div className="w-full h-full bg-[#080c18] rounded-[10px] flex items-center justify-center overflow-hidden relative">
          {/* Subtle Ambient Scan Ray */}
          <div className="absolute inset-0 bg-gradient-to-b from-cyan-500/10 via-transparent to-purple-500/10 pointer-events-none" />
          
          <svg 
            viewBox="0 0 64 64" 
            width={size} 
            height={size} 
            fill="none" 
            className="drop-shadow-[0_0_8px_rgba(56,189,248,0.4)]"
          >
            {/* Outer Shield Shell */}
            <path 
              d="M32 6 L52 14 C52 35 43 49 32 58 C21 49 12 35 12 14 Z" 
              fill="#0a0f1d" 
              stroke="url(#dsGrad)" 
              strokeWidth="2.5" 
              strokeLinejoin="round" 
            />
            {/* Inner Shield Horizon */}
            <path 
              d="M32 14 L44 19 C44 33 38 43 32 49 C26 43 20 33 20 19 Z" 
              fill="none" 
              stroke="#38bdf8" 
              strokeOpacity="0.35" 
              strokeWidth="1.2" 
              strokeDasharray="2.5 1.5" 
            />
            {/* Core Radar/Aperture Iris ("See Beyond the Surface") */}
            <circle cx="32" cy="30" r="9" fill="#030712" stroke="#38bdf8" strokeWidth="1.8" />
            <circle cx="32" cy="30" r="4" fill="#38bdf8" />
            <line x1="23" y1="30" x2="41" y2="30" stroke="#38bdf8" strokeWidth="1.2" strokeLinecap="round" opacity="0.75" />
            <line x1="32" y1="21" x2="32" y2="39" stroke="#c084fc" strokeWidth="1.2" strokeLinecap="round" opacity="0.75" />
            <defs>
              <linearGradient id="dsGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#38bdf8" />
                <stop offset="50%" stopColor="#6366f1" />
                <stop offset="100%" stopColor="#c084fc" />
              </linearGradient>
            </defs>
          </svg>
        </div>
      </div>

      {showText && (
        <div className="flex flex-col">
          <div className="flex items-center gap-2">
            <span className="font-extrabold text-base tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-300 bg-clip-text text-transparent">
              DeepShield
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-medium">
              v1.0.0
            </span>
          </div>
          {tagline ? (
            <p className="text-[10px] text-cyan-400 font-mono tracking-wide">
              See Beyond the Surface. Detect Deception.
            </p>
          ) : (
            <p className="text-[10px] text-slate-400 font-mono tracking-wider">
              CYBERSECURITY FORENSICS
            </p>
          )}
        </div>
      )}
    </div>
  );
};
