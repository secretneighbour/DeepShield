import React from 'react';
import {
  Shield,
  ArrowRight,
  Lock,
  Cpu,
  FileText,
  Link as LinkIcon,
  Image as ImageIcon,
  Mic,
  CheckCircle2,
  AlertTriangle,
  Eye,
  ChevronRight,
  ExternalLink,
} from 'lucide-react';

import { DeepShieldLogo } from './DeepShieldLogo';

interface LandingPageViewProps {
  onEnterDashboard: () => void;
  onNavigateAnalyze: (type: 'text' | 'url' | 'image' | 'video' | 'audio') => void;
}

export const LandingPageView: React.FC<LandingPageViewProps> = ({
  onEnterDashboard,
  onNavigateAnalyze,
}) => {
  const scrollToFeatures = () => {
    document.getElementById('features-section')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-[#05070f] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-300">
      {/* Top Ambient Light Glow */}
      <div className="fixed top-0 left-1/2 -translate-x-1/2 w-[1000px] h-[400px] bg-gradient-to-b from-indigo-950/30 via-cyan-950/20 to-transparent blur-3xl pointer-events-none -z-10" />

      {/* Asus-Inspired Minimalist Navigation Header */}
      <header className="sticky top-0 z-50 bg-[#05070f]/80 backdrop-blur-xl border-b border-slate-800/80">
        <div className="max-w-7xl mx-auto px-6 h-20 flex items-center justify-between">
          <div className="flex items-center gap-3.5">
            <DeepShieldLogo size={28} showText={true} tagline={true} />
          </div>

          <nav className="hidden md:flex items-center gap-8 text-sm text-slate-300">
            <button
              onClick={scrollToFeatures}
              className="hover:text-cyan-400 transition tracking-wide text-xs uppercase font-medium"
            >
              Capabilities
            </button>
            <a
              href="#how-it-works"
              className="hover:text-cyan-400 transition tracking-wide text-xs uppercase font-medium"
            >
              How It Works
            </a>
            <a
              href="#evidence-ai"
              className="hover:text-cyan-400 transition tracking-wide text-xs uppercase font-medium"
            >
              Two-Stage LLM
            </a>
            <a
              href="#privacy"
              className="hover:text-cyan-400 transition tracking-wide text-xs uppercase font-medium"
            >
              Zero-Retention
            </a>
          </nav>

          <div className="flex items-center gap-4">
            <button
              onClick={onEnterDashboard}
              className="px-5 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-white text-xs font-semibold tracking-wider uppercase transition flex items-center gap-2 group shadow-lg shadow-black/50"
            >
              <span>Open Dashboard</span>
              <ArrowRight size={14} className="group-hover:translate-x-1 transition text-cyan-400" />
            </button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative pt-20 pb-28 md:pt-28 md:pb-36 overflow-hidden">
        <div className="max-w-7xl mx-auto px-6 grid lg:grid-cols-12 gap-12 items-center">
          {/* Left Editorial Copy */}
          <div className="lg:col-span-7 space-y-8 z-10">
            <div className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full bg-slate-900/90 border border-slate-800 text-xs text-slate-300 shadow-inner">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              <span className="font-mono text-cyan-300">Autonomous Threat Intelligence</span>
              <span className="text-slate-600">•</span>
              <span className="text-slate-400">Deepfake & Phishing Forensics</span>
            </div>

            <h1 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight text-white leading-[1.08]">
              See Beyond the Surface.{' '}
              <span className="bg-gradient-to-r from-cyan-400 via-indigo-300 to-purple-400 bg-clip-text text-transparent block mt-2">
                Detect Deception.
              </span>
            </h1>

            <p className="text-base sm:text-lg text-slate-400 max-w-2xl leading-relaxed font-normal">
              Analyze suspicious messages, investigate potentially dangerous links, and examine media
              for signs of manipulation with transparent, evidence-grounded AI telemetry.
            </p>

            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-4 pt-2">
              <button
                onClick={scrollToFeatures}
                className="px-8 py-4 rounded-xl bg-gradient-to-r from-cyan-500 via-indigo-600 to-violet-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-semibold text-sm tracking-wide transition shadow-xl shadow-cyan-950/60 flex items-center justify-center gap-2.5 group cursor-pointer"
              >
                <span>Explore DeepShield</span>
                <ChevronRight size={16} className="group-hover:translate-x-1 transition" />
              </button>

              <button
                onClick={onEnterDashboard}
                className="px-8 py-4 rounded-xl bg-slate-900/90 hover:bg-slate-800/90 border border-slate-700 text-slate-200 hover:text-white font-medium text-sm transition flex items-center justify-center gap-2 cursor-pointer"
              >
                <span>Open Dashboard</span>
                <ExternalLink size={15} className="text-slate-400" />
              </button>
            </div>

            <div className="pt-6 border-t border-slate-800/60 grid grid-cols-3 gap-6 text-left">
              <div>
                <div className="text-xl font-bold font-mono text-slate-100">Zero-Trust</div>
                <div className="text-xs text-slate-400 mt-0.5">Dual-LLM Cross-Check</div>
              </div>
              <div>
                <div className="text-xl font-bold font-mono text-slate-100">&lt;5ms</div>
                <div className="text-xs text-slate-400 mt-0.5">Local Baseline Engine</div>
              </div>
              <div>
                <div className="text-xl font-bold font-mono text-emerald-400">100% Private</div>
                <div className="text-xs text-slate-400 mt-0.5">Ephemeral Memory Mode</div>
              </div>
            </div>
          </div>

          {/* Right Abstract Animated Security Shield (ASUS-Style Geometric Shield) */}
          <div className="lg:col-span-5 flex items-center justify-center relative">
            <div className="relative w-80 h-80 sm:w-96 sm:h-96 flex items-center justify-center">
              {/* Outer Glowing Orbital Rings */}
              <div className="absolute inset-0 rounded-full border border-indigo-500/20 animate-spin [animation-duration:30s]" />
              <div className="absolute inset-4 rounded-full border border-dashed border-cyan-500/20 animate-spin [animation-duration:20s] [animation-direction:reverse]" />
              <div className="absolute inset-12 rounded-full border border-slate-800" />

              {/* Central Glowing Core Shield */}
              <div className="relative z-10 w-48 h-48 sm:w-56 sm:h-56 rounded-3xl bg-gradient-to-b from-slate-900/90 to-slate-950/90 border border-slate-700/80 backdrop-blur-2xl p-6 flex flex-col items-center justify-center shadow-2xl shadow-indigo-950/60 overflow-hidden group">
                {/* Sweeping Laser Radar Line */}
                <div className="absolute inset-x-0 h-1 bg-gradient-to-r from-transparent via-cyan-400 to-transparent top-0 animate-[scan_3s_ease-in-out_infinite]" />

                <Shield size={64} className="text-cyan-400 stroke-[1.5] mb-3 drop-shadow-[0_0_20px_rgba(56,189,248,0.5)]" />
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                  Forensic Core
                </span>
                <span className="text-[10px] font-mono text-cyan-400 mt-1 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                  Active Telemetry
                </span>
              </div>

              {/* Floating Analytical Orbit Nodes */}
              <div className="absolute -top-2 left-10 p-3 rounded-xl bg-slate-900/90 border border-slate-800 text-[11px] font-mono text-slate-300 shadow-xl backdrop-blur-md flex items-center gap-2">
                <FileText size={14} className="text-cyan-400" />
                <span>Stage 1: Local Ollama</span>
              </div>

              <div className="absolute bottom-2 right-6 p-3 rounded-xl bg-slate-900/90 border border-slate-800 text-[11px] font-mono text-slate-300 shadow-xl backdrop-blur-md flex items-center gap-2">
                <Cpu size={14} className="text-purple-400" />
                <span>Stage 2: Gemini Cloud</span>
              </div>

              <div className="absolute top-1/2 -right-4 -translate-y-1/2 p-2.5 rounded-xl bg-slate-900/90 border border-slate-800 text-[11px] font-mono text-emerald-400 shadow-xl backdrop-blur-md flex items-center gap-1.5">
                <Lock size={13} />
                <span>SSRF Verified</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Feature Showcase Grid */}
      <section id="features-section" className="py-24 border-t border-slate-800/80 bg-[#070a14]/60 relative">
        <div className="max-w-7xl mx-auto px-6">
          <div className="max-w-2xl mb-16 space-y-3">
            <span className="text-xs font-mono uppercase tracking-widest text-cyan-400">
              ENGINEERED FORENSIC SUITE
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white">
              Specialized Detection Modules
            </h2>
            <p className="text-slate-400 text-sm leading-relaxed">
              Every vector of fraud employs distinct evasion techniques. DeepShield deploys calibrated,
              evidence-grounded analysis pipelines specifically designed for each media format.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {/* Feature 1: Text */}
            <div
              onClick={() => onNavigateAnalyze('text')}
              className="p-7 rounded-2xl bg-slate-900/40 hover:bg-slate-900/80 border border-slate-800 hover:border-cyan-500/50 transition duration-300 group cursor-pointer flex flex-col justify-between"
            >
              <div>
                <div className="w-12 h-12 rounded-xl bg-cyan-950/60 border border-cyan-800/40 text-cyan-400 flex items-center justify-center mb-6 group-hover:scale-110 transition">
                  <FileText size={22} />
                </div>
                <h3 className="text-lg font-bold text-slate-100 mb-2">Scam Intelligence</h3>
                <p className="text-xs text-slate-400 leading-relaxed mb-4">
                  Multi-turn social engineering analysis detecting false urgency, executive impersonation,
                  unsolicited OTP solicitation, wire fraud, and blackmail scareware.
                </p>
              </div>
              <div className="pt-4 border-t border-slate-800/60 flex items-center justify-between text-xs text-cyan-400 font-mono">
                <span>Two-Stage Pipeline</span>
                <ArrowRight size={14} className="group-hover:translate-x-1 transition" />
              </div>
            </div>

            {/* Feature 2: URL */}
            <div
              onClick={() => onNavigateAnalyze('url')}
              className="p-7 rounded-2xl bg-slate-900/40 hover:bg-slate-900/80 border border-slate-800 hover:border-indigo-500/50 transition duration-300 group cursor-pointer flex flex-col justify-between"
            >
              <div>
                <div className="w-12 h-12 rounded-xl bg-indigo-950/60 border border-indigo-800/40 text-indigo-400 flex items-center justify-center mb-6 group-hover:scale-110 transition">
                  <LinkIcon size={22} />
                </div>
                <h3 className="text-lg font-bold text-slate-100 mb-2">Phishing & URL Forensics</h3>
                <p className="text-xs text-slate-400 leading-relaxed mb-4">
                  Detects IDN homoglyph lookalikes (Cyrillic disguised as Latin), algorithmically registered
                  high-entropy hostnames, and blocks internal RFC-1918 SSRF exploitation.
                </p>
              </div>
              <div className="pt-4 border-t border-slate-800/60 flex items-center justify-between text-xs text-indigo-400 font-mono">
                <span>SSRF + Threat Intel</span>
                <ArrowRight size={14} className="group-hover:translate-x-1 transition" />
              </div>
            </div>

            {/* Feature 3: Image */}
            <div
              onClick={() => onNavigateAnalyze('image')}
              className="p-7 rounded-2xl bg-slate-900/40 hover:bg-slate-900/80 border border-slate-800 hover:border-purple-500/50 transition duration-300 group cursor-pointer flex flex-col justify-between"
            >
              <div>
                <div className="w-12 h-12 rounded-xl bg-purple-950/60 border border-purple-800/40 text-purple-400 flex items-center justify-center mb-6 group-hover:scale-110 transition">
                  <ImageIcon size={22} />
                </div>
                <h3 className="text-lg font-bold text-slate-100 mb-2">Image Deepfakes</h3>
                <p className="text-xs text-slate-400 leading-relaxed mb-4">
                  Error Level Analysis (ELA) heatmap generation, 2D Fast Fourier Transform spectral grid
                  anomaly detection, and EXIF software generation footprint inspection.
                </p>
              </div>
              <div className="pt-4 border-t border-slate-800/60 flex items-center justify-between text-xs text-purple-400 font-mono">
                <span>ELA & FFT Spectrum</span>
                <ArrowRight size={14} className="group-hover:translate-x-1 transition" />
              </div>
            </div>

            {/* Feature 4: Audio/Video */}
            <div
              onClick={() => onNavigateAnalyze('audio')}
              className="p-7 rounded-2xl bg-slate-900/40 hover:bg-slate-900/80 border border-slate-800 hover:border-pink-500/50 transition duration-300 group cursor-pointer flex flex-col justify-between"
            >
              <div>
                <div className="w-12 h-12 rounded-xl bg-pink-950/60 border border-pink-800/40 text-pink-400 flex items-center justify-center mb-6 group-hover:scale-110 transition">
                  <Mic size={22} />
                </div>
                <h3 className="text-lg font-bold text-slate-100 mb-2">Audio & Video Analysis</h3>
                <p className="text-xs text-slate-400 leading-relaxed mb-4">
                  Vocal pitch jitter micro-tremor tracking, vocoder frequency cliff detection, and frame-sampled
                  temporal inconsistency timeline graphing.
                </p>
              </div>
              <div className="pt-4 border-t border-slate-800/60 flex items-center justify-between text-xs text-pink-400 font-mono">
                <span>Dual-Verdict Audio</span>
                <ArrowRight size={14} className="group-hover:translate-x-1 transition" />
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section id="how-it-works" className="py-24 border-t border-slate-800/80 relative">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center max-w-3xl mx-auto mb-20 space-y-3">
            <span className="text-xs font-mono uppercase tracking-widest text-indigo-400">
              SYSTEM ARCHITECTURE
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white">
              The 3-Step Verification Protocol
            </h2>
            <p className="text-slate-400 text-sm leading-relaxed">
              Transparent, repeatable forensic verification designed to empower human judgment rather than replace it.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8 relative">
            {/* Step 1 */}
            <div className="p-8 rounded-2xl bg-slate-900/40 border border-slate-800 space-y-4 relative">
              <div className="text-4xl font-extrabold font-mono text-cyan-400/30">01</div>
              <h3 className="text-lg font-bold text-slate-100">Submit Content</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Paste message text, enter target URLs, or upload images, audio, or video clips directly
                through drag-and-drop interfaces with automated binary magic-byte validation.
              </p>
            </div>

            {/* Step 2 */}
            <div className="p-8 rounded-2xl bg-slate-900/40 border border-slate-800 space-y-4 relative">
              <div className="text-4xl font-extrabold font-mono text-indigo-400/30">02</div>
              <h3 className="text-lg font-bold text-slate-100">Analyze Available Evidence</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Independent detectors inspect lexical patterns, acoustic waveforms, frequency harmonics,
                or spatiotemporal stability. Quoted evidence is verified directly against source inputs.
              </p>
            </div>

            {/* Step 3 */}
            <div className="p-8 rounded-2xl bg-slate-900/40 border border-slate-800 space-y-4 relative">
              <div className="text-4xl font-extrabold font-mono text-purple-400/30">03</div>
              <h3 className="text-lg font-bold text-slate-100">Understand Risks & Actions</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Review calibrated risk verdicts, highlighted suspicious tokens, technical limitations, and actionable
                defensive next steps without fabricated certitude.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Two-Stage LLM Explanation Section */}
      <section id="evidence-ai" className="py-24 border-t border-slate-800/80 bg-[#070a14]/60">
        <div className="max-w-7xl mx-auto px-6 grid lg:grid-cols-12 gap-12 items-center">
          <div className="lg:col-span-6 space-y-6">
            <span className="text-xs font-mono uppercase tracking-widest text-cyan-400">
              MANDATORY SEQUENCING
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white leading-tight">
              Two-Stage LLM Architecture: Local First, Gemini Review Second
            </h2>
            <p className="text-sm text-slate-400 leading-relaxed">
              Single-LLM pipelines frequently suffer from hallucination and overconfidence. DeepShield
              enforces an asymmetric, dual-stage security protocol:
            </p>

            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-start gap-3">
                <div className="p-2 rounded-lg bg-cyan-950 text-cyan-400 shrink-0">
                  <Cpu size={18} />
                </div>
                <div>
                  <h4 className="text-sm font-semibold text-slate-200">Stage 1: Local LLM (Ollama / Gemma 3 4B)</h4>
                  <p className="text-xs text-slate-400 leading-relaxed mt-1">
                    Operates on-device without cloud transmission. Extracts suspicious phrases, coercion cues, and plausible innocent interpretations.
                  </p>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-start gap-3">
                <div className="p-2 rounded-lg bg-purple-950 text-purple-400 shrink-0">
                  <Shield size={18} />
                </div>
                <div>
                  <h4 className="text-sm font-semibold text-slate-200">Stage 2: Gemini Cloud Reviewer</h4>
                  <p className="text-xs text-slate-400 leading-relaxed mt-1">
                    When permitted by your privacy setting, Gemini critically reviews the original text alongside the local model&apos;s findings, challenging over-reach and identifying missed nuances.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="lg:col-span-6 p-7 rounded-2xl bg-slate-950 border border-slate-800 space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 text-slate-400">
              <span className="text-cyan-400 font-bold">PIPELINE VERIFICATION PROTOCOL</span>
              <span>STRICT ORDER</span>
            </div>
            <div className="space-y-2 text-slate-300">
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle2 size={14} />
                <span>1. Strict Untrusted Input Sanitization</span>
              </div>
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle2 size={14} />
                <span>2. Local Stage Execution via Ollama HTTP</span>
              </div>
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle2 size={14} />
                <span>3. Quoted Evidence Verified Against Source Text</span>
              </div>
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle2 size={14} />
                <span>4. User Cloud Privacy Policy Gate</span>
              </div>
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle2 size={14} />
                <span>5. Google Gemini Cross-Examination</span>
              </div>
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle2 size={14} />
                <span>6. Multi-Provider Consensus Synthesis</span>
              </div>
            </div>
            <div className="p-3 rounded-lg bg-slate-900 text-slate-400 text-[11px] leading-relaxed border border-slate-800">
              &quot;Low risk does not guarantee safety, and inconclusive evidence does not prove legitimacy.&quot;
            </div>
          </div>
        </div>
      </section>

      {/* Privacy and Responsible AI Section */}
      <section id="privacy" className="py-24 border-t border-slate-800/80 relative">
        <div className="max-w-7xl mx-auto px-6">
          <div className="max-w-2xl mb-12 space-y-3">
            <span className="text-xs font-mono uppercase tracking-widest text-emerald-400">
              ETHICAL DEFENSE
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white">
              Privacy by Design & Responsible AI
            </h2>
            <p className="text-slate-400 text-sm leading-relaxed">
              Cybersecurity tools should protect user privacy, not invade it. DeepShield gives users full sovereign control.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 space-y-3">
              <Lock className="text-emerald-400" size={24} />
              <h3 className="text-base font-bold text-slate-100">Zero-Retention Mode</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Toggle ephemeral analysis mode with one click. In this mode, zero message texts, audio clips,
                or forensic reports are written to disk or stored in SQLite.
              </p>
            </div>

            <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 space-y-3">
              <Eye className="text-cyan-400" size={24} />
              <h3 className="text-base font-bold text-slate-100">User-Controlled Cloud Gate</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                You decide whether Gemini cloud analysis runs. If disabled, submitted content never leaves your
                host, and the analysis is certified as Local Only.
              </p>
            </div>

            <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 space-y-3">
              <AlertTriangle className="text-amber-400" size={24} />
              <h3 className="text-base font-bold text-slate-100">Zero Fabricated Certitude</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                We never fabricate detection rates or attack statistics. When models disagree or evidence is thin,
                results are honestly marked as Inconclusive.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Final Editorial Call to Action (ASUS Inspired) */}
      <section className="py-24 border-t border-slate-800/80 bg-gradient-to-b from-slate-950 via-[#0a0e1c] to-[#05070f] relative overflow-hidden">
        <div className="max-w-4xl mx-auto px-6 text-center space-y-8 relative z-10">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-cyan-500 via-indigo-600 to-purple-600 p-[1px] mx-auto shadow-2xl shadow-cyan-950">
            <div className="w-full h-full bg-slate-950 rounded-[15px] flex items-center justify-center text-cyan-400">
              <Shield size={32} />
            </div>
          </div>

          <h2 className="text-4xl sm:text-5xl font-black text-white tracking-tight">
            Look closer. Question more. Verify better.
          </h2>

          <p className="text-slate-400 text-sm max-w-xl mx-auto leading-relaxed">
            Protect your communications, evaluate suspicious links, and expose synthetic deepfakes with
            explainable, evidence-grounded AI telemetry.
          </p>

          <div className="pt-4 flex justify-center">
            <button
              onClick={onEnterDashboard}
              className="px-10 py-4 rounded-xl bg-gradient-to-r from-cyan-500 via-indigo-600 to-purple-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-bold text-sm tracking-wide transition shadow-2xl shadow-cyan-950 flex items-center gap-3 group cursor-pointer"
            >
              <span>Launch DeepShield Operations</span>
              <ArrowRight size={18} className="group-hover:translate-x-1.5 transition text-white" />
            </button>
          </div>
        </div>
      </section>

      {/* Editorial Footer */}
      <footer className="border-t border-slate-800/80 py-12 bg-[#04060d]">
        <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-6 text-xs text-slate-500">
          <div className="flex items-center gap-3">
            <Shield size={16} className="text-cyan-400" />
            <span className="font-bold text-slate-200">DeepShield</span>
            <span className="text-cyan-400 font-mono">• See Beyond the Surface. Detect Deception.</span>
          </div>

          <div className="flex items-center gap-6">
            <span>FastAPI Backend (8000)</span>
            <span>React Vite (5173)</span>
            <span>Ollama Gemma 3 4B</span>
            <span>Google Gemini Reviewer</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
