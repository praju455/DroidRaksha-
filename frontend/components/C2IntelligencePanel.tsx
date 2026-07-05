"use client";

import { Shield, Radio, Globe, Server, AlertTriangle, Lock, Wifi } from "lucide-react";

// ── Types ─────────────────────────────────────────────────────────────────────

interface FrameworkDetection {
  framework: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  description: string;
  matched_pattern: string;
}

interface C2IP {
  ip: string;
  confidence: number;
  country: string;
  isp: string;
  usage_type: string;
  geo_risk_score: number;
  geo_risk_reasons: string[];
  c2_probability: "HIGH" | "MEDIUM" | "LOW";
}

interface C2Intelligence {
  c2_verdict: "CONFIRMED" | "LIKELY" | "SUSPECTED" | "NONE";
  c2_confidence_score: number;
  frameworks_detected: FrameworkDetection[];
  c2_framework_detected: boolean;
  confirmed_c2_ips: C2IP[];
  all_flagged_ips: C2IP[];
  beacon_patterns: string[];
  tor_detected: boolean;
  india_c2_domains: string[];
  summary: string;
}

interface Props {
  c2Intelligence: C2Intelligence | null | undefined;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const verdictStyles: Record<string, { border: string; bg: string; text: string; label: string }> = {
  CONFIRMED: {
    border: "border-[#f43f5e]",
    bg:     "bg-[rgba(244,63,94,0.08)]",
    text:   "text-[#f43f5e]",
    label:  "C2 CONFIRMED",
  },
  LIKELY: {
    border: "border-[#f97316]",
    bg:     "bg-[rgba(249,115,22,0.08)]",
    text:   "text-[#f97316]",
    label:  "C2 LIKELY",
  },
  SUSPECTED: {
    border: "border-[#eab308]",
    bg:     "bg-[rgba(234,179,8,0.08)]",
    text:   "text-[#eab308]",
    label:  "C2 SUSPECTED",
  },
  NONE: {
    border: "border-border",
    bg:     "bg-surface-raised",
    text:   "text-[#22d3ee]",
    label:  "NO C2 DETECTED",
  },
};

const severityColor = (s: string) =>
  s === "CRITICAL" ? "text-[#f43f5e] border-[#f43f5e] bg-[rgba(244,63,94,0.1)]"
  : s === "HIGH"   ? "text-[#f97316] border-[#f97316] bg-[rgba(249,115,22,0.1)]"
  :                  "text-[#eab308] border-[#eab308] bg-[rgba(234,179,8,0.1)]";

const probColor = (p: string) =>
  p === "HIGH"   ? "text-[#f43f5e]"
  : p === "MEDIUM" ? "text-[#f97316]"
  :                  "text-[#22d3ee]";

// ── Score Ring ────────────────────────────────────────────────────────────────

function ScoreRing({ score, verdict }: { score: number; verdict: string }) {
  const style = verdictStyles[verdict] ?? verdictStyles.NONE;
  const r = 36;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;

  return (
    <div className="relative flex items-center justify-center w-24 h-24">
      <svg className="absolute inset-0 -rotate-90" width="96" height="96" viewBox="0 0 96 96">
        <circle cx="48" cy="48" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="6" />
        <circle
          cx="48" cy="48" r={r} fill="none"
          stroke={score >= 70 ? "#f43f5e" : score >= 40 ? "#f97316" : score >= 15 ? "#eab308" : "#22d3ee"}
          strokeWidth="6"
          strokeDasharray={`${dash} ${circ - dash}`}
          strokeLinecap="round"
          style={{ transition: "stroke-dasharray 1s ease" }}
        />
      </svg>
      <div className="text-center z-10">
        <span className={`text-xl font-bold font-mono ${style.text}`}>{score}</span>
        <span className="block text-[0.5rem] font-mono text-muted uppercase tracking-widest">/ 100</span>
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function C2IntelligencePanel({ c2Intelligence }: Props) {
  if (!c2Intelligence) {
    return (
      <div className="border border-border bg-surface-raised p-4 corner-brackets">
        <p className="text-[0.65rem] font-mono text-muted uppercase tracking-widest">
          [ C2 INTELLIGENCE ] — Not available for this analysis
        </p>
      </div>
    );
  }

  const c2 = c2Intelligence;
  const style = verdictStyles[c2.c2_verdict] ?? verdictStyles.NONE;

  return (
    <div id="c2-intelligence-panel" className={`border ${style.border} ${style.bg} overflow-hidden`}>
      {/* Header */}
      <div className={`flex items-center justify-between px-5 py-3 border-b ${style.border} bg-[rgba(0,0,0,0.3)]`}>
        <div className="flex items-center gap-3">
          <Radio className={`w-4 h-4 ${style.text}`} />
          <span className="text-xs font-mono uppercase tracking-widest text-secondary font-bold">
            C2 Intelligence
          </span>
          {c2.c2_verdict !== "NONE" && (
            <span className={`text-[0.6rem] font-bold px-2 py-0.5 border ${style.text} ${style.border} uppercase tracking-widest`}>
              {style.label}
            </span>
          )}
        </div>
        <span className={`text-[0.65rem] font-mono ${style.text} uppercase`}>
          {c2.summary.split("]")[0]?.replace("[", "") || c2.c2_verdict}
        </span>
      </div>

      <div className="p-5 space-y-5">
        {/* Score + Summary */}
        <div className="flex items-center gap-6">
          <ScoreRing score={c2.c2_confidence_score} verdict={c2.c2_verdict} />
          <div className="flex-1 space-y-2">
            <p className="text-[0.75rem] font-mono text-secondary leading-relaxed">
              {c2.summary}
            </p>
            <div className="flex flex-wrap gap-2">
              {c2.tor_detected && (
                <span className="flex items-center gap-1 text-[0.6rem] font-mono px-2 py-0.5 border border-[#a78bfa] text-[#a78bfa] bg-[rgba(167,139,250,0.1)]">
                  <Lock className="w-2.5 h-2.5" /> TOR ROUTING
                </span>
              )}
              {c2.beacon_patterns.length > 0 && (
                <span className="flex items-center gap-1 text-[0.6rem] font-mono px-2 py-0.5 border border-[#f97316] text-[#f97316] bg-[rgba(249,115,22,0.1)]">
                  <Wifi className="w-2.5 h-2.5" /> BEACON DETECTED
                </span>
              )}
              {c2.india_c2_domains.length > 0 && (
                <span className="flex items-center gap-1 text-[0.6rem] font-mono px-2 py-0.5 border border-[#f43f5e] text-[#f43f5e] bg-[rgba(244,63,94,0.1)]">
                  <AlertTriangle className="w-2.5 h-2.5" /> INDIA C2 DOMAINS
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Framework Detections */}
        {c2.frameworks_detected.length > 0 && (
          <div className="space-y-2">
            <p className="text-[0.6rem] font-mono text-muted uppercase tracking-widest border-b border-border pb-1">
              Detected Frameworks / Families
            </p>
            <div className="space-y-2">
              {c2.frameworks_detected.map((f, i) => (
                <div key={i} className="flex items-start gap-3 p-3 bg-[rgba(0,0,0,0.3)] border border-border">
                  <Shield className="w-3.5 h-3.5 mt-0.5 text-danger shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-[0.75rem] font-mono font-bold text-secondary">{f.framework}</span>
                      <span className={`text-[0.55rem] font-bold px-1.5 py-0.5 border ${severityColor(f.severity)}`}>
                        {f.severity}
                      </span>
                    </div>
                    <p className="text-[0.65rem] font-mono text-muted">{f.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Confirmed C2 IPs */}
        {c2.confirmed_c2_ips.length > 0 && (
          <div className="space-y-2">
            <p className="text-[0.6rem] font-mono text-muted uppercase tracking-widest border-b border-border pb-1">
              Confirmed C2 IP Addresses ({c2.confirmed_c2_ips.length})
            </p>
            <div className="space-y-1.5">
              {c2.confirmed_c2_ips.map((ip, i) => (
                <div key={i} className="flex items-center gap-3 p-2.5 bg-[rgba(244,63,94,0.05)] border border-[rgba(244,63,94,0.2)]">
                  <Server className="w-3 h-3 text-danger shrink-0" />
                  <code className="text-[0.7rem] font-mono text-danger font-bold w-32 shrink-0">{ip.ip}</code>
                  <span className="text-[0.6rem] font-mono text-muted flex-1 truncate">{ip.isp} · {ip.country}</span>
                  <span className={`text-[0.6rem] font-mono font-bold ${probColor(ip.c2_probability)}`}>
                    {ip.c2_probability} PROB
                  </span>
                  <span className="text-[0.6rem] font-mono text-muted">
                    {ip.confidence}% confidence
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Beacon Patterns */}
        {c2.beacon_patterns.length > 0 && (
          <div className="space-y-2">
            <p className="text-[0.6rem] font-mono text-muted uppercase tracking-widest border-b border-border pb-1">
              Beacon Patterns
            </p>
            <div className="space-y-1">
              {c2.beacon_patterns.map((p, i) => (
                <div key={i} className="flex items-center gap-2 text-[0.65rem] font-mono text-[#f97316]">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#f97316] animate-pulse shrink-0" />
                  {p}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* India C2 Domains */}
        {c2.india_c2_domains.length > 0 && (
          <div className="space-y-2">
            <p className="text-[0.6rem] font-mono text-muted uppercase tracking-widest border-b border-border pb-1">
              India-Specific C2 / Phishing Domains ({c2.india_c2_domains.length})
            </p>
            <div className="flex flex-wrap gap-1.5">
              {c2.india_c2_domains.map((d, i) => (
                <code key={i} className="text-[0.65rem] font-mono px-2 py-0.5 bg-[rgba(244,63,94,0.1)] border border-[rgba(244,63,94,0.2)] text-danger">
                  {d}
                </code>
              ))}
            </div>
          </div>
        )}

        {/* Clean bill */}
        {c2.c2_verdict === "NONE" && (
          <div className="flex items-center gap-3 p-3 border border-[rgba(34,197,94,0.2)] bg-[rgba(34,197,94,0.05)]">
            <Globe className="w-4 h-4 text-[#22c55e]" />
            <p className="text-[0.7rem] font-mono text-[#22c55e]">
              No C2 infrastructure indicators detected in static analysis.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
