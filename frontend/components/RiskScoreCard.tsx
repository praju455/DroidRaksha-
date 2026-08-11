import type { Risk } from "@/lib/types";
import { Shield, TrendingUp } from "lucide-react";

const LEVEL_CONFIG = {
  CRITICAL: { color: "#f43f5e", glow: "rgba(244,63,94,0.3)", label: "CRITICAL" },
  HIGH:     { color: "#f97316", glow: "rgba(249,115,22,0.3)", label: "HIGH" },
  MEDIUM:   { color: "#fbbf24", glow: "rgba(251,191,36,0.3)", label: "MEDIUM" },
  LOW:      { color: "#4ade80", glow: "rgba(74,222,128,0.3)", label: "LOW" },
  SAFE:     { color: "#22d3ee", glow: "rgba(34,211,238,0.3)", label: "SAFE" },
} as const;

const BREAKDOWN_LABELS: Record<string, string> = {
  permissions: "Permissions",
  yara:        "YARA Rules",
  certificate: "Certificate",
  threat_intel:"Threat Intel",
  obfuscation: "Obfuscation",
  india_ioc:   "India IOC",
  strings:     "Strings",
};

const BREAKDOWN_MAX: Record<string, number> = {
  permissions: 25, yara: 30, certificate: 15,
  threat_intel: 25, obfuscation: 15, india_ioc: 20, strings: 15,
};

interface Props { risk: Risk }

export default function RiskScoreCard({ risk }: Props) {
  const cfg = LEVEL_CONFIG[risk.risk_level] ?? LEVEL_CONFIG.SAFE;
  const pct = risk.score;
  const circ = 2 * Math.PI * 54; // r=54
  const dash = circ - (pct / 100) * circ;

  return (
    <div className="card-surface p-6 rounded-2xl space-y-6" style={{ boxShadow: `0 0 30px ${cfg.glow}` }}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-indigo-400" />
          <h2 className="font-semibold text-slate-200">Risk Assessment</h2>
        </div>
        <span
          className={`text-xs font-bold px-2.5 py-1 rounded-full risk-badge-${risk.risk_level.toLowerCase()}`}
        >
          {cfg.label}
        </span>
      </div>

      {/* Circular score */}
      <div className="flex flex-col items-center gap-3">
        <svg width="128" height="128" viewBox="0 0 128 128">
          {/* Track */}
          <circle cx="64" cy="64" r="54" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="10" />
          {/* Score arc */}
          <circle
            cx="64" cy="64" r="54"
            fill="none"
            stroke={cfg.color}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={dash}
            transform="rotate(-90 64 64)"
            style={{ filter: `drop-shadow(0 0 6px ${cfg.color})`, transition: "stroke-dashoffset 0.8s ease" }}
          />
          <text x="64" y="60" textAnchor="middle" fill={cfg.color} fontSize="26" fontWeight="700" fontFamily="var(--font-mono)">
            {pct}
          </text>
          <text x="64" y="78" textAnchor="middle" fill="#64748b" fontSize="10" fontFamily="var(--font-mono)">
            / 100
          </text>
        </svg>

        {/* Threat categories */}
        {risk.threat_categories.length > 0 && (
          <div className="flex flex-wrap justify-center gap-1.5">
            {risk.threat_categories.map((cat) => (
              <span
                key={cat}
                className="text-xs px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-300 border border-rose-500/20"
              >
                {cat}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Score breakdown bars */}
      <div className="space-y-2.5">
        <p className="text-xs text-slate-300 flex items-center gap-1.5">
          <TrendingUp className="w-3.5 h-3.5" /> Score Breakdown
        </p>
        {Object.entries(risk.breakdown).map(([key, val]) => {
          const max = BREAKDOWN_MAX[key] ?? 30;
          const pctBar = Math.round((val / max) * 100);
          return (
            <div key={key} className="flex items-center gap-3">
              <span className="text-xs text-slate-200 w-24 shrink-0">{BREAKDOWN_LABELS[key] ?? key}</span>
              <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{
                    width: `${pctBar}%`,
                    background: pctBar > 66 ? cfg.color : pctBar > 33 ? "#fbbf24" : "#4ade80",
                  }}
                />
              </div>
              <span className="text-xs font-mono text-slate-300 w-8 text-right">{val}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
