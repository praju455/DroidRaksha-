import type { 
  Risk, 
  DynamicSandbox, 
  MLClassification, 
  XGBoostResult, 
  MalBERTResult, 
  NetworkData, 
  Strings 
} from "@/lib/types";
import { Shield, TrendingUp, Cpu, Zap, Brain, Target, Box, AlertTriangle } from "lucide-react";

const LEVEL_CONFIG: Record<string, { color: string; glow: string; label: string }> = {
  CRITICAL: { color: "#f43f5e", glow: "rgba(244,63,94,0.3)", label: "CRITICAL" },
  HIGH:     { color: "#f97316", glow: "rgba(249,115,22,0.3)", label: "HIGH" },
  MEDIUM:   { color: "#fbbf24", glow: "rgba(251,191,36,0.3)", label: "MEDIUM" },
  LOW:      { color: "#4ade80", glow: "rgba(74,222,128,0.3)", label: "LOW" },
  SAFE:     { color: "#22d3ee", glow: "rgba(34,211,238,0.3)", label: "SAFE" },
};

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

interface Props {
  risk: Risk;
  dynamic?: DynamicSandbox;
  mlClassification?: MLClassification;
  xgboost?: XGBoostResult;
  malbert?: MalBERTResult;
  network?: NetworkData;
  strings?: Strings;
}

export default function RiskScoreCard({ risk, dynamic, mlClassification, xgboost, malbert, network, strings }: Props) {
  // Calculate weights and scores
  let wSandbox = 30;
  let wStatic = 25;
  let wDNN = 20;
  let wML = 15;
  let wHeuristic = 10;
  
  let dynamicC2ModifierTriggered = false;
  let sandboxScoreBoost = 0;

  // Cross-correlate dynamic network IPs vs static IPs
  const staticIps = new Set((strings?.ips ?? []).map(ip => ip.value));
  let dynamicNetworkIps: string[] = [];
  
  if (network?.remote_ips) {
     dynamicNetworkIps = network.remote_ips.map(f => f.ip).filter(Boolean) as string[];
  }
  
  for (const dip of dynamicNetworkIps) {
    if (dip && !staticIps.has(dip)) {
       dynamicC2ModifierTriggered = true;
       break;
    }
  }

  // Apply C2 Modifier
  if (dynamicC2ModifierTriggered && dynamic?.sandbox_available) {
     wSandbox = 40;
     wStatic = 15; // Steal 10% from static
     sandboxScoreBoost = 15;
  }
  
  // Redistribute if Sandbox is unavailable
  if (!dynamic?.sandbox_available) {
     wSandbox = 0;
     wStatic = 35;
     wDNN = 30;
     wML = 20;
     wHeuristic = 15;
  }

  // Get raw scores
  const scoreStatic = risk.score ?? 0;
  let scoreSandbox = (dynamic?.behavioral_score?.score ?? 0) + sandboxScoreBoost;
  if (scoreSandbox > 100) scoreSandbox = 100;
  
  const scoreHeuristic = mlClassification?.confidence ?? 0;
  const scoreML = xgboost?.available ? Math.round((xgboost?.probability ?? 0) * 100) : 0;
  const scoreDNN = malbert?.available ? Math.round((malbert?.confidence ?? 0) * 100) : 0;
  
  let totalWeight = wStatic + wSandbox;
  if (mlClassification) totalWeight += wHeuristic; else wHeuristic = 0;
  if (xgboost?.available) totalWeight += wML; else wML = 0;
  if (malbert?.available) totalWeight += wDNN; else wDNN = 0;
  
  const weightedSum = (scoreStatic * wStatic) + (scoreSandbox * wSandbox) + (scoreHeuristic * wHeuristic) + (scoreML * wML) + (scoreDNN * wDNN);
  const ensembleScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : scoreStatic;
  
  // Determine new risk level
  let finalRiskLevel = risk.risk_level;
  if (ensembleScore >= 80) finalRiskLevel = "CRITICAL";
  else if (ensembleScore >= 60) finalRiskLevel = "HIGH";
  else if (ensembleScore >= 40) finalRiskLevel = "MEDIUM";
  else if (ensembleScore >= 20) finalRiskLevel = "LOW";
  else finalRiskLevel = "SAFE";

  const cfg = LEVEL_CONFIG[finalRiskLevel] ?? LEVEL_CONFIG.SAFE;
  
  // SVG config
  const pct = ensembleScore;
  const circ = 2 * Math.PI * 54;
  const dash = circ - (pct / 100) * circ;

  return (
    <div className="card-surface p-6 rounded-2xl space-y-6" style={{ boxShadow: `0 0 30px ${cfg.glow}` }}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5" style={{ color: cfg.color }} />
          <h2 className="font-semibold text-slate-200 text-sm">Combined Risk Score</h2>
        </div>
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border border-white/20`} style={{ backgroundColor: cfg.glow, color: cfg.color }}>
          {cfg.label}
        </span>
      </div>

      {/* Circular score */}
      <div className="flex flex-col items-center gap-2">
        <svg width="128" height="128" viewBox="0 0 128 128">
          <circle cx="64" cy="64" r="54" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="10" />
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

        <p className="text-[10px] text-slate-400 font-mono tracking-widest uppercase mt-2">Ensemble Ratio</p>
      </div>

      {/* Detection Layers Breakdown */}
      <div className="space-y-3 pt-2">
        <p className="text-xs text-slate-300 flex items-center gap-1.5 font-semibold">
          <Cpu className="w-3.5 h-3.5 text-indigo-400" /> Detection Layers
        </p>
        
        {/* Static Analysis */}
        <div className="flex items-center gap-3 group">
           <Shield className="w-3.5 h-3.5 text-slate-400" />
           <span className="text-[10px] text-slate-200 w-32 shrink-0 flex items-center gap-1">
              Static Rules 
              <span className="text-[8px] text-slate-500 bg-slate-800 px-1 rounded">{wStatic}%</span>
           </span>
           <div className="flex-1 h-1 bg-slate-800 rounded-full overflow-hidden">
              <div className="h-full bg-slate-400 rounded-full transition-all duration-700" style={{ width: `${scoreStatic}%` }} />
           </div>
           <span className="text-[10px] font-mono text-slate-300 w-8 text-right">{scoreStatic}</span>
        </div>

        {/* Sandbox */}
        {dynamic?.sandbox_available && (
          <div className="flex items-center gap-3 group">
             {dynamicC2ModifierTriggered ? <AlertTriangle className="w-3.5 h-3.5 text-rose-500 animate-pulse" /> : <Box className="w-3.5 h-3.5 text-emerald-400" />}
             <span className="text-[10px] text-slate-200 w-32 shrink-0 flex items-center gap-1">
               Sandbox 
               <span className={`text-[8px] px-1 rounded ${dynamicC2ModifierTriggered ? 'text-rose-400 border border-rose-500/30 bg-rose-500/10' : 'text-emerald-500 bg-emerald-500/10'}`}>
                 {dynamicC2ModifierTriggered ? "C2 MODIFIER" : `${wSandbox}%`}
               </span>
             </span>
             <div className="flex-1 h-1 bg-slate-800 rounded-full overflow-hidden">
                <div className={`h-full rounded-full transition-all duration-700 ${dynamicC2ModifierTriggered ? 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]' : 'bg-emerald-400'}`} style={{ width: `${scoreSandbox}%` }} />
             </div>
             <span className="text-[10px] font-mono text-slate-300 w-8 text-right">{scoreSandbox}</span>
          </div>
        )}
        
        {/* DNN */}
        {malbert?.available && (
          <div className="flex items-center gap-3 group">
             <Brain className="w-3.5 h-3.5 text-cyan-400" />
             <span className="text-[10px] text-slate-200 w-32 shrink-0 flex items-center gap-1">
               Deep Neural Net
               <span className="text-[8px] text-cyan-500 bg-cyan-500/10 px-1 rounded">{wDNN}%</span>
             </span>
             <div className="flex-1 h-1 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-cyan-400 rounded-full transition-all duration-700" style={{ width: `${scoreDNN}%` }} />
             </div>
             <span className="text-[10px] font-mono text-slate-300 w-8 text-right">{scoreDNN}</span>
          </div>
        )}

        {/* Static ML */}
        {xgboost?.available && (
          <div className="flex items-center gap-3 group">
             <Zap className="w-3.5 h-3.5 text-indigo-400" />
             <span className="text-[10px] text-slate-200 w-32 shrink-0 flex items-center gap-1">
               Static ML
               <span className="text-[8px] text-indigo-400 bg-indigo-500/10 px-1 rounded">{wML}%</span>
             </span>
             <div className="flex-1 h-1 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-indigo-400 rounded-full transition-all duration-700" style={{ width: `${scoreML}%` }} />
             </div>
             <span className="text-[10px] font-mono text-slate-300 w-8 text-right">{scoreML}</span>
          </div>
        )}

        {/* Heuristic Engine */}
        {mlClassification && (
          <div className="flex items-center gap-3 group">
             <Target className="w-3.5 h-3.5 text-orange-400" />
             <span className="text-[10px] text-slate-200 w-32 shrink-0 flex items-center gap-1">
               Heuristic Engine
               <span className="text-[8px] text-orange-400 bg-orange-500/10 px-1 rounded">{wHeuristic}%</span>
             </span>
             <div className="flex-1 h-1 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-orange-400 rounded-full transition-all duration-700" style={{ width: `${scoreHeuristic}%` }} />
             </div>
             <span className="text-[10px] font-mono text-slate-300 w-8 text-right">{scoreHeuristic}</span>
          </div>
        )}
      </div>

      {/* Legacy Static Score breakdown bars (Keep for detailed view) */}
      <div className="space-y-2.5 pt-4 border-t border-white/5">
        <p className="text-xs text-slate-400 flex items-center gap-1.5 font-semibold">
          <TrendingUp className="w-3.5 h-3.5" /> Static Features Breakdown
        </p>
        {Object.entries(risk.breakdown).map(([key, val]) => {
          const max = BREAKDOWN_MAX[key] ?? 30;
          const pctBar = Math.round((val / max) * 100);
          return (
            <div key={key} className="flex items-center gap-3 opacity-60 hover:opacity-100 transition-opacity">
              <span className="text-[10px] text-slate-300 w-24 shrink-0">{BREAKDOWN_LABELS[key] ?? key}</span>
              <div className="flex-1 h-1 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{
                    width: `${pctBar}%`,
                    background: pctBar > 66 ? "#f43f5e" : pctBar > 33 ? "#fbbf24" : "#4ade80",
                  }}
                />
              </div>
              <span className="text-[10px] font-mono text-slate-400 w-8 text-right">{val}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
