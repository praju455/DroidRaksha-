import type { Strings } from "@/lib/types";
import { Link2, Globe, Code2, Search } from "lucide-react";
import { useState } from "react";
import EvidenceViewer, { Evidence } from "./EvidenceViewer";

interface Props { strings: Strings }

const RISK_COLORS = {
  high:   "text-rose-400",
  medium: "text-yellow-400",
  low:    "text-slate-200",
};

export default function StringsTable({ strings }: Props) {
  const allUrls = strings.urls ?? [];
  const allIps  = strings.ips ?? [];
  const susp    = strings.suspicious_strings ?? [];

  return (
    <div className="card-surface p-6 rounded-2xl space-y-5">
      <div className="flex items-center gap-2">
        <Code2 className="w-5 h-5 text-cyan-400" />
        <h2 className="font-semibold text-slate-200">Extracted Strings</h2>
      </div>

      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "URLs",        count: allUrls.length,  color: "text-indigo-400" },
          { label: "IP Addresses",count: allIps.length,   color: "text-cyan-400"   },
          { label: "Suspicious",  count: susp.length,     color: "text-rose-400"   },
        ].map(({ label, count, color }) => (
          <div key={label} className="rounded-lg p-3 bg-slate-800/60 text-center">
            <p className={`text-xl font-bold font-mono ${color}`}>{count}</p>
            <p className="text-xs text-slate-300 mt-0.5">{label}</p>
          </div>
        ))}
      </div>

      {allUrls.length > 0 && (
        <Section title="URLs" icon={<Link2 className="w-3.5 h-3.5 text-indigo-400" />}>
          {allUrls.slice(0, 15).map((u: any, i) => (
            <Row key={i} value={u.value} risk={u.risk} evidence={u.evidence} />
          ))}
          {allUrls.length > 15 && (
            <p className="text-xs text-slate-200 italic">+{allUrls.length - 15} more URLs…</p>
          )}
        </Section>
      )}

      {allIps.length > 0 && (
        <Section title="IP Addresses" icon={<Globe className="w-3.5 h-3.5 text-cyan-400" />}>
          {allIps.map((ip: any, i) => (
            <Row key={i} value={ip.value} risk={ip.risk} evidence={ip.evidence} />
          ))}
        </Section>
      )}

      {susp.length > 0 && (
        <Section title="Suspicious Strings" icon={<Code2 className="w-3.5 h-3.5 text-rose-400" />}>
          {susp.slice(0, 10).map((s: any, i) => (
            <Row key={i} value={s.value} risk={s.risk ?? "high"} evidence={s.evidence} />
          ))}
        </Section>
      )}
    </div>
  );
}

function Section({
  title,
  icon,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-2">
      <p className="text-xs text-slate-300 flex items-center gap-1.5 uppercase tracking-wider font-medium">
        {icon} {title}
      </p>
      <div className="space-y-1">{children}</div>
    </div>
  );
}

function Row({ value, risk, evidence }: { value: string; risk?: string; evidence?: Evidence }) {
  const [showEvidence, setShowEvidence] = useState(false);
  const color = RISK_COLORS[(risk as keyof typeof RISK_COLORS) ?? "low"] ?? "text-slate-200";
  
  return (
    <div className="flex flex-col">
      <div className="flex items-center gap-2 rounded px-2 py-1 hover:bg-white/[0.02] transition-colors">
        <span className={`font-mono text-xs break-all ${color}`}>{value}</span>
        
        <div className="ml-auto flex items-center gap-2 shrink-0">
          {evidence && (
            <button
              onClick={() => setShowEvidence(!showEvidence)}
              className="flex items-center gap-1.5 px-2 py-0.5 rounded border border-slate-700 bg-slate-800 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
            >
              <Search className="w-3 h-3" />
              Evidence
            </button>
          )}
          {risk === "high" && (
            <span className="text-xs px-1.5 rounded bg-rose-500/10 text-rose-400">High</span>
          )}
        </div>
      </div>
      
      {showEvidence && evidence && (
        <div className="px-2 pb-2">
          <EvidenceViewer evidence={evidence} risk={risk} />
        </div>
      )}
    </div>
  );
}
