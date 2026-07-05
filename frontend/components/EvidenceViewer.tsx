import { FileCode2, MapPin, Fingerprint } from "lucide-react";

export interface Evidence {
  file: string;
  line?: number;
  offset?: string;
  context?: string;
  matched?: string;
}

interface Props {
  evidence: Evidence;
  risk?: string;
}

export default function EvidenceViewer({ evidence, risk = "high" }: Props) {
  if (!evidence) return null;
  const borderColor = risk === "high" ? "border-rose-500/30" : risk === "medium" ? "border-yellow-500/30" : "border-slate-700";
  const bgColor = risk === "high" ? "bg-rose-500/5" : risk === "medium" ? "bg-yellow-500/5" : "bg-slate-800/50";
  const iconColor = risk === "high" ? "text-rose-400" : risk === "medium" ? "text-yellow-400" : "text-slate-400";

  return (
    <div className={`mt-3 rounded-lg border ${borderColor} ${bgColor} p-4 space-y-3`}>
      <div className="flex flex-wrap items-center gap-4 text-sm">
        <div className="flex items-center gap-1.5 text-slate-200 font-medium break-all">
          <FileCode2 className={`w-4 h-4 shrink-0 ${iconColor}`} />
          {evidence.file}
        </div>
        
        {evidence.line && (
          <div className="flex items-center gap-1.5 text-slate-400 shrink-0">
            <MapPin className="w-3.5 h-3.5" />
            Line {evidence.line}
          </div>
        )}

        {evidence.offset && (
          <div className="flex items-center gap-1.5 text-slate-400 shrink-0">
            <MapPin className="w-3.5 h-3.5" />
            Offset: {evidence.offset}
          </div>
        )}
      </div>

      {(evidence.context || evidence.matched) && (
        <div className="rounded bg-[#0d1117] border border-slate-800/60 p-3 overflow-x-auto shadow-inner">
          <div className="flex items-center gap-2 mb-2 pb-2 border-b border-slate-800">
            <Fingerprint className="w-3.5 h-3.5 text-slate-500" />
            <span className="text-xs text-slate-500 font-semibold uppercase tracking-wider">
              {evidence.context ? "Source Context" : "Matched Bytes"}
            </span>
          </div>
          <pre className="text-xs font-mono text-slate-300 leading-relaxed">
            <code>{evidence.context || evidence.matched}</code>
          </pre>
        </div>
      )}
    </div>
  );
}
