"use client";

import { useState, useRef } from "react";
import {
  Globe, Wifi, AlertTriangle, Shield, Upload,
  ChevronDown, ChevronUp, Activity, Search, Zap,
  Radio, Server, Lock
} from "lucide-react";
import type { NetworkData } from "@/lib/types";

// ── Types ──────────────────────────────────────────────────────────────────

interface Props {
  analysisId: string;
  initialNetwork?: NetworkData | null;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api";

const riskColor = (risk: string) => ({
  CRITICAL: "text-danger bg-[rgba(244,63,94,0.1)] border-danger",
  HIGH:     "text-[#f97316] bg-[rgba(249,115,22,0.1)] border-[#f97316]",
  MEDIUM:   "text-[#eab308] bg-[rgba(234,179,8,0.1)] border-[#eab308]",
  LOW:      "text-[#22c55e] bg-[rgba(34,197,94,0.1)] border-[#22c55e]",
}[risk] ?? "text-muted bg-surface-raised border-border");

const portLabel = (p: number) =>
  ({80:"HTTP",443:"HTTPS",53:"DNS",22:"SSH",21:"FTP",
    8080:"HTTP-Alt",3306:"MySQL",5432:"PG",6379:"Redis",
    4444:"C2?",1337:"C2?",31337:"C2?"})[p] ?? String(p);

// ── Expandable Table ────────────────────────────────────────────────────────

function ExpandableTable({
  title, icon, badge, badgeColor, children, defaultExpanded = true,
}: {
  title: string; icon: React.ReactNode; badge?: string | number;
  badgeColor?: string; children: React.ReactNode; defaultExpanded?: boolean;
}) {
  const [open, setOpen] = useState(defaultExpanded);
  return (
    <div className="border border-border bg-surface-raised overflow-hidden glass-panel">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-surface-raised transition-colors border-b border-transparent data-[open=true]:border-border"
        data-open={open}
      >
        <div className="flex items-center gap-3 text-xs font-mono uppercase tracking-widest text-secondary">
          {icon}{title}
          {badge !== undefined && (
            <span className={`text-[0.6rem] px-2 py-0.5 font-bold border ${badgeColor ?? "bg-background text-muted border-border"}`}>
              {badge}
            </span>
          )}
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-muted" /> : <ChevronDown className="w-4 h-4 text-muted" />}
      </button>
      {open && <div className="px-4 pb-4 pt-2 bg-background/50">{children}</div>}
    </div>
  );
}

// ── PCAP Upload Zone ────────────────────────────────────────────────────────

function PcapUploadZone({ analysisId, onSuccess }: { analysisId: string; onSuccess: (data: NetworkData) => void }) {
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState("");
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = async (file: File) => {
    if (!file.name.match(/\.(pcap|pcapng)$/i)) {
      setError("Only .pcap and .pcapng files are accepted.");
      return;
    }
    setError(null);
    setUploading(true);
    setProgress("[ UPLOADING PCAP ]");

    try {
      const form = new FormData();
      form.append("file", file);
      form.append("analysis_id", analysisId);

      const res = await fetch(`${API_BASE}/upload/pcap`, { method: "POST", body: form });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail ?? "Upload failed");
      }
      const data = await res.json();
      setProgress("[ ANALYSIS COMPLETE ]");
      onSuccess(data.network as NetworkData);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div
      className={`relative border border-dashed p-10 flex flex-col items-center gap-4 transition-all cursor-pointer select-none corner-brackets
        ${dragging ? "border-primary bg-[rgba(0,237,63,0.05)]" : "border-border hover:border-primary bg-surface-raised"}`}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
      onClick={() => inputRef.current?.click()}
    >
      <input ref={inputRef} type="file" accept=".pcap,.pcapng" className="hidden"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />

      <div className="w-12 h-12 bg-background border border-border flex items-center justify-center">
        {uploading
          ? <Activity className="w-5 h-5 text-primary animate-pulse" />
          : <Upload className="w-5 h-5 text-muted" />}
      </div>

      <div className="text-center font-mono">
        <p className="text-secondary font-semibold text-xs uppercase tracking-widest mb-1">
          {uploading ? progress : "[ UPLOAD PCAP FOR NETWORK ANALYSIS ]"}
        </p>
        <p className="text-muted text-[0.65rem] uppercase tracking-widest">
          {uploading ? "Analyzing packets, detecting beaconing…"
            : "Drag & drop or click — .pcap / .pcapng up to 200 MB"}
        </p>
      </div>

      {error && (
        <div className="w-full bg-[rgba(244,63,94,0.1)] border border-[rgba(244,63,94,0.3)] px-4 py-2 text-danger text-xs font-mono uppercase text-center">
          [ ERR: {error} ]
        </div>
      )}
    </div>
  );
}

// ── Main Panel ──────────────────────────────────────────────────────────────

export default function NetworkTrafficPanel({ analysisId, initialNetwork }: Props) {
  const [network, setNetwork] = useState<NetworkData | null>(initialNetwork ?? null);
  const [search, setSearch] = useState("");

  if (!network) {
    return (
      <div className="space-y-4 glass-panel p-6">
        <div className="flex items-center gap-3">
          <Globe className="w-5 h-5 text-primary" />
          <h2 className="text-lg font-bold text-secondary uppercase font-mono tracking-tight">Network Traffic Analysis</h2>
        </div>
        <p className="text-muted text-sm mb-4">
          Upload a PCAP capture from this device to analyze network behavior,
          detect C2 beaconing, DGA domains, and India IOC matches.
        </p>
        <PcapUploadZone analysisId={analysisId} onSuccess={setNetwork} />
      </div>
    );
  }

  if (!network.available) {
    return (
      <div className="glass-panel border border-border p-6 text-center space-y-3 bg-surface-raised">
        <AlertTriangle className="w-8 h-8 text-[#eab308] mx-auto" />
        <p className="text-secondary font-mono uppercase text-sm tracking-widest">[ PCAP Analysis Unavailable ]</p>
        <p className="text-muted text-xs font-mono">{network.error ?? "Unknown error"}</p>
      </div>
    );
  }

  const { summary, beaconing_alerts, dga_suspects, india_ioc_hits,
          dns_queries, http_hosts, remote_ips, tls_sni } = network;

  const filteredDns = dns_queries.filter(d =>
    !search || d.domain.toLowerCase().includes(search.toLowerCase()));
  const filteredIps = remote_ips.filter(r =>
    !search || r.ip.includes(search));

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 border-b border-border">
        <div className="flex items-center gap-3">
          <Globe className="w-5 h-5 text-primary" />
          <h2 className="text-lg font-bold text-secondary uppercase tracking-tight font-mono">Network Traffic Analysis</h2>
          <span className={`text-[0.65rem] font-bold px-3 py-1 border uppercase tracking-widest ${riskColor(network.pcap_risk)}`}>
            {network.pcap_risk}
          </span>
        </div>
        <button
          onClick={() => setNetwork(null)}
          className="text-[0.65rem] font-mono text-muted hover:text-secondary uppercase tracking-widest transition-colors"
        >
          [ UPLOAD NEW PCAP ]
        </button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        {[
          { label: "Packets",      value: summary.total_packets.toLocaleString(),  icon: <Wifi className="w-3.5 h-3.5" />,      color: "text-primary" },
          { label: "Remote IPs",   value: summary.unique_remote_ips,               icon: <Server className="w-3.5 h-3.5" />,    color: "text-[#0ea5e9]" },
          { label: "DNS Queries",  value: summary.dns_query_count,                 icon: <Search className="w-3.5 h-3.5" />,    color: "text-[#06b6d4]" },
          { label: "Beacons",      value: summary.beaconing_alerts,                icon: <Radio className="w-3.5 h-3.5" />,     color: summary.beaconing_alerts > 0 ? "text-danger" : "text-[#22c55e]" },
          { label: "India IOC",    value: summary.india_hits,                      icon: <Shield className="w-3.5 h-3.5" />,    color: summary.india_hits > 0 ? "text-danger" : "text-[#22c55e]" },
        ].map(card => (
          <div key={card.label} className="bg-surface-raised border border-border p-4 flex flex-col gap-2 corner-brackets group hover:border-border transition-colors">
            <div className={`flex items-center gap-2 text-[0.65rem] font-mono uppercase tracking-widest ${card.color}`}>
              {card.icon}{card.label}
            </div>
            <p className="text-2xl font-bold text-secondary font-mono">{card.value}</p>
          </div>
        ))}
      </div>

      {/* Beaconing Alerts */}
      {beaconing_alerts.length > 0 && (
        <ExpandableTable
          title="C2 Beaconing Alerts"
          icon={<Radio className="w-4 h-4 text-danger" />}
          badge={beaconing_alerts.length}
          badgeColor="bg-[rgba(244,63,94,0.1)] text-danger border-danger"
        >
          <div className="space-y-3 pt-2">
            {beaconing_alerts.map((a, i) => (
              <div key={i} className="bg-surface-raised border border-border border-l-2 border-l-[#f43f5e] p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm text-danger font-semibold">{a.ip}</span>
                  <span className={`text-[0.65rem] px-2 py-0.5 font-bold border uppercase tracking-widest ${
                    a.confidence === "HIGH"
                      ? "bg-[rgba(244,63,94,0.1)] text-danger border-danger"
                      : "bg-[rgba(249,115,22,0.1)] text-[#f97316] border-[#f97316]"
                  }`}>
                    {a.confidence} CONFIDENCE
                  </span>
                </div>
                <p className="text-xs text-muted font-mono">{a.description}</p>
                <div className="flex gap-4 text-[0.65rem] text-muted font-mono uppercase tracking-widest border-t border-border pt-2">
                  <span>Contacts: <span className="text-secondary">{a.contact_count}</span></span>
                  <span>Interval: <span className="text-secondary">~{a.avg_interval_sec}s</span></span>
                  <span>Jitter CV: <span className="text-secondary">{a.jitter_cv}</span></span>
                </div>
              </div>
            ))}
          </div>
        </ExpandableTable>
      )}

      {/* India IOC Hits */}
      {india_ioc_hits.length > 0 && (
        <ExpandableTable
          title="India IOC Matches"
          icon={<Shield className="w-4 h-4 text-[#f97316]" />}
          badge={india_ioc_hits.length}
          badgeColor="bg-[rgba(249,115,22,0.1)] text-[#f97316] border-[#f97316]"
        >
          <div className="space-y-2 pt-2">
            {india_ioc_hits.map((hit, i) => (
              <div key={i} className="flex items-start justify-between gap-4 bg-surface-raised border border-border p-4 border-l-2 border-l-[#f97316]">
                <div>
                  <span className="font-mono text-sm text-[#f97316] font-semibold block mb-1">{hit.value}</span>
                  <span className="text-[0.65rem] text-muted font-mono uppercase tracking-widest">{hit.reason}</span>
                </div>
                <span className={`shrink-0 text-[0.6rem] px-2 py-0.5 font-bold border uppercase tracking-widest ${riskColor(hit.severity)}`}>
                  {hit.severity}
                </span>
              </div>
            ))}
          </div>
        </ExpandableTable>
      )}

      {/* DGA Suspects */}
      {dga_suspects.length > 0 && (
        <ExpandableTable
          title="Suspected DGA Domains"
          icon={<Zap className="w-4 h-4 text-[#eab308]" />}
          badge={dga_suspects.length}
          badgeColor="bg-[rgba(234,179,8,0.1)] text-[#eab308] border-[#eab308]"
        >
          <div className="pt-2 overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b border-border text-[0.65rem] uppercase tracking-widest text-muted">
                  <th className="text-left py-2 font-medium">Domain</th>
                  <th className="text-right py-2 font-medium">Queries</th>
                  <th className="text-right py-2 font-medium">Entropy</th>
                </tr>
              </thead>
              <tbody>
                {dga_suspects.map((d, i) => (
                  <tr key={i} className="border-b border-border hover:bg-surface-raised">
                    <td className="py-2 text-[#eab308] break-all">{d.domain}</td>
                    <td className="py-2 text-right text-secondary">{d.query_count}</td>
                    <td className="py-2 text-right text-[#f97316] font-bold">{d.entropy}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </ExpandableTable>
      )}

      {/* Search */}
      <div className="relative border border-border bg-surface-raised">
        <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
        <input
          type="text"
          placeholder="FILTER IPS, DOMAINS…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full pl-12 pr-4 py-3 bg-transparent text-[0.65rem] font-mono tracking-widest uppercase text-secondary placeholder-[#555] focus:outline-none focus:border-primary"
        />
      </div>

      {/* DNS Queries */}
      <ExpandableTable
        title="DNS Queries"
        icon={<Search className="w-4 h-4 text-[#06b6d4]" />}
        badge={summary.dns_query_count}
        defaultExpanded={false}
      >
        <div className="pt-2 max-h-72 overflow-y-auto space-y-1 pr-2 custom-scrollbar">
          {filteredDns.slice(0, 100).map((d, i) => (
            <div key={i} className="flex items-center justify-between py-2 border-b border-border hover:bg-surface-raised px-2 font-mono">
              <span className="text-[0.65rem] text-[#aaa] break-all">{d.domain}</span>
              <span className="text-[0.65rem] text-muted shrink-0 ml-4 border border-border px-1 bg-background">{d.count}×</span>
            </div>
          ))}
        </div>
      </ExpandableTable>

      {/* TLS SNI */}
      {tls_sni.length > 0 && (
        <ExpandableTable
          title="TLS / HTTPS Hosts (SNI)"
          icon={<Lock className="w-4 h-4 text-[#22c55e]" />}
          badge={tls_sni.length}
          defaultExpanded={false}
        >
          <div className="pt-2 flex flex-wrap gap-2">
            {tls_sni.map((sni, i) => (
              <span key={i} className="font-mono text-[0.65rem] bg-surface-raised text-[#aaa] px-2 py-1 border border-border">
                {sni}
              </span>
            ))}
          </div>
        </ExpandableTable>
      )}

      {/* HTTP Hosts */}
      {http_hosts.length > 0 && (
        <ExpandableTable
          title="HTTP Hosts"
          icon={<Globe className="w-4 h-4 text-primary" />}
          badge={http_hosts.length}
          defaultExpanded={false}
        >
          <div className="pt-2 max-h-60 overflow-y-auto space-y-1 pr-2 custom-scrollbar">
            {http_hosts.map((h, i) => (
              <div key={i} className="flex items-center justify-between py-2 border-b border-border hover:bg-surface-raised px-2 font-mono">
                <span className="text-[0.65rem] text-[#aaa] break-all">{h.host}</span>
                <span className="text-[0.65rem] text-muted shrink-0 ml-4 border border-border px-1 bg-background">{h.count}×</span>
              </div>
            ))}
          </div>
        </ExpandableTable>
      )}

      {/* Remote IPs */}
      <ExpandableTable
        title="Remote IP Connections"
        icon={<Server className="w-4 h-4 text-[#0ea5e9]" />}
        badge={summary.unique_remote_ips}
        defaultExpanded={false}
      >
        <div className="pt-2 overflow-x-auto">
          <table className="w-full text-[0.65rem] font-mono">
            <thead>
              <tr className="border-b border-border uppercase tracking-widest text-muted">
                <th className="text-left py-2 font-medium">IP</th>
                <th className="text-right py-2 font-medium">Packets</th>
                <th className="text-left py-2 pl-6 font-medium">Ports</th>
                <th className="text-right py-2 font-medium">First seen</th>
              </tr>
            </thead>
            <tbody>
              {filteredIps.slice(0, 50).map((r, i) => (
                <tr key={i} className="border-b border-border hover:bg-surface-raised">
                  <td className="py-3">
                    <span className="text-[#0ea5e9] block">{r.ip}</span>
                    {r.static_files && r.static_files.length > 0 && (
                      <div className="mt-1 flex flex-col gap-1">
                        {r.static_files.map((file: string, idx: number) => (
                          <span key={idx} className="text-[0.55rem] text-[#22c55e] bg-[rgba(34,197,94,0.1)] border border-[rgba(34,197,94,0.3)] px-1 py-0.5 max-w-[200px] truncate block" title={file}>
                            FOUND IN: {file.split('/').pop()}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="py-3 text-right text-secondary align-top">{r.count.toLocaleString()}</td>
                  <td className="py-3 pl-6 align-top">
                    <div className="flex flex-wrap gap-1.5">
                      {r.ports.slice(0, 6).map(p => (
                        <span key={p} className={`px-1.5 py-0.5 border uppercase tracking-widest ${
                          [4444,1337,31337].includes(p)
                            ? "bg-[rgba(244,63,94,0.1)] text-danger border-danger"
                            : "bg-background text-muted border-border"
                        }`}>
                          {portLabel(p)}
                        </span>
                      ))}
                      {r.ports.length > 6 && <span className="text-muted border border-transparent px-1 flex items-center">+{r.ports.length - 6}</span>}
                    </div>
                  </td>
                  <td className="py-3 text-right text-muted whitespace-nowrap">
                    {r.first_seen.slice(0,10)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </ExpandableTable>
    </div>
  );
}
