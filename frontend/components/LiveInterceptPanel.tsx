"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import {
  Wifi, Radio, Play, Square, AlertTriangle, Shield,
  ShieldAlert, ShieldCheck, Lock, Globe, Zap, Activity,
  Server, ChevronDown, ChevronUp, Terminal, Clock,
} from "lucide-react";
import type { InterceptFlow, InterceptCorrelation, CorrelatedIP } from "@/lib/types";

// Use relative path so Next.js rewrite proxy handles routing in both dev and Docker.
// next.config.mjs rewrites /api/* → http://backend:8000/api/*
const API_BASE = "/api";


// ── Types ──────────────────────────────────────────────────────────────────

interface Props {
  analysisId: string;
  staticIps?: Array<{ type: string; value: string; risk: string }>;
}

interface SessionState {
  running: boolean;
  elapsed_sec: number;
  remaining_sec: number;
  duration_sec: number;
  flow_count: number;
  flows: InterceptFlow[];
  correlation: InterceptCorrelation | null;
}

// ── Helpers ────────────────────────────────────────────────────────────────

const riskGradient: Record<string, string> = {
  CRITICAL: "from-[rgba(244,63,94,0.15)] to-transparent border-[rgba(244,63,94,0.5)]",
  HIGH:     "from-[rgba(249,115,22,0.15)] to-transparent border-[rgba(249,115,22,0.5)]",
  MEDIUM:   "from-[rgba(251,191,36,0.12)] to-transparent border-[rgba(251,191,36,0.4)]",
  LOW:      "from-[rgba(34,197,94,0.1)]  to-transparent border-[rgba(34,197,94,0.3)]",
};

const riskText: Record<string, string> = {
  CRITICAL: "text-[#f43f5e]",
  HIGH:     "text-[#f97316]",
  MEDIUM:   "text-[#fbbf24]",
  LOW:      "text-[#22c55e]",
};

const verdictConfig = {
  CONFIRMED_C2: {
    label:  "CONFIRMED C2",
    color:  "text-[#f43f5e]",
    bg:     "bg-[rgba(244,63,94,0.1)]",
    border: "border-[rgba(244,63,94,0.4)]",
    pulse:  true,
    icon:   ShieldAlert,
  },
  STATIC_ONLY: {
    label:  "ENCODED ONLY",
    color:  "text-[#fbbf24]",
    bg:     "bg-[rgba(251,191,36,0.08)]",
    border: "border-[rgba(251,191,36,0.3)]",
    pulse:  false,
    icon:   Shield,
  },
  LIVE_ONLY: {
    label:  "UNKNOWN EXTERNAL",
    color:  "text-[#f97316]",
    bg:     "bg-[rgba(249,115,22,0.08)]",
    border: "border-[rgba(249,115,22,0.3)]",
    pulse:  false,
    icon:   Globe,
  },
};

function formatTime(ts: number) {
  return new Date(ts * 1000).toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function statusColor(code: number) {
  if (code >= 500) return "text-[#f43f5e]";
  if (code >= 400) return "text-[#f97316]";
  if (code >= 300) return "text-[#fbbf24]";
  return "text-[#22c55e]";
}

// ── IP Correlation Side-by-Side Card ──────────────────────────────────────

function IPCorrelationCard({ ip }: { ip: CorrelatedIP }) {
  const cfg = verdictConfig[ip.verdict];
  const Icon = cfg.icon;
  return (
    <div className={`border ${cfg.border} ${cfg.bg} p-4 space-y-2 relative overflow-hidden`}>
      {cfg.pulse && (
        <span className="absolute top-3 right-3 flex gap-1 items-center">
          <span className="w-2 h-2 rounded-full bg-[#f43f5e] animate-ping absolute" />
          <span className="w-2 h-2 rounded-full bg-[#f43f5e]" />
        </span>
      )}
      <div className="flex items-center gap-2">
        <Icon className={`w-4 h-4 ${cfg.color} shrink-0`} />
        <span className={`text-[0.7rem] font-bold font-mono ${cfg.color} uppercase tracking-widest`}>
          {cfg.label}
        </span>
      </div>
      <p className={`font-mono text-sm font-black ${cfg.color}`}>{ip.ip}</p>
      <p className="text-[0.6rem] font-mono text-muted uppercase">{ip.label}</p>
      {ip.live_calls !== undefined && (
        <p className="text-[0.6rem] font-mono text-muted">
          {ip.live_calls} live calls · {ip.tls ? "🔒 TLS" : "HTTP"}
        </p>
      )}
      {ip.hosts && ip.hosts.length > 0 && (
        <p className="text-[0.6rem] font-mono text-[#22d3ee] truncate">
          {ip.hosts[0]}
        </p>
      )}
      {ip.urls && ip.urls.length > 0 && (
        <p className="text-[0.55rem] font-mono text-muted truncate opacity-70" title={ip.urls[0]}>
          {ip.urls[0].slice(0, 80)}
        </p>
      )}
    </div>
  );
}

// ── Live Flow Row ─────────────────────────────────────────────────────────

function FlowRow({ flow, isNew, confirmed }: { flow: InterceptFlow; isNew: boolean; confirmed: boolean }) {
  return (
    <div className={`flex items-center gap-2 py-1.5 px-3 border-b border-[rgba(255,255,255,0.04)] font-mono text-[0.6rem] 
      ${isNew ? "bg-[rgba(0,237,63,0.04)] animate-pulse-once" : ""}
      ${confirmed ? "border-l-2 border-l-[#f43f5e]" : "border-l-2 border-l-transparent"}`}
    >
      <span className="text-muted shrink-0 w-16">{flow.ts ? formatTime(flow.ts) : "--:--:--"}</span>
      <span className={`shrink-0 w-10 font-bold ${
        flow.method === "POST" ? "text-[#f97316]" :
        flow.method === "GET"  ? "text-[#22d3ee]" : "text-muted"
      }`}>{flow.method || "?"}</span>
      <span className="shrink-0">{flow.tls ? <Lock className="w-3 h-3 text-[#22c55e] inline" /> : <Globe className="w-3 h-3 text-muted inline" />}</span>
      <span className="flex-1 text-[#aaa] truncate" title={flow.url}>{flow.host}</span>
      <span className="text-muted shrink-0 w-24 text-right truncate">{flow.dst_ip || "—"}</span>
      <span className={`shrink-0 w-8 text-right font-bold ${statusColor(flow.status)}`}>
        {flow.status || "—"}
      </span>
      {confirmed && (
        <span className="shrink-0 text-[#f43f5e] text-[0.5rem] font-bold uppercase tracking-widest">C2</span>
      )}
    </div>
  );
}

// ── Countdown Timer ───────────────────────────────────────────────────────

function CountdownRing({ remaining, total }: { remaining: number; total: number }) {
  const elapsed = total - remaining;
  const pct = (elapsed / total) * 100;
  const r = 36;
  const circ = 2 * Math.PI * r;
  const stroke = circ * (pct / 100);
  // Color transitions from green to red as it fills up
  const color = pct < 50 ? "#00ed3f" : pct < 75 ? "#fbbf24" : "#f43f5e";
  return (
    <div className="relative flex items-center justify-center w-24 h-24">
      <svg className="absolute" width="96" height="96" viewBox="0 0 96 96">
        <circle cx="48" cy="48" r={r} stroke="#111" strokeWidth="6" fill="none" />
        <circle
          cx="48" cy="48" r={r}
          stroke={color}
          strokeWidth="6" fill="none"
          strokeDasharray={`${stroke} ${circ}`}
          strokeLinecap="round"
          style={{ transform: "rotate(-90deg)", transformOrigin: "48px 48px", transition: "stroke-dasharray 1s linear" }}
        />
      </svg>
      <div className="text-center z-10">
        <p className="text-lg font-black font-mono" style={{ color }}>{Math.floor(elapsed)}</p>
        <p className="text-[0.5rem] font-mono text-muted uppercase">sec</p>
      </div>
    </div>
  );
}

// ── Setup Guide ───────────────────────────────────────────────────────────
// ... skipping to the correlation section ...


function SetupGuide({ port }: { port: number }) {
  const [open, setOpen] = useState(false);
  const [hostIp, setHostIp] = useState("10.0.2.2");

  useEffect(() => {
    fetch(`${API_BASE}/intercept/status`)
      .then(r => r.json())
      .then(d => { if (d.host_ip) setHostIp(d.host_ip); })
      .catch(() => {});
  }, []);

  const cmds = [
    `adb shell settings put global http_proxy ${hostIp}:${port}`,
    `adb push %USERPROFILE%\\.mitmproxy\\mitmproxy-ca-cert.pem /data/local/tmp/`,
    `adb shell su -c "cp /data/local/tmp/mitmproxy-ca-cert.pem /system/etc/security/cacerts/c8750f0d.0"`,
    `adb shell su -c "chmod 644 /system/etc/security/cacerts/c8750f0d.0"`,
  ];

  return (
    <div className="border border-border bg-surface-raised">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-3 text-[0.65rem] font-mono uppercase tracking-widest text-muted hover:text-secondary transition-colors"
      >
        <span className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-primary" />
          [ EMULATOR PROXY SETUP — ONE TIME ]
        </span>
        {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
      </button>
      {open && (
        <div className="px-4 pb-4 border-t border-border space-y-3">
          <p className="text-[0.6rem] font-mono text-muted mt-3">
            Run these once in your terminal with the emulator running (rooted Google APIs image):
          </p>
          <div className="space-y-2">
            {cmds.map((cmd, i) => (
              <div key={i} className="bg-[#050505] border border-[#1a1a1a] p-3 font-mono text-[0.6rem] text-[#00ed3f] relative group">
                <span>{cmd}</span>
              </div>
            ))}
          </div>
          <p className="text-[0.55rem] font-mono text-muted">
            After setup, the mitmproxy CA certificate will be trusted system-wide.
            HTTPS traffic will be automatically decrypted. The certificate is already
            generated the first time you run mitmdump (session start creates it automatically).
          </p>
        </div>
      )}
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────

export default function LiveInterceptPanel({ analysisId, staticIps = [] }: Props) {
  const [status, setStatus] = useState<"idle" | "starting" | "running" | "done">("idle");
  const [error, setError] = useState<string | null>(null);
  const [session, setSession] = useState<SessionState | null>(null);
  const [port, setPort] = useState(8080);
  const [newFlowIndexes, setNewFlowIndexes] = useState<Set<number>>(new Set());
  const [showAllFlows, setShowAllFlows] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  // Get status + port on mount
  useEffect(() => {
    fetch(`${API_BASE}/intercept/status`)
      .then(r => r.json())
      .then(d => { if (d.mitm_port) setPort(d.mitm_port); })
      .catch(() => {});
  }, []);

  // Auto-scroll live log
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [session?.flows.length]);

  const connectSSE = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }
    const es = new EventSource(`${API_BASE}/intercept/${analysisId}/stream`);
    eventSourceRef.current = es;

    es.onmessage = (e) => {
      const data = JSON.parse(e.data);
      const newIdxs = new Set<number>();

      setSession(prev => {
        const prevCount = prev?.flows.length ?? 0;
        const allFlows = data.new_flows
          ? [...(prev?.flows ?? []), ...data.new_flows]
          : prev?.flows ?? [];
        // Mark new flow indexes
        for (let i = prevCount; i < allFlows.length; i++) newIdxs.add(i);
        return {
          running:       data.running,
          elapsed_sec:   data.elapsed_sec ?? 0,
          remaining_sec: data.remaining_sec ?? 0,
          duration_sec:  60,
          flow_count:    data.flow_count ?? allFlows.length,
          flows:         allFlows,
          correlation:   data.correlation ?? prev?.correlation ?? null,
        };
      });
      setNewFlowIndexes(newIdxs);
      if (newIdxs.size > 0) {
        setTimeout(() => setNewFlowIndexes(new Set()), 2000);
      }
      if (data.done || !data.running) {
        setStatus("done");
        es.close();
      }
    };

    es.onerror = () => {
      es.close();
      setStatus("done");
    };
  }, [analysisId]);

  // Restore an active or completed intercept session when the tab is opened again.
  useEffect(() => {
    let cancelled = false;

    async function loadExistingSession() {
      try {
        const res = await fetch(`${API_BASE}/intercept/${analysisId}`);
        const data = await res.json();
        if (cancelled || !data.session_found) return;

        setSession({
          running:       Boolean(data.running),
          elapsed_sec:   data.elapsed_sec ?? 0,
          remaining_sec: data.remaining_sec ?? 0,
          duration_sec:  data.duration_sec ?? 60,
          flow_count:    data.flow_count ?? data.flows?.length ?? 0,
          flows:         data.flows ?? [],
          correlation:   data.correlation ?? null,
        });

        if (data.running) {
          setStatus("running");
          connectSSE();
        } else {
          setStatus("done");
        }
      } catch {
        // No prior session is fine; the idle start state remains the right UI.
      }
    }

    loadExistingSession();
    return () => {
      cancelled = true;
    };
  }, [analysisId, connectSSE]);

  const handleStart = async () => {
    setStatus("starting");
    setError(null);
    setSession(null);
    try {
      const res = await fetch(`${API_BASE}/intercept/${analysisId}/start`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail ?? "Failed to start interception");
        setStatus("idle");
        return;
      }
      setStatus("running");
      connectSSE();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Network error");
      setStatus("idle");
    }
  };

  const handleStop = async () => {
    eventSourceRef.current?.close();
    try {
      await fetch(`${API_BASE}/intercept/${analysisId}/stop`, { method: "POST" });
    } catch {}
    setStatus("done");
    // Fetch final results
    try {
      const res = await fetch(`${API_BASE}/intercept/${analysisId}`);
      const data = await res.json();
      if (data.session_found) {
        setSession(prev => ({
          ...(prev ?? { running: false, elapsed_sec: 0, remaining_sec: 0, duration_sec: 60, flow_count: 0, flows: [] }),
          running: false,
          flows: data.flows ?? prev?.flows ?? [],
          correlation: data.correlation ?? prev?.correlation ?? null,
        }));
      }
    } catch {}
  };

  // Confirmed C2 IP set for highlighting flows
  const confirmedIPs = new Set(session?.correlation?.confirmed_c2.map(c => c.ip) ?? []);

  const displayedFlows = showAllFlows
    ? (session?.flows ?? [])
    : (session?.flows ?? []).slice(-50);

  const correlation = session?.correlation;
  const risk = correlation?.risk ?? "LOW";

  // ── Idle State ────────────────────────────────────────────────────────────
  if (status === "idle") {
    return (
      <div className="space-y-4">
        {/* Header */}
        <div className="flex items-center gap-3 border-b border-border pb-4">
          <Radio className="w-5 h-5 text-[#f43f5e] animate-pulse" />
          <h2 className="font-bold text-secondary uppercase tracking-tight font-mono text-lg">
            Live Traffic Interception
          </h2>
          <span className="text-[0.6rem] font-mono text-muted uppercase border border-border px-2 py-0.5 ml-auto">
            mitmproxy · port {port}
          </span>
        </div>

        {/* Static IPs Summary */}
        {staticIps.length > 0 && (
          <div className="bg-surface-raised border border-border p-4 space-y-3">
            <p className="text-[0.65rem] font-mono text-muted uppercase tracking-widest">
              IPs encoded in this APK ({staticIps.length} found via static analysis)
            </p>
            <div className="flex flex-wrap gap-2">
              {staticIps.map((ip, i) => (
                <span
                  key={i}
                  className={`text-[0.6rem] font-mono px-2 py-1 border uppercase ${
                    ip.risk === "high"
                      ? "text-[#f43f5e] border-[rgba(244,63,94,0.4)] bg-[rgba(244,63,94,0.06)]"
                      : "text-[#fbbf24] border-[rgba(251,191,36,0.3)] bg-[rgba(251,191,36,0.05)]"
                  }`}
                >
                  {ip.value}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Start CTA */}
        <div className="bg-surface-raised border border-border p-8 flex flex-col items-center gap-5 text-center relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-b from-[rgba(0,237,63,0.02)] to-transparent pointer-events-none" />
          <div className="relative z-10 space-y-2">
            <div className="w-16 h-16 border border-primary/30 rounded-full flex items-center justify-center mx-auto mb-2 relative">
              <Wifi className="w-7 h-7 text-primary" />
              <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-primary animate-ping opacity-40" />
              <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-primary" />
            </div>
            <p className="text-secondary font-mono font-bold text-sm uppercase tracking-widest">
              Start Live Traffic Interception
            </p>
            <p className="text-muted font-mono text-[0.65rem] max-w-md">
              Interact with the app in the Android emulator for 60 seconds.
              All HTTP/HTTPS traffic is captured and automatically compared
              against the IPs encoded in this APK.
            </p>
          </div>
          <button
            id="btn-start-intercept"
            onClick={handleStart}
            className="btn-hex px-8 py-3 text-[0.7rem] relative z-10 group"
          >
            <span className="relative z-10 flex items-center gap-2">
              <Play className="w-4 h-4" />
              START 60s INTERCEPTION
            </span>
          </button>
          {error && (
            <p className="text-[0.65rem] font-mono text-[#f43f5e] relative z-10">{error}</p>
          )}
        </div>

        <SetupGuide port={port} />
      </div>
    );
  }

  // ── Starting State ────────────────────────────────────────────────────────
  if (status === "starting") {
    return (
      <div className="flex flex-col items-center justify-center gap-4 py-16">
        <span className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        <p className="text-muted font-mono text-xs uppercase animate-pulse">
          Starting mitmproxy on port {port}...
        </p>
      </div>
    );
  }

  // ── Running / Done State ──────────────────────────────────────────────────
  return (
    <div className="space-y-5">

      {/* ── Header + Controls ──────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div className="flex items-center gap-3">
          <Radio className={`w-5 h-5 ${status === "running" ? "text-[#f43f5e] animate-pulse" : "text-muted"}`} />
          <h2 className="font-bold text-secondary uppercase tracking-tight font-mono">
            Live Traffic Interception
          </h2>
          <span className={`text-[0.6rem] font-bold px-2 py-0.5 border font-mono uppercase
            ${status === "running"
              ? "text-[#f43f5e] border-[rgba(244,63,94,0.4)] bg-[rgba(244,63,94,0.08)] animate-pulse"
              : "text-[#22c55e] border-[rgba(34,197,94,0.3)] bg-[rgba(34,197,94,0.06)]"}`}
          >
            {status === "running" ? "● INTERCEPTING" : "● SESSION COMPLETE"}
          </span>
        </div>

        <div className="flex items-center gap-3">
          {status === "running" && (
            <CountdownRing
              remaining={session?.remaining_sec ?? 0}
              total={session?.duration_sec ?? 60}
            />
          )}
          {status === "running" && (
            <button
              id="btn-stop-intercept"
              onClick={handleStop}
              className="flex items-center gap-2 px-4 py-2 border border-[rgba(244,63,94,0.4)] text-[#f43f5e] font-mono text-[0.65rem] uppercase hover:bg-[rgba(244,63,94,0.08)] transition-colors"
            >
              <Square className="w-3 h-3 fill-current" />
              Stop Early
            </button>
          )}
          {status === "done" && (
            <button
              onClick={() => { setStatus("idle"); setSession(null); }}
              className="flex items-center gap-2 px-5 py-2 border border-primary text-primary font-mono text-[0.65rem] uppercase font-bold hover:bg-[rgba(0,237,63,0.1)] transition-colors animate-pulse"
            >
              <Play className="w-3 h-3 fill-current" />
              Start New Session
            </button>
          )}
        </div>
      </div>

      {status === "done" && (session?.flow_count ?? 0) === 0 && (
        <div className="bg-[rgba(244,63,94,0.08)] border border-[rgba(244,63,94,0.3)] p-3 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-[#f43f5e]" />
          <div>
            <p className="text-[0.7rem] font-bold font-mono text-[#f43f5e] uppercase">0 Flows Captured</p>
            <p className="text-[0.6rem] font-mono text-muted uppercase mt-0.5">
              Make sure your Android emulator's proxy is configured (see the Setup Guide below) before starting a new session!
            </p>
          </div>
        </div>
      )}

      {/* ── Stats Row ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Flows Captured", value: session?.flow_count ?? 0, icon: <Activity className="w-3.5 h-3.5" />, color: "text-primary" },
          { label: "Elapsed",        value: `${Math.floor(session?.elapsed_sec ?? 0)}s`,    icon: <Clock className="w-3.5 h-3.5" />,    color: "text-[#06b6d4]" },
          { label: "Confirmed C2",   value: correlation?.match_count ?? 0,                  icon: <ShieldAlert className="w-3.5 h-3.5" />, color: correlation?.match_count ? "text-[#f43f5e]" : "text-[#22c55e]" },
          { label: "Live IPs",       value: correlation?.total_live_ips ?? 0,               icon: <Server className="w-3.5 h-3.5" />,   color: "text-[#0ea5e9]" },
        ].map(card => (
          <div key={card.label} className="bg-surface-raised border border-border p-4 space-y-1">
            <div className={`flex items-center gap-1.5 text-[0.6rem] font-mono uppercase tracking-widest ${card.color}`}>
              {card.icon}{card.label}
            </div>
            <p className="text-2xl font-black font-mono text-secondary">{card.value}</p>
          </div>
        ))}
      </div>

      {/* ── IP Correlation Panel ───────────────────────────────────────────── */}
      {correlation && (
        <div className={`border bg-gradient-to-br ${riskGradient[risk]} p-5 space-y-4`}>
          <div className="flex items-center gap-3">
            <Zap className={`w-5 h-5 ${riskText[risk]}`} />
            <h3 className="font-bold font-mono uppercase tracking-widest text-sm text-secondary">
              IP Correlation Intelligence
            </h3>
            <span className={`text-[0.65rem] font-bold font-mono px-3 py-1 border uppercase tracking-widest ml-auto
              ${risk === "CRITICAL" ? "text-[#f43f5e] border-[rgba(244,63,94,0.5)] bg-[rgba(244,63,94,0.1)]"
              : risk === "HIGH"     ? "text-[#f97316] border-[rgba(249,115,22,0.4)] bg-[rgba(249,115,22,0.08)]"
              : "text-[#fbbf24] border-[rgba(251,191,36,0.4)] bg-[rgba(251,191,36,0.06)]"}`}
            >
              {risk}
            </span>
          </div>

          <p className="text-[0.65rem] font-mono text-muted uppercase">{correlation.summary}</p>

          {/* Confirmed C2 — shown prominently */}
          <div className="space-y-2 border-b border-[rgba(255,255,255,0.06)] pb-4">
            <p className="text-[0.6rem] font-mono text-[#f43f5e] uppercase tracking-widest font-bold flex items-center gap-2">
              <ShieldAlert className="w-3.5 h-3.5" />
              CONFIRMED C2 ADDRESSES — Encoded in APK + Active Live Traffic
            </p>
            {correlation.confirmed_c2.length === 0 ? (
              <p className="text-[0.6rem] font-mono text-muted italic bg-[rgba(244,63,94,0.02)] border border-[rgba(244,63,94,0.1)] p-3">
                No common IPs identified yet. When a hardcoded IP is successfully contacted during live interception, it will appear here.
              </p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {correlation.confirmed_c2.map((ip, i) => (
                  <IPCorrelationCard key={i} ip={ip} />
                ))}
              </div>
            )}
          </div>

          {/* Side-by-side: Static Only vs Live Only */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Static Only */}
            <div className="space-y-2">
              <p className="text-[0.6rem] font-mono text-[#fbbf24] uppercase tracking-widest font-bold flex items-center gap-2">
                <Shield className="w-3.5 h-3.5" />
                HARDCODED IN APK ({correlation.static_only.length})
              </p>
              {correlation.static_only.length === 0 ? (
                <p className="text-[0.6rem] font-mono text-muted italic">All static IPs seen in live traffic</p>
              ) : (
                <div className="space-y-2">
                  {correlation.static_only.map((ip, i) => (
                    <IPCorrelationCard key={i} ip={ip} />
                  ))}
                </div>
              )}
            </div>

            {/* Live Only */}
            <div className="space-y-2">
              <p className="text-[0.6rem] font-mono text-[#f97316] uppercase tracking-widest font-bold flex items-center gap-2">
                <Globe className="w-3.5 h-3.5" />
                UNKNOWN EXTERNAL ({correlation.live_only.length})
              </p>
              {correlation.live_only.length === 0 ? (
                <p className="text-[0.6rem] font-mono text-muted italic">No unknown external IPs detected</p>
              ) : (
                <div className="space-y-2">
                  {correlation.live_only.map((ip, i) => (
                    <IPCorrelationCard key={i} ip={ip} />
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Summary counts */}
          <div className="flex flex-wrap gap-4 pt-2 border-t border-[rgba(255,255,255,0.06)] text-[0.6rem] font-mono text-muted uppercase">
            <span>Static IPs: <span className="text-secondary font-bold">{correlation.total_static_ips}</span></span>
            <span>Live IPs: <span className="text-secondary font-bold">{correlation.total_live_ips}</span></span>
            <span>Matches: <span className={`font-bold ${correlation.match_count > 0 ? "text-[#f43f5e]" : "text-[#22c55e]"}`}>{correlation.match_count}</span></span>
            <span>Total Flows: <span className="text-secondary font-bold">{correlation.total_live_flows}</span></span>
          </div>
        </div>
      )}

      {/* ── Live Hosts Table ───────────────────────────────────────────────── */}
      {correlation && correlation.live_hosts.length > 0 && (
        <div className="bg-surface-raised border border-border overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
            <Globe className="w-4 h-4 text-[#0ea5e9]" />
            <span className="text-[0.65rem] font-mono uppercase tracking-widest text-secondary">
              Live Hosts Contacted
            </span>
            <span className="text-[0.6rem] font-mono text-muted border border-border px-2 ml-auto">
              {correlation.live_hosts.length}
            </span>
          </div>
          <div className="max-h-48 overflow-y-auto">
            {correlation.live_hosts.map((h, i) => (
              <div key={i} className={`flex items-center gap-3 px-4 py-2 border-b border-[rgba(255,255,255,0.03)] font-mono text-[0.6rem]
                ${h.confirmed ? "bg-[rgba(244,63,94,0.04)] border-l-2 border-l-[#f43f5e]" : "border-l-2 border-l-transparent"}`}
              >
                {h.tls
                  ? <Lock className="w-3 h-3 text-[#22c55e] shrink-0" />
                  : <Globe className="w-3 h-3 text-muted shrink-0" />}
                <span className="flex-1 text-[#aaa] truncate">{h.host}</span>
                <span className="text-muted shrink-0">{h.ip}</span>
                <span className={`shrink-0 text-[0.55rem] px-1.5 py-0.5 border uppercase tracking-widest font-bold ${
                  h.method === "POST"
                    ? "text-[#f97316] border-[rgba(249,115,22,0.4)]"
                    : "text-muted border-border"
                }`}>{h.method || "?"}</span>
                {h.confirmed && (
                  <span className="shrink-0 text-[0.5rem] font-bold uppercase text-[#f43f5e]">● C2</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Live Flow Log ──────────────────────────────────────────────────── */}
      <div className="bg-surface-raised border border-border overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
          <Terminal className="w-4 h-4 text-primary" />
          <span className="text-[0.65rem] font-mono uppercase tracking-widest text-secondary">
            Intercepted Flows
          </span>
          <span className="text-[0.6rem] font-mono text-muted border border-border px-2">
            {session?.flow_count ?? 0}
          </span>
          {status === "running" && (
            <span className="text-[0.55rem] font-mono text-primary animate-pulse ml-1">● live</span>
          )}
          <button
            onClick={() => setShowAllFlows(!showAllFlows)}
            className="ml-auto text-[0.6rem] font-mono text-muted uppercase hover:text-secondary transition-colors"
          >
            {showAllFlows ? "Show last 50" : "Show all"}
          </button>
        </div>

        {/* Column Headers */}
        <div className="flex items-center gap-2 px-3 py-1.5 bg-[#050505] border-b border-[rgba(255,255,255,0.04)] font-mono text-[0.55rem] uppercase tracking-widest text-muted">
          <span className="w-16">Time</span>
          <span className="w-10">Method</span>
          <span className="w-4"></span>
          <span className="flex-1">Host</span>
          <span className="w-24 text-right">Dst IP</span>
          <span className="w-8 text-right">Status</span>
          <span className="w-8"></span>
        </div>

        <div ref={logRef} className="max-h-64 overflow-y-auto bg-[#030303]">
          {displayedFlows.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 gap-2 text-center">
              <Activity className="w-8 h-8 text-[#1a1a1a]" />
              <p className="text-[0.65rem] font-mono text-muted uppercase">
                {status === "running"
                  ? "Waiting for traffic... Interact with the app in the emulator"
                  : "No flows captured"}
              </p>
            </div>
          ) : (
            displayedFlows.map((flow, i) => {
              const globalIdx = (session?.flows.length ?? 0) - displayedFlows.length + i;
              return (
                <FlowRow
                  key={i}
                  flow={flow}
                  isNew={newFlowIndexes.has(globalIdx)}
                  confirmed={confirmedIPs.has(flow.dst_ip)}
                />
              );
            })
          )}
        </div>
      </div>

      {/* Setup guide at bottom */}
      <SetupGuide port={port} />
    </div>
  );
}
