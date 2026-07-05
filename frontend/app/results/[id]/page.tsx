"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { ArrowLeft, Shield } from "lucide-react";
import Link from "next/link";

import { getAnalysis } from "@/lib/api";
import type { AnalysisResult } from "@/lib/types";

import RiskScoreCard from "@/components/RiskScoreCard";
import AIExplanation from "@/components/AIExplanation";
import PermissionTable from "@/components/PermissionTable";
import StringsTable from "@/components/StringsTable";
import CertificatePanel from "@/components/CertificateCard";
import MitreTable from "@/components/MitreTable";
import ExportButton from "@/components/ExportButton";
import APKFileTree from "@/components/APKFileTree";
import ManifestViewer from "@/components/ManifestViewer";
import MalwareFamilyBadge from "@/components/MalwareFamilyBadge";
import NetworkTrafficPanel from "@/components/NetworkTrafficPanel";
import NetworkFlowDiagram from "@/components/NetworkFlowDiagram";
import BehaviourTimeline from "@/components/BehaviourTimeline";
import CorrelationPanel from "@/components/CorrelationPanel";
import DynamicAnalysisPanel from "@/components/DynamicAnalysisPanel";
import DecompilerPanel from "@/components/DecompilerPanel";
import ThreatCopilot from "@/components/ThreatCopilot";
import C2IntelligencePanel from "@/components/C2IntelligencePanel";
import LiveInterceptPanel from "@/components/LiveInterceptPanel";
import ThreatMap from "@/components/ThreatMap";

export default function ResultsPage() {
  const { id } = useParams() as { id: string };

  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "filetree" | "manifest" | "ml" | "network" | "sandbox" | "decompile" | "certificate" | "intercept">("overview");

  useEffect(() => {
    if (!id) return;
    setIsLoading(true);
    getAnalysis(id)
      .then((data) => { setResult(data); setIsLoading(false); })
      .catch((err) => { setError(err.message || "Failed to load analysis result."); setIsLoading(false); });
  }, [id]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background grid-bg flex flex-col items-center justify-center gap-4">
        <span className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin mb-4"></span>
        <p className="text-muted font-mono text-xs uppercase animate-pulse">Retrieving analysis results...</p>
      </div>
    );
  }

  if (error || !result) {
    return (
      <div className="min-h-screen bg-background grid-bg flex flex-col items-center justify-center gap-4">
        <div className="bg-[rgba(244,63,94,0.1)] border border-danger p-4 text-danger font-mono text-xs uppercase text-center">
          <p className="mb-2 font-bold">[ ERROR LOADING RESULTS ]</p>
          <p>{error || "Analysis not found."}</p>
        </div>
        <Link href="/" className="btn-hex px-6 py-2 mt-4 text-[0.65rem]">
          <span className="relative z-10 flex items-center gap-2">RETURN TO TERMINAL</span>
        </Link>
      </div>
    );
  }

  const riskColor = result.risk.risk_level === 'CRITICAL' ? '#f43f5e' : 
                    result.risk.risk_level === 'HIGH' ? '#f97316' : 
                    result.risk.risk_level === 'MEDIUM' ? '#fbbf24' : 
                    result.risk.risk_level === 'LOW' ? '#4ade80' : '#22d3ee';

  // Identify dangerous dynamic IPs (intercepted IPs not found in static analysis)
  let dangerousIps: string[] = [];
  if (result.network?.remote_ips && result.strings?.ips) {
    const staticIps = new Set(result.strings.ips.map(ip => ip.value));
    dangerousIps = result.network.remote_ips
      .map(f => f.ip)
      .filter(ip => ip && !staticIps.has(ip));
  }

  return (
    <div className="min-h-screen bg-background grid-bg p-6 md:p-12 relative">
      <div className="absolute inset-0 bg-gradient-to-b from-transparent to-black pointer-events-none z-0"></div>
      
      <div className="max-w-[100rem] mx-auto space-y-8 relative z-10">
        
        {/* Navigation & Actions */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-6">
          <div className="flex items-center gap-4">
            <Link href="/dashboard" className="text-muted hover:text-secondary transition-colors">
              <ArrowLeft className="w-5 h-5" />
            </Link>
            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-xl md:text-2xl font-bold text-secondary uppercase tracking-tighter truncate max-w-md">{result.filename}</h1>
                <span className={`text-[0.6rem] font-bold px-2 py-0.5 border risk-badge-${result.risk.risk_level.toLowerCase()}`}>
                  {result.risk.risk_level}
                </span>
              </div>
              <p className="text-[0.65rem] font-mono text-muted mt-1 break-all uppercase tracking-widest">
                SHA-256: {result.hashes.sha256}
              </p>
            </div>
          </div>
          <ExportButton
            analysisId={result.id}
            packageName={result.manifest?.package_name}
            sha256={result.hashes?.sha256}
          />
        </div>

        {/* Tab Navigation */}
        <div className="flex gap-2 overflow-x-auto pb-2 border-b border-border">
          {(["overview", "filetree", "manifest", "ml", "network", "intercept", "sandbox", "decompile", "certificate"] as const).map((tab) => (
            <button
              key={tab}
              id={`tab-${tab}`}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 text-[0.65rem] font-mono uppercase tracking-widest transition-all whitespace-nowrap border-b-2 ${
                activeTab === tab
                  ? "border-primary text-primary bg-[rgba(0,237,63,0.05)]"
                  : "border-transparent text-muted hover:text-secondary hover:bg-surface-raised"
              }`}
            >
              {tab === "overview" ? "[ ANALYSIS ]"
                : tab === "filetree" ? "[ FILE TREE ]"
                : tab === "manifest" ? "[ MANIFEST ]"
                : tab === "ml" ? "[ INTELLIGENCE ]"
                : tab === "network" ? "[ NETWORK ]"
                : tab === "decompile" ? "[ DECOMPILE ]"
                : tab === "intercept" ? (
                  <span className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#f43f5e] animate-pulse" />
                    [ INTERCEPT ]
                  </span>
                )
                : tab === "certificate" ? (
                  <span className="flex items-center gap-1.5">
                    {result.certificate?.trust_verdict === "VERIFIED" ? (
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    ) : result.certificate?.trust_verdict === "UNTRUSTED" ? (
                      <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-pulse" />
                    ) : (
                      <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
                    )}
                    [ CERTIFICATE ]
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5">
                    {(result.dynamic?.sandbox_available || result.mobsf?.available) && (
                      <span className="w-1.5 h-1.5 rounded-full bg-[#4ade80] animate-pulse" />
                    )}
                    [ SANDBOX ]
                  </span>
                )}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === "overview" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-1 space-y-6">
              <RiskScoreCard 
                risk={result.risk} 
                dynamic={result.dynamic}
                mlClassification={result.ml_classification}
                xgboost={result.xgboost}
                malbert={result.malbert}
                network={result.network}
                strings={result.strings}
              />
              {result.ml_classification && (
                <MalwareFamilyBadge
                  mlClassification={result.ml_classification}
                  xgboost={result.xgboost}
                  malbert={result.malbert}
                  anomaly={result.anomaly}
                  agentVerdict={result.agent_verdict}
                />
              )}
              <AIExplanation narrative={result.ai_narrative} recommendations={result.ai_recommendations} />
              {/* Certificate moved to its own tab — show mini trust badge here */}
              {result.certificate && (
                <button
                  onClick={() => setActiveTab("certificate")}
                  className={`w-full text-left p-4 rounded-xl border transition-all hover:scale-[1.01] ${
                    result.certificate.trust_verdict === "VERIFIED"
                      ? "border-emerald-500/30 bg-emerald-500/5"
                      : result.certificate.trust_verdict === "UNTRUSTED"
                      ? "border-rose-500/30 bg-rose-500/5"
                      : "border-yellow-500/30 bg-yellow-500/5"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-bold ${
                        result.certificate.trust_verdict === "VERIFIED" ? "text-emerald-400" :
                        result.certificate.trust_verdict === "UNTRUSTED" ? "text-rose-400" :
                        "text-yellow-400"
                      }`}>
                        {result.certificate.trust_verdict === "VERIFIED" ? "✓ Verified Publisher" :
                         result.certificate.trust_verdict === "UNTRUSTED" ? "✗ Untrusted Certificate" :
                         "⚠ Unrecognized Certificate"}
                      </span>
                    </div>
                    <span className="text-[0.6rem] font-mono text-slate-500">CERT RISK: {result.certificate.cert_risk_score ?? "—"}/100 → View Details</span>
                  </div>
                  {result.certificate.publisher_match && (
                    <p className="text-xs text-slate-400 mt-1">{result.certificate.publisher_match.name}</p>
                  )}
                </button>
              )}
            </div>
            <div className="lg:col-span-2 space-y-6">
              <div className="bg-surface-raised border border-border p-6 corner-brackets grid grid-cols-2 md:grid-cols-4 gap-6">
                <InfoItem label="Package Name" value={result.manifest.package_name} />
                <InfoItem label="Version" value={`${result.manifest.version_name} (${result.manifest.version_code})`} />
                <InfoItem label="Target SDK" value={result.manifest.target_sdk.toString()} />
                <InfoItem label="File Size" value={`${(result.hashes.file_size / 1024 / 1024).toFixed(2)} MB`} />
              </div>
              <MitreTable tactics={result.mitre} />
              {dangerousIps.length > 0 && <ThreatMap ips={dangerousIps} />}
              <PermissionTable permissions={result.manifest.permissions} dangerousCombos={result.manifest.dangerous_combos} />
              <StringsTable strings={result.strings} />
            </div>
          </div>
        )}

        {activeTab === "filetree" && (
          <div className="space-y-4">
            <p className="text-[0.65rem] font-mono text-muted uppercase tracking-widest border-l-2 border-border pl-3">
              Decoded APK structure. Suspicious entries highlighted.
            </p>
            <APKFileTree analysisId={result.id} />
          </div>
        )}

        {activeTab === "manifest" && (
          <div className="space-y-4">
            <p className="text-[0.65rem] font-mono text-muted uppercase tracking-widest border-l-2 border-border pl-3">
              Decoded AndroidManifest.xml. Dangerous permissions highlighted.
            </p>
            <ManifestViewer analysisId={result.id} />
          </div>
        )}

        {activeTab === "ml" && (
          <div className="space-y-6">
            <p className="text-[0.65rem] font-mono text-muted uppercase tracking-widest border-l-2 border-border pl-3">
              Full ML Intelligence Layer results — Static ML, Deep Neural Net, LangChain Agent.
            </p>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <MalwareFamilyBadge
                mlClassification={result.ml_classification}
                xgboost={result.xgboost}
                malbert={result.malbert}
                anomaly={result.anomaly}
                agentVerdict={result.agent_verdict}
              />

              {/* Court Narrative */}
              {result.agent_verdict?.court_narrative && (
                <div className="bg-surface-raised border border-border p-6 corner-brackets space-y-4">
                  <div className="flex items-center gap-2 border-b border-border pb-2">
                    <h3 className="font-bold text-secondary uppercase tracking-tight text-sm font-mono">Agent Verdict</h3>
                    <span className="ml-auto text-[0.65rem] font-mono text-muted uppercase">
                      Confidence: <span className="text-primary">{result.agent_verdict.verdict_confidence}%</span>
                    </span>
                  </div>
                  <div className="text-[0.7rem] font-mono text-muted leading-relaxed whitespace-pre-wrap uppercase">
                    {result.agent_verdict.court_narrative}
                  </div>
                  {result.agent_verdict.ioc_summary && (
                    <div className="p-3 bg-[rgba(204,34,0,0.1)] border border-[rgba(244,63,94,0.2)] mt-4">
                      <p className="text-[0.65rem] font-mono font-bold text-danger uppercase tracking-widest mb-1">IOC Summary</p>
                      <p className="text-[0.65rem] font-mono text-danger/80 uppercase">{result.agent_verdict.ioc_summary}</p>
                    </div>
                  )}
                </div>
              )}

              {/* XGBoost Class Probabilities */}
              {result.xgboost?.available && (
                <div className="bg-surface-raised border border-border p-6 corner-brackets space-y-4">
                  <h3 className="font-bold text-secondary uppercase tracking-tight text-sm font-mono flex items-center gap-2 border-b border-border pb-2">
                    XGBoost Probabilities
                    <span className="text-[0.65rem] text-muted font-normal ml-auto">MalDroid 2020 · {result.xgboost.inference_ms}ms</span>
                  </h3>
                  {Object.entries(result.xgboost.class_probs)
                    .sort(([, a], [, b]) => b - a)
                    .map(([cls, prob]) => (
                      <div key={cls} className="flex items-center gap-3">
                        <span className="text-[0.65rem] font-mono text-muted uppercase w-28 shrink-0">{cls}</span>
                        <div className="flex-1 h-1 bg-surface-raised overflow-hidden">
                          <div
                            className="h-full transition-all duration-700 relative"
                            style={{ width: `${prob * 100}%`, background: prob > 0.5 ? "#f43f5e" : prob > 0.2 ? "#f97316" : "#22d3ee" }}
                          >
                             <div className="absolute right-0 top-1/2 -translate-y-1/2 w-1 h-1 bg-white shadow-[0_0_5px_#fff]"></div>
                          </div>
                        </div>
                        <span className="text-[0.65rem] font-mono text-secondary w-10 text-right">{(prob * 100).toFixed(1)}%</span>
                      </div>
                    ))}
                </div>
              )}

              {/* Deep Neural Net all scores */}
              {result.malbert?.available && (
                <div className="bg-surface-raised border border-border p-6 corner-brackets space-y-4">
                  <h3 className="font-bold text-secondary uppercase tracking-tight text-sm font-mono flex items-center gap-2 border-b border-border pb-2">
                    Deep Neural Net Zero-Shot
                    <span className="text-[0.65rem] text-muted font-normal ml-auto">{result.malbert.inference_ms}ms</span>
                  </h3>
                  {Object.entries(result.malbert.all_scores)
                    .sort(([, a], [, b]) => b - a)
                    .map(([cls, score]) => (
                      <div key={cls} className="flex items-center gap-3">
                        <span className="text-[0.65rem] font-mono text-muted uppercase w-36 shrink-0">{cls}</span>
                        <div className="flex-1 h-1 bg-surface-raised overflow-hidden">
                          <div
                            className="h-full transition-all duration-700 relative"
                            style={{ width: `${score * 100}%`, background: score > 0.5 ? "#f43f5e" : score > 0.2 ? "#f97316" : "#22d3ee" }}
                          >
                             <div className="absolute right-0 top-1/2 -translate-y-1/2 w-1 h-1 bg-white shadow-[0_0_5px_#fff]"></div>
                          </div>
                        </div>
                        <span className="text-[0.65rem] font-mono text-secondary w-10 text-right">{(score * 100).toFixed(1)}%</span>
                      </div>
                    ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* 🔬 Network Traffic Tab */}
        {activeTab === "network" && (
          <div className="space-y-6">
            {/* C2 Intelligence — shown first as the primary threat signal */}
            <C2IntelligencePanel c2Intelligence={(result as any).c2_intelligence ?? null} />
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
              <NetworkFlowDiagram network={result.network ?? null} />
              <BehaviourTimeline result={result} network={result.network ?? null} />
            </div>
            <CorrelationPanel correlation={result.correlation ?? null} />
            <NetworkTrafficPanel
              analysisId={result.id}
              initialNetwork={result.network ?? null}
            />
          </div>
        )}

        {/* 📡 Live Intercept Tab */}
        <div className={activeTab === "intercept" ? "block" : "hidden"}>
          <div className="space-y-4">
            <p className="text-[0.65rem] font-mono text-muted uppercase tracking-widest border-l-2 border-[#f43f5e] pl-3">
              Live mitmproxy interception — interact with the APK in the Android emulator for 60 seconds.
              Captured IPs are cross-correlated with IPs hardcoded in the APK to confirm active C2 communication.
            </p>
            <LiveInterceptPanel
              analysisId={result.id}
              staticIps={result.strings?.ips as any ?? []}
            />
          </div>
        </div>

        {/* 📦 Dynamic Sandbox Tab */}
        {activeTab === "sandbox" && (
          <div className="space-y-4">
            <p className="text-[0.65rem] font-mono text-muted uppercase tracking-widest border-l-2 border-primary pl-3">
              Frida offline behavioral analysis + MobSF deep static scan.
              Decompiles APK with apktool, walks smali bytecode for API calls,
              crypto usage, anti-analysis tricks, and hardcoded secrets.
            </p>
            <DynamicAnalysisPanel
              analysisId={result.id}
              dynamic={result.dynamic}
              mobsf={result.mobsf}
            />
          </div>
        )}

        {/* 🔬 Decompile Tab */}
        {activeTab === "decompile" && (
          <div className="space-y-4">
            <DecompilerPanel analysisId={result.id} />
          </div>
        )}

        {/* 🔐 Certificate Analysis Tab */}
        {activeTab === "certificate" && result.certificate && (
          <div className="space-y-4">
            <p className="text-[0.65rem] font-mono text-muted uppercase tracking-widest border-l-2 border-border pl-3">
              APK signing certificate analysis — publisher verification, trust verdict, and certificate risk scoring.
            </p>
            <div className="max-w-2xl">
              <CertificatePanel cert={result.certificate as any} />
            </div>
          </div>
        )}
      </div>

      {/* Floating Threat Copilot */}
      <ThreatCopilot
        analysisId={result.id}
        activeTab={activeTab}
        filename={result.filename}
        riskLevel={result.risk.risk_level}
      />
    </div>
  );
}

function InfoItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-1">
      <p className="text-[0.6rem] font-mono text-muted uppercase tracking-widest">{label}</p>
      <p className="text-sm font-bold text-secondary truncate font-mono" title={value}>{value}</p>
    </div>
  );
}
