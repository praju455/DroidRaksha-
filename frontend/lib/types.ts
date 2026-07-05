// DroidRaksha — TypeScript type definitions

export interface HashInfo {
  md5: string;
  sha1: string;
  sha256: string;
  file_size: number;
}

export interface Permission {
  name: string;
  is_dangerous: boolean;
  protection_level: string;
  description?: string;
}

export interface DangerousCombo {
  label: string;
  permissions: string[];
  risk: string;
}

export interface Manifest {
  package_name: string;
  version_name: string;
  version_code: number;
  min_sdk: number;
  target_sdk: number;
  permissions: Permission[];
  dangerous_combos: DangerousCombo[];
  activities: string[];
  services: string[];
  receivers: string[];
  providers: string[];
  error?: string;
}

export interface StringItem {
  value: string;
  context?: string;
  risk?: "high" | "medium" | "low";
}

export interface Strings {
  urls: StringItem[];
  ips: StringItem[];
  emails: StringItem[];
  crypto_keys: StringItem[];
  suspicious_strings: StringItem[];
  base64_strings: string[];
}

export interface CertPublisherMatch {
  name: string;
  package: string;
  trust: string;
}

export interface Certificate {
  issuer: string;
  subject: string;
  not_before: string;
  not_after: string;
  is_expired: boolean;
  is_self_signed: boolean;
  serial_number: string;
  signature_algorithm: string;
  // fingerprint field — backend returns sha256_fingerprint, old records may have fingerprint_sha256
  sha256_fingerprint?: string;
  fingerprint_sha256?: string;
  warnings: string[];
  // New publisher verification fields
  publisher_match: CertPublisherMatch | null;
  trust_verdict: "VERIFIED" | "PARTIAL" | "UNRECOGNIZED" | "UNTRUSTED" | "EXPIRED" | "UNVERIFIED";
  cert_risk_score: number;
  score_reasons: string[];
  error?: string;
}

export interface YaraMatch {
  rule: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  tags: string[];
  description?: string;
}

export interface YaraScan {
  matches: YaraMatch[];
  total_matches: number;
  scan_duration_ms?: number;
}

export interface Obfuscation {
  score: number;
  has_dex_classloader: boolean;
  has_reflection: boolean;
  has_string_encryption: boolean;
  has_native_code: boolean;
  class_name_entropy: number;
  short_class_ratio: number;
  indicators: string[];
}

export interface VirusTotal {
  found: boolean;
  detection_count: number;
  total_engines: number;
  malware_families: string[];
  scan_date?: string;
  permalink?: string;
  error?: string;
}

export interface AbuseIPDB {
  flagged_ips: string[];
  max_confidence: number;
  results: Array<{
    ip: string;
    confidence: number;
    country: string;
    usage: string;
  }>;
  error?: string;
}

export interface IndiaIOC {
  is_fake_upi: boolean;
  is_fake_bank: boolean;
  is_loan_scam: boolean;
  risk_flags: string[];
  matched_ips: string[];
  matched_domains: string[];
}

export interface RiskBreakdown {
  permissions: number;
  yara: number;
  certificate: number;
  threat_intel: number;
  obfuscation: number;
  india_ioc: number;
  strings: number;
}

export interface Risk {
  score: number;
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE";
  breakdown: RiskBreakdown;
  threat_categories: string[];
}

export interface MitreTactic {
  technique_id: string;
  name: string;
  tactic: string;
  evidence: string;
  all_evidence?: string[];
}

// ── P11 ML Intelligence Layer types ─────────────────────────────────────

export type MalwareFamilyLabel =
  | "BankingTrojan" | "RAT" | "Spyware" | "Ransomware" | "Adware"
  | "Dropper" | "SMSStealer" | "FakeApp" | "CryptoMiner"
  | "Stalkerware" | "ClipboardHijacker" | "Unknown";

export interface SHAPFeature {
  feature: string;
  raw_name: string;
  shap_value: number;
  direction: "increases" | "decreases";
}

export interface XGBoostResult {
  label: "Adware" | "Banking" | "SMS_Malware" | "Riskware" | "Benign" | "unavailable" | "error";
  probability: number;
  class_probs: Record<string, number>;
  shap_top5: SHAPFeature[];
  available: boolean;
  inference_ms: number;
}

export interface MalBERTResult {
  label: MalwareFamilyLabel | string;
  raw_label: string;
  confidence: number;
  all_scores: Record<string, number>;
  input_text_preview: string;
  available: boolean;
  inference_ms: number;
}

export interface MLClassification {
  family: MalwareFamilyLabel;
  confidence: number;
  evidence: string[];
  secondary_families: string[];
  is_india_targeted: boolean;
}

export interface AnomalyDetection {
  is_anomalous: boolean;
  anomaly_score: number;
  anomaly_percentile: number;
  zero_day_risk: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  explanation: string;
  model_used: "isolation_forest" | "heuristic";
  available: boolean;
  inference_ms: number;
}

export interface AgentVerdict {
  court_narrative: string;
  ioc_summary: string;
  recommendations: string[];
  reasoning_steps: string[];
  verdict_confidence: number;
  agent_used: string;
  inference_ms?: number;
}

// ── Dynamic Sandbox types ─────────────────────────────────────────────────

export interface ApiHit {
  api: string;
  file: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
}

export interface BehavioralScore {
  score: number;
  level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE";
  flags: string[];
  summary: string;
}

export interface SmaliAnalysis {
  smali_file_count: number;
  total_methods: number;
  critical_apis: ApiHit[];
  high_apis: ApiHit[];
  medium_apis: ApiHit[];
  crypto_usage: Record<string, string[]>;
  antianalysis: Record<string, Array<{ file: string; match: string }>>;
  sensitive_data: Record<string, Array<{ file: string; snippet: string }>>;
  dynamic_loading: string[];
  native_libs: string[];
  reflection_calls: string[];
  network_endpoints: string[];
}

export interface DynamicSandbox {
  sandbox_available: boolean;
  engine?: string;
  analysis_time_sec?: number;
  behavioral_score?: BehavioralScore;
  smali_analysis?: SmaliAnalysis;
  manifest?: Record<string, unknown>;
  resources?: {
    total_assets: number;
    suspicious_assets: string[];
    embedded_executables: string[];
    hidden_dex: string[];
  };
  error?: string;
}

export interface MobSFFinding {
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  desc: string;
  files: string[];
}

export interface MobSFResult {
  available: boolean;
  app_name?: string;
  package_name?: string;
  version_name?: string;
  security_score?: number;
  dangerous_perms?: Array<{ name: string; status: string; info: string }>;
  findings?: MobSFFinding[];
  urls?: string[];
  emails?: string[];
  apkid?: Record<string, unknown>;
  error?: string;
}

export interface DgaSuspect {
  domain: string;
  query_count: number;
  entropy: number;
  score?: number;
  is_dga?: boolean;
  reasons?: string[];
}

export interface BeaconAlert {
  ip: string;
  contact_count: number;
  avg_interval_sec: number;
  jitter_cv: number;
  confidence: "HIGH" | "MEDIUM";
  description: string;
}

export interface NetworkData {
  available: boolean;
  error?: string;
  pcap_risk: string;
  summary: {
    total_packets: number;
    parse_errors: number;
    unique_remote_ips: number;
    dns_query_count: number;
    http_host_count: number;
    tls_sni_count: number;
    beaconing_alerts: number;
    dga_suspects: number;
    india_hits: number;
  };
  dns_queries: Array<{ domain: string; count: number }>;
  http_hosts: Array<{ host: string; count: number }>;
  http_requests?: Array<{ host: string; method: string; uri: string }>;
  tls_sni: string[];
  remote_ips: Array<{ ip: string; count: number; ports: number[]; first_seen: string; static_files?: string[] }>;
  beaconing_alerts: BeaconAlert[];
  dga_suspects: DgaSuspect[];
  india_ioc_hits: Array<{ type: "ip" | "domain"; value: string; reason: string; severity: string }>;
}

export interface CorrelationFinding {
  type: "domain" | "ip" | "india_ioc";
  value: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  explanation: string;
  static_source?: string;
  dynamic_source?: string;
}

export interface CorrelationResult {
  available: boolean;
  score: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  summary: string;
  matches: CorrelationFinding[];
  hidden_runtime_indicators: CorrelationFinding[];
  threat_intel_overlaps: CorrelationFinding[];
  behaviour_links: string[];
  static_counts: { domains: number; ips: number };
  dynamic_counts: { domains: number; ips: number };
  threat_intel?: Record<string, unknown>;
}

export interface AnalysisResult {
  id: string;
  status: "complete" | "pending" | "error";
  created_at: string;
  filename: string;
  hashes: HashInfo;
  manifest: Manifest;
  strings: Strings;
  certificate: Certificate;
  yara: YaraScan;
  obfuscation: Obfuscation;
  virustotal: VirusTotal;
  abuseipdb: AbuseIPDB;
  india_ioc: IndiaIOC;
  risk: Risk;
  mitre: MitreTactic[];
  // ML Intelligence Layer
  ml_classification?: MLClassification;
  xgboost?: XGBoostResult;
  malbert?: MalBERTResult;
  anomaly?: AnomalyDetection;
  agent_verdict?: AgentVerdict;
  // AI Narrative
  ai_narrative: string;
  ai_recommendations: string[];
  // Network
  network?: NetworkData;
  correlation?: CorrelationResult;
  dga_static?: {
    available: boolean;
    total_domains: number;
    suspect_count: number;
    suspects: DgaSuspect[];
  };
  asn?: Record<string, unknown>;
  otx?: Record<string, unknown>;
  // Dynamic Sandbox
  dynamic?: DynamicSandbox;
  mobsf?: MobSFResult;
}

// ── Live Intercept types ──────────────────────────────────────────────────

export interface InterceptFlow {
  ts: number;
  method: string;
  host: string;
  url: string;
  dst_ip: string;
  dst_port: number;
  status: number;
  tls: boolean;
}

export interface CorrelatedIP {
  ip: string;
  verdict: "CONFIRMED_C2" | "STATIC_ONLY" | "LIVE_ONLY";
  risk: string;
  label: string;
  static_risk?: string;
  live_calls?: number;
  methods?: string[];
  hosts?: string[];
  urls?: string[];
  tls?: boolean;
  first_seen?: number;
}

export interface InterceptCorrelation {
  risk: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  total_static_ips: number;
  total_live_ips: number;
  confirmed_c2: CorrelatedIP[];
  static_only: CorrelatedIP[];
  live_only: CorrelatedIP[];
  live_hosts: Array<{
    host: string; ip: string; tls: boolean;
    method: string; status: number; confirmed: boolean;
  }>;
  match_count: number;
  total_live_flows: number;
  summary: string;
}

export interface InterceptResult {
  analysis_id: string;
  session_found: boolean;
  running: boolean;
  elapsed_sec: number;
  remaining_sec: number;
  duration_sec: number;
  flow_count: number;
  flows: InterceptFlow[];
  static_ips: Array<{ type: string; value: string; risk: string }>;
  correlation: InterceptCorrelation;
}

export interface DashboardStats {
  total_analyzed: number;
  threats_detected: number;
  india_threats: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  safe_count: number;
  family_breakdown: Record<string, number>;
  india_targeted: number;
  pcap_scans: number;
  recent_analyses: Array<{
    id: string;
    filename: string;
    package_name: string;
    risk_score: number;
    risk_level: string;
    created_at: string;
  }>;
}
