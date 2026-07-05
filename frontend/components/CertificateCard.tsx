"use client";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Calendar,
  Hash,
  Award,
  Info,
} from "lucide-react";

interface CertificateData {
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  signature_algorithm: string;
  is_self_signed: boolean;
  is_expired: boolean;
  sha256_fingerprint?: string;
  fingerprint_sha256?: string; // backward compat with older MongoDB records
  publisher_match: {
    name: string;
    package: string;
    trust: string;
  } | null;
  trust_verdict:
    | "VERIFIED"
    | "PARTIAL"
    | "UNRECOGNIZED"
    | "UNTRUSTED"
    | "EXPIRED"
    | "UNVERIFIED";
  cert_risk_score: number;
  score_reasons: string[];
  warnings: string[];
  error?: string | null;
}

interface Props {
  cert: CertificateData;
}

const VERDICT_CONFIG: Record<
  string,
  {
    label: string;
    color: string;
    bg: string;
    border: string;
    ring: string;
    icon: React.ElementType;
    description: string;
  }
> = {
  VERIFIED: {
    label: "Verified Publisher",
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/30",
    ring: "#4ade80",
    icon: ShieldCheck,
    description:
      "Certificate fingerprint matches a known, trusted publisher in our database.",
  },
  PARTIAL: {
    label: "Partially Trusted",
    color: "text-cyan-400",
    bg: "bg-cyan-500/10",
    border: "border-cyan-500/30",
    ring: "#22d3ee",
    icon: Shield,
    description:
      "Issuer name matches a known organization, but fingerprint is not in our verified database.",
  },
  UNRECOGNIZED: {
    label: "Unknown Publisher",
    color: "text-yellow-400",
    bg: "bg-yellow-500/10",
    border: "border-yellow-500/30",
    ring: "#fbbf24",
    icon: ShieldAlert,
    description:
      "Certificate issuer is not recognized. May be a legitimate app not in our database.",
  },
  UNTRUSTED: {
    label: "Untrusted",
    color: "text-rose-400",
    bg: "bg-rose-500/10",
    border: "border-rose-500/30",
    ring: "#f43f5e",
    icon: ShieldX,
    description:
      "Self-signed, debug, or otherwise untrusted certificate. High risk indicator.",
  },
  EXPIRED: {
    label: "Expired Certificate",
    color: "text-orange-400",
    bg: "bg-orange-500/10",
    border: "border-orange-500/30",
    ring: "#f97316",
    icon: ShieldAlert,
    description:
      "Certificate validity period has ended. Legitimate apps maintain valid certificates.",
  },
  UNVERIFIED: {
    label: "Unverified",
    color: "text-slate-400",
    bg: "bg-slate-500/10",
    border: "border-slate-500/30",
    ring: "#94a3b8",
    icon: Shield,
    description: "Certificate could not be fully analyzed.",
  },
};

function ScoreRing({
  score,
  ring,
}: {
  score: number;
  ring: string;
}) {
  const radius = 34;
  const circ = 2 * Math.PI * radius;
  const fill = ((100 - score) / 100) * circ; // high score = bad → fill = inversed
  return (
    <svg width="90" height="90" viewBox="0 0 90 90">
      <circle cx="45" cy="45" r={radius} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="7" />
      <circle
        cx="45"
        cy="45"
        r={radius}
        fill="none"
        stroke={ring}
        strokeWidth="7"
        strokeDasharray={`${fill} ${circ}`}
        strokeLinecap="round"
        strokeDashoffset={circ / 4}
        style={{ transition: "stroke-dasharray 0.8s ease", filter: `drop-shadow(0 0 6px ${ring}88)` }}
      />
      <text x="45" y="41" textAnchor="middle" fill={ring} fontSize="16" fontWeight="bold" fontFamily="monospace">
        {score}
      </text>
      <text x="45" y="56" textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="8" fontFamily="monospace">
        CERT RISK
      </text>
    </svg>
  );
}

function Row({ label, value, mono = false, highlight }: { label: string; value: string; mono?: boolean; highlight?: "rose" | "yellow" | "green" }) {
  const color =
    highlight === "rose"
      ? "text-rose-400"
      : highlight === "yellow"
      ? "text-yellow-400"
      : highlight === "green"
      ? "text-emerald-400"
      : "text-slate-300";
  return (
    <div className="flex gap-3 py-1.5 border-b border-white/5 last:border-0">
      <span className="text-[0.65rem] font-mono text-slate-500 uppercase tracking-wider w-32 shrink-0 pt-0.5">
        {label}
      </span>
      <span className={`text-xs break-all ${mono ? "font-mono" : ""} ${color}`}>
        {value || "—"}
      </span>
    </div>
  );
}

export default function CertificatePanel({ cert }: Props) {
  if (!cert) return null;

  if (cert.error && !cert.trust_verdict) {
    return (
      <div className="card-surface p-6 rounded-2xl">
        <div className="flex items-center gap-2 mb-3">
          <Shield className="w-5 h-5 text-slate-400" />
          <h2 className="font-semibold text-slate-200 text-sm uppercase tracking-wider">
            Certificate Analysis
          </h2>
        </div>
        <p className="text-sm text-slate-400">{cert.error}</p>
      </div>
    );
  }

  const verdict = cert.trust_verdict || "UNVERIFIED";
  const cfg = VERDICT_CONFIG[verdict] ?? VERDICT_CONFIG["UNVERIFIED"];
  const VerdictIcon = cfg.icon;
  const score = cert.cert_risk_score ?? 50;

  const formatDate = (iso: string) => {
    try {
      return new Date(iso).toLocaleDateString("en-IN", {
        day: "2-digit",
        month: "short",
        year: "numeric",
      });
    } catch {
      return iso;
    }
  };

  const formatFingerprint = (fp: string) => {
    if (!fp || fp === "unknown") return "—";
    return fp.match(/.{1,2}/g)?.join(":").toUpperCase() || fp;
  };

  return (
    <div className="card-surface rounded-2xl overflow-hidden">
      {/* Header */}
      <div className="p-5 border-b border-white/5">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-slate-400" />
          <h2 className="text-[0.7rem] font-mono text-slate-400 uppercase tracking-widest">
            Certificate Analysis
          </h2>
        </div>
      </div>

      {/* Trust Verdict Banner */}
      <div className={`px-5 py-4 ${cfg.bg} border-b ${cfg.border}`}>
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-4">
            <ScoreRing score={score} ring={cfg.ring} />
            <div>
              <div className="flex items-center gap-2 mb-1">
                <VerdictIcon className={`w-5 h-5 ${cfg.color}`} />
                <span className={`font-bold text-base ${cfg.color}`}>
                  {cfg.label}
                </span>
              </div>
              <p className="text-xs text-slate-400 max-w-sm leading-relaxed">
                {cfg.description}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="p-5 space-y-6">
        {/* Publisher Match */}
        {cert.publisher_match ? (
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4">
            <div className="flex items-center gap-2 mb-3">
              <Award className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">
                ✓ Verified Publisher Match
              </span>
            </div>
            <div className="space-y-1.5">
              <div className="flex gap-3">
                <span className="text-[0.65rem] font-mono text-slate-500 uppercase w-28 shrink-0">Publisher</span>
                <span className="text-xs text-emerald-300 font-semibold">{cert.publisher_match.name}</span>
              </div>
              <div className="flex gap-3">
                <span className="text-[0.65rem] font-mono text-slate-500 uppercase w-28 shrink-0">Package</span>
                <span className="text-xs font-mono text-slate-300">{cert.publisher_match.package}</span>
              </div>
              <div className="flex gap-3">
                <span className="text-[0.65rem] font-mono text-slate-500 uppercase w-28 shrink-0">Trust Status</span>
                <span className="text-xs text-emerald-400 font-bold">{cert.publisher_match.trust}</span>
              </div>
            </div>
          </div>
        ) : (
          <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4">
            <div className="flex items-center gap-2 mb-1">
              <Info className="w-4 h-4 text-yellow-400" />
              <span className="text-xs font-semibold text-yellow-400 uppercase tracking-wider">
                No Publisher Match Found
              </span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              This certificate fingerprint is not in our known-publisher database.
              This is expected for newly published or obscure apps, but is a red flag
              for any app claiming to be a major bank or payment service.
            </p>
          </div>
        )}

        {/* Certificate Details */}
        <div>
          <p className="text-[0.65rem] font-mono text-slate-500 uppercase tracking-wider mb-2">
            Certificate Details
          </p>
          <div className="bg-slate-900/40 rounded-xl p-3">
            <Row label="Subject (CN)" value={cert.subject} />
            <Row label="Issuer" value={cert.issuer} highlight={cert.is_self_signed ? "yellow" : undefined} />
            <Row label="Serial No." value={cert.serial_number} mono />
            <Row
              label="Valid From"
              value={cert.not_before !== "unknown" ? formatDate(cert.not_before) : "—"}
            />
            <Row
              label="Valid Until"
              value={cert.not_after !== "unknown" ? formatDate(cert.not_after) : "—"}
              highlight={cert.is_expired ? "rose" : undefined}
            />
            <Row
              label="Algorithm"
              value={cert.signature_algorithm}
              highlight={
                cert.signature_algorithm?.toLowerCase().includes("sha1") ||
                cert.signature_algorithm?.toLowerCase().includes("md5")
                  ? "yellow"
                  : undefined
              }
            />
          </div>
        </div>

        {/* Flags */}
        <div className="flex flex-wrap gap-2">
          {cert.is_self_signed && (
            <Flag icon={XCircle} text="Self-Signed" color="rose" />
          )}
          {cert.is_expired && (
            <Flag icon={Calendar} text="Expired" color="rose" />
          )}
          {cert.serial_number === "0x1" && (
            <Flag icon={Hash} text="Serial = 1 (Debug cert)" color="yellow" />
          )}
          {!cert.is_self_signed && !cert.is_expired && (
            <Flag icon={CheckCircle2} text="Valid Dates" color="green" />
          )}
          {cert.publisher_match && (
            <Flag icon={CheckCircle2} text="Publisher Verified" color="green" />
          )}
        </div>

        {/* Score Reasons */}
        {cert.score_reasons && cert.score_reasons.length > 0 && (
          <div>
            <p className="text-[0.65rem] font-mono text-slate-500 uppercase tracking-wider mb-2">
              Risk Score Breakdown
            </p>
            <ul className="space-y-1.5">
              {cert.score_reasons.map((r, i) => (
                <li key={i} className="flex items-start gap-2">
                  <AlertTriangle className="w-3 h-3 text-yellow-400 mt-0.5 shrink-0" />
                  <span className="text-xs text-slate-300">{r}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* SHA-256 Fingerprint */}
        {(cert.sha256_fingerprint || cert.fingerprint_sha256) && (cert.sha256_fingerprint || cert.fingerprint_sha256) !== "unknown" && (
          <div>
            <p className="text-[0.65rem] font-mono text-slate-500 uppercase tracking-wider mb-1.5">
              SHA-256 Fingerprint
            </p>
            <div className="bg-slate-900/60 rounded-lg p-3 border border-white/5">
              <p className="font-mono text-[0.6rem] text-slate-300 break-all leading-relaxed">
                {formatFingerprint(cert.sha256_fingerprint || cert.fingerprint_sha256 || "")}
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Flag({
  icon: Icon,
  text,
  color,
}: {
  icon: React.ElementType;
  text: string;
  color: "rose" | "yellow" | "green";
}) {
  const styles = {
    rose: "bg-rose-500/10 text-rose-400 border-rose-500/20",
    yellow: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    green: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  };
  return (
    <span
      className={`text-xs px-2.5 py-1 rounded-full border flex items-center gap-1.5 ${styles[color]}`}
    >
      <Icon className="w-3 h-3" />
      {text}
    </span>
  );
}
