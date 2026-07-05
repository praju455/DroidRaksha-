// DroidRaksha — API client
import type { AnalysisResult, DashboardStats } from "./types";

export interface UploadResponse {
  job_id: string;
  status: "queued" | "complete";
  cached: boolean;
  ws_url?: string;
  result?: AnalysisResult; // only present when status=="complete" (cache hit or sync fallback)
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.detail ?? `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

/** Upload an APK file — returns immediately with job_id for async progress. */
export async function uploadApk(file: File): Promise<UploadResponse> {
  const fd = new FormData();
  fd.append("file", file);
  return request<UploadResponse>("/api/upload", { method: "POST", body: fd });
}

/** Fetch a previously-run analysis by ID. */
export async function getAnalysis(id: string): Promise<AnalysisResult> {
  return request<AnalysisResult>(`/api/analysis/${id}`);
}

/** Get dashboard stats. */
export async function getStats(): Promise<DashboardStats> {
  return request<DashboardStats>("/api/stats");
}

/** Download the PDF forensic report for an analysis. */
export function getReportUrl(id: string): string {
  return `${API_BASE}/api/report/${id}`;
}
