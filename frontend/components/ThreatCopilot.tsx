"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { MessageSquare, Send, X, Sparkles, Bot, User, Minimize2, Maximize2, Trash2 } from "lucide-react";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
}

interface ThreatCopilotProps {
  analysisId: string;
  activeTab: string;
  filename?: string;
  riskLevel?: string;
}

const SUGGESTED_QUESTIONS = [
  "Is this app safe to install?",
  "Explain the risk score in simple terms",
  "What permissions does this app abuse?",
  "What is a Banking Trojan?",
  "Why was this flagged as malware?",
  "What should I do if I already installed this?",
];

// Use relative path — Next.js rewrites /api/* → backend:8000 (works in Docker and local dev)

export default function ThreatCopilot({ analysisId, activeTab, filename, riskLevel }: ThreatCopilotProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(true);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  useEffect(() => {
    if (isOpen && !isMinimized) {
      inputRef.current?.focus();
    }
  }, [isOpen, isMinimized]);

  const sendMessage = async (question: string) => {
    if (!question.trim() || isStreaming) return;

    const userMsg: Message = {
      id: crypto.randomUUID(),
      role: "user",
      content: question.trim(),
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setShowSuggestions(false);
    setIsStreaming(true);

    const assistantId = crypto.randomUUID();
    setMessages((prev) => [
      ...prev,
      { id: assistantId, role: "assistant", content: "", timestamp: new Date() },
    ]);

    try {
      const res = await fetch(`/api/copilot/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          analysis_id: analysisId,
          question: question.trim(),
          context_tab: activeTab,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      const reader = res.body?.getReader();
      const decoder = new TextDecoder();

      if (!reader) throw new Error("No stream available");

      let fullText = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value, { stream: true });
        fullText += chunk;

        setMessages((prev) =>
          prev.map((m) =>
            m.id === assistantId ? { ...m, content: fullText } : m
          )
        );
      }
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : "Unknown error";
      setMessages((prev) =>
        prev.map((m) =>
          m.id === assistantId
            ? { ...m, content: `⚠️ Sorry, I couldn't connect to the AI service. Error: ${errorMessage}` }
            : m
        )
      );
    } finally {
      setIsStreaming(false);
    }
  };

  const clearChat = () => {
    setMessages([]);
    setShowSuggestions(true);
  };

  // Floating trigger button
  if (!isOpen) {
    return (
      <button
        id="copilot-trigger"
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 z-50 group"
        title="Open Threat Copilot"
      >
        <div className="relative flex items-center gap-2 bg-[rgba(0,0,0,0.9)] border border-[rgba(255,255,255,0.2)] px-4 py-3 backdrop-blur-xl hover:border-[rgba(255,255,255,0.5)] transition-all duration-300 hover:shadow-[0_0_30px_rgba(255,255,255,0.1)]"
          style={{ clipPath: "var(--clip-corner-md)" }}
        >
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-[rgba(255,255,255,0.03)] to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
          <Sparkles className="w-4 h-4 text-[#a78bfa] relative z-10" />
          <span className="text-[0.65rem] font-mono uppercase tracking-widest text-white relative z-10">
            Threat Copilot
          </span>
          {riskLevel && (riskLevel === "CRITICAL" || riskLevel === "HIGH") && (
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-[#f43f5e] rounded-full animate-pulse" />
          )}
        </div>
      </button>
    );
  }

  // Chat panel
  return (
    <div
      id="copilot-panel"
      className={`fixed z-50 transition-all duration-300 ${
        isMinimized
          ? "bottom-6 right-6 w-[320px]"
          : "bottom-6 right-6 w-[420px] h-[600px] max-h-[80vh]"
      }`}
    >
      <div
        className={`flex flex-col bg-[rgba(5,5,5,0.97)] border border-[rgba(255,255,255,0.15)] backdrop-blur-xl shadow-[0_0_60px_rgba(0,0,0,0.8)] overflow-hidden ${
          isMinimized ? "h-auto" : "h-full"
        }`}
        style={{ clipPath: "var(--clip-corner-md)" }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-[rgba(255,255,255,0.1)] bg-[rgba(255,255,255,0.02)] shrink-0">
          <div className="flex items-center gap-2">
            <div className="relative">
              <Bot className="w-4 h-4 text-[#a78bfa]" />
              <span className="absolute -bottom-0.5 -right-0.5 w-1.5 h-1.5 bg-[#4ade80] rounded-full" />
            </div>
            <div>
              <span className="text-[0.7rem] font-mono uppercase tracking-widest text-white font-bold">
                Threat Copilot
              </span>
              <span className="text-[0.55rem] font-mono text-[#94a3b8] block -mt-0.5">
                {isStreaming ? "Analyzing..." : "Online"}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={clearChat}
              className="p-1.5 text-[#94a3b8] hover:text-white transition-colors"
              title="Clear chat"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setIsMinimized(!isMinimized)}
              className="p-1.5 text-[#94a3b8] hover:text-white transition-colors"
              title={isMinimized ? "Expand" : "Minimize"}
            >
              {isMinimized ? <Maximize2 className="w-3.5 h-3.5" /> : <Minimize2 className="w-3.5 h-3.5" />}
            </button>
            <button
              onClick={() => { setIsOpen(false); setIsMinimized(false); }}
              className="p-1.5 text-[#94a3b8] hover:text-[#f43f5e] transition-colors"
              title="Close"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Body (hidden when minimized) */}
        {!isMinimized && (
          <>
            {/* Messages */}
            <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4 min-h-0">
              {/* Welcome message */}
              {messages.length === 0 && (
                <div className="space-y-4">
                  <div className="flex gap-2.5">
                    <div className="shrink-0 w-6 h-6 bg-[rgba(167,139,250,0.15)] border border-[rgba(167,139,250,0.3)] flex items-center justify-center mt-0.5">
                      <Bot className="w-3 h-3 text-[#a78bfa]" />
                    </div>
                    <div className="space-y-2">
                      <p className="text-[0.875rem] font-sans text-[#e2e8f0] leading-relaxed">
                        Hello! I&apos;m your <span className="text-[#a78bfa] font-semibold">Threat Copilot</span>.
                        I can explain anything you see on this analysis report in simple, everyday language.
                      </p>
                      <p className="text-[0.75rem] font-sans text-[#94a3b8]">
                        Analyzing: <span className="text-white font-medium">{filename || "this APK"}</span>
                      </p>
                    </div>
                  </div>

                  {/* Suggested questions */}
                  {showSuggestions && (
                    <div className="space-y-1.5 pl-8">
                      <p className="text-[0.7rem] font-mono text-[#94a3b8] uppercase tracking-widest mb-2">
                        Try asking:
                      </p>
                      {SUGGESTED_QUESTIONS.map((q) => (
                        <button
                          key={q}
                          onClick={() => sendMessage(q)}
                          className="block w-full text-left px-3 py-2 text-[0.8rem] font-sans text-[#94a3b8] bg-[rgba(255,255,255,0.03)] border border-[rgba(255,255,255,0.08)] hover:border-[rgba(167,139,250,0.4)] hover:text-[#a78bfa] hover:bg-[rgba(167,139,250,0.05)] transition-all duration-200"
                        >
                          {q}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Chat messages */}
              {messages.map((msg) => (
                <div key={msg.id} className={`flex gap-2.5 ${msg.role === "user" ? "flex-row-reverse" : ""}`}>
                  <div
                    className={`shrink-0 w-6 h-6 flex items-center justify-center mt-0.5 ${
                      msg.role === "user"
                        ? "bg-[rgba(255,255,255,0.1)] border border-[rgba(255,255,255,0.2)]"
                        : "bg-[rgba(167,139,250,0.15)] border border-[rgba(167,139,250,0.3)]"
                    }`}
                  >
                    {msg.role === "user" ? (
                      <User className="w-3 h-3 text-white" />
                    ) : (
                      <Bot className="w-3 h-3 text-[#a78bfa]" />
                    )}
                  </div>
                  <div
                    className={`max-w-[85%] px-4 py-3 text-[0.9375rem] font-sans leading-[1.7] ${
                      msg.role === "user"
                        ? "bg-[rgba(255,255,255,0.08)] border border-[rgba(255,255,255,0.15)] text-white"
                        : "bg-[rgba(167,139,250,0.05)] border border-[rgba(167,139,250,0.15)] text-[#e2e8f0]"
                    }`}
                  >
                    {msg.content || (
                      <span className="inline-flex items-center gap-1 text-[#94a3b8]">
                        <span className="w-1.5 h-1.5 bg-[#a78bfa] rounded-full animate-pulse" />
                        <span className="w-1.5 h-1.5 bg-[#a78bfa] rounded-full animate-pulse" style={{ animationDelay: "0.2s" }} />
                        <span className="w-1.5 h-1.5 bg-[#a78bfa] rounded-full animate-pulse" style={{ animationDelay: "0.4s" }} />
                      </span>
                    )}
                  </div>
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>

            {/* Input */}
            <div className="shrink-0 px-4 py-3 border-t border-[rgba(255,255,255,0.1)] bg-[rgba(255,255,255,0.02)]">
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  sendMessage(input);
                }}
                className="flex items-center gap-2"
              >
                <input
                  ref={inputRef}
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Ask about this analysis..."
                  disabled={isStreaming}
                  className="flex-1 bg-[rgba(255,255,255,0.05)] border border-[rgba(255,255,255,0.1)] text-white text-[0.875rem] font-sans px-3 py-2 outline-none focus:border-[rgba(167,139,250,0.5)] transition-colors placeholder:text-[#64748b] disabled:opacity-50"
                />
                <button
                  type="submit"
                  disabled={!input.trim() || isStreaming}
                  className="p-2 bg-[rgba(167,139,250,0.2)] border border-[rgba(167,139,250,0.3)] text-[#a78bfa] hover:bg-[rgba(167,139,250,0.3)] transition-all disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  <Send className="w-3.5 h-3.5" />
                </button>
              </form>
              <p className="text-[0.55rem] font-mono text-[#475569] mt-1.5 text-center">
                Powered by Gemini • Context-aware analysis
              </p>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
