"use client";

import { useMemo, useRef, useState } from "react";

type NavItem = "chat" | "logs" | "admin";

type PipelineStep = "shield" | "scrubber" | "ai" | "rehydrate";
type StepStatus = "IDLE" | "RUNNING" | "PASSED" | "BLOCKED" | "DONE";

type SecurityVerdict = "SAFE" | "UNSAFE";

type LogVerdict = "SAFE" | "ML_GUARD";

type SecurityLogEntry = {
  id: string;
  ts: number; // epoch ms
  inputPreview: string;
  verdict: LogVerdict;
  security_score?: number;
  maskedEntities?: number;
  latencyMs?: number;
};

type ChatMessage = {
  id: string;
  role: "user" | "assistant" | "security";
  content: string;
  meta?: {
    latencyMs?: number;
    maskedEntities?: number;
    verdict?: SecurityVerdict;
    security_score?: number;
    blockedReason?: string;
  };
};

type SecurityAlert = {
  id: string;
  title: string;
  description: string;
  verdict: "ML_GUARD";
};

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

function delay(ms: number) {
  return new Promise<void>((resolve) => setTimeout(resolve, ms));
}

function scrubPII(input: string): {
  cleanText: string;
  mapping: Record<string, string>;
  maskedEntities: number;
} {
  const mapping: Record<string, string> = {};
  let idx = 1;

  // Emails
  const emailRegex =
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;

  let cleanText = input.replace(emailRegex, (match) => {
    const token = `[USER_${idx}]`;
    mapping[token] = match;
    idx += 1;
    return token;
  });

  // Very light "Name-like" masking (demo only): two capitalized words
  const nameRegex = /\b([A-Z][a-z]{2,})\s([A-Z][a-z]{2,})\b/g;
  cleanText = cleanText.replace(nameRegex, (match) => {
    // Avoid double-masking things already turned into tokens
    if (match.includes("[USER_")) return match;
    const token = `[USER_${idx}]`;
    mapping[token] = match;
    idx += 1;
    return token;
  });

  return { cleanText, mapping, maskedEntities: Object.keys(mapping).length };
}

function rehydrate(text: string, mapping: Record<string, string>) {
  let out = text;
  for (const [token, value] of Object.entries(mapping)) {
    out = out.split(token).join(value);
  }
  return out;
}

function looksUnsafe(input: string): { unsafe: boolean; reason?: string } {
  const s = input.toLowerCase();

  const rules: Array<{ test: (t: string) => boolean; reason: string }> = [
    {
      test: (t) => /\bssn\b|\bsocial security\b|\bcredit card\b|\bcard number\b/.test(t),
      reason: "Possible sensitive identifier detected (SSN / card data).",
    },
    {
      test: (t) => /\bpassword\b|\bpasscode\b|\b2fa\b|\bone-time code\b/.test(t),
      reason: "Possible credential or authentication secret detected.",
    },
    {
      test: (t) => /\bignore (all|any) (previous|prior) instructions\b|\bsystem prompt\b/.test(t),
      reason: "Potential prompt-injection pattern detected.",
    },
  ];

  const hit = rules.find((r) => r.test(s));
  return hit ? { unsafe: true, reason: hit.reason } : { unsafe: false };
}

export default function Home() {
  const [active, setActive] = useState<NavItem>("chat");
  const [draft, setDraft] = useState<string>("");
  const [messages, setMessages] = useState<ChatMessage[]>(() => [
    {
      id: "m1",
      role: "assistant",
      content:
        "Welcome to Sentinel AI. Your messages will be screened and redacted before any AI processing.",
    },
  ]);

  const [processing, setProcessing] = useState<boolean>(false);
  const [pipeline, setPipeline] = useState<Record<PipelineStep, StepStatus>>({
    shield: "IDLE",
    scrubber: "IDLE",
    ai: "IDLE",
    rehydrate: "IDLE",
  });

  const [alert, setAlert] = useState<SecurityAlert | null>(null);
  const [lastMetrics, setLastMetrics] = useState<{
    latencyMs?: number;
    maskedEntities?: number;
  }>({});

  const [securityLogs, setSecurityLogs] = useState<SecurityLogEntry[]>(() => []);

  const scrollRef = useRef<HTMLDivElement | null>(null);

  const title = useMemo(() => {
    switch (active) {
      case "chat":
        return "AI Chat";
      case "logs":
        return "Security Logs";
      case "admin":
        return "Admin Dashboard";
      default:
        return "Sentinel AI";
    }
  }, [active]);

  function scrollToBottomSoon() {
    window.setTimeout(() => {
      scrollRef.current?.scrollTo({
        top: scrollRef.current.scrollHeight,
        behavior: "smooth",
      });
    }, 50);
  }

  async function sendLocalMessage() {
    const trimmed = draft.trim();
    if (!trimmed || processing) return;

    setAlert(null);
    setProcessing(true);
    setDraft("");
    setPipeline({ shield: "IDLE", scrubber: "IDLE", ai: "IDLE", rehydrate: "IDLE" });

    const startedAt = performance.now();
    const userMessageId = crypto.randomUUID();

    setMessages((prev) => [
      ...prev,
      { id: userMessageId, role: "user", content: trimmed },
    ]);
    scrollToBottomSoon();

    // Step 1: The Shield (UI simulation)
    setPipeline((p) => ({ ...p, shield: "RUNNING" }));
    await delay(450);

    const { unsafe, reason } = looksUnsafe(trimmed);
    const security_score = unsafe ? 0.92 : 0.08;

    if (unsafe) {
      setPipeline((p) => ({ ...p, shield: "BLOCKED", scrubber: "IDLE", ai: "IDLE", rehydrate: "IDLE" }));

      const violationId = crypto.randomUUID();
      setAlert({
        id: violationId,
        title: "Security Violation",
        description:
          reason ??
          "Your message was blocked by Sentinel Shield. Please remove sensitive content and try again.",
        verdict: "ML_GUARD",
      });

      setMessages((prev) => [
        ...prev,
        {
          id: crypto.randomUUID(),
          role: "security",
          content:
            "Message blocked by Sentinel Shield (ML_GUARD). Remove sensitive content and retry.",
          meta: {
            verdict: "UNSAFE",
            security_score,
            blockedReason: reason,
          },
        },
      ]);

      const latencyMs = Math.max(1, Math.round(performance.now() - startedAt));
      setSecurityLogs((prev) => [
        {
          id: crypto.randomUUID(),
          ts: Date.now(),
          inputPreview: trimmed,
          verdict: "ML_GUARD",
          security_score,
          latencyMs,
          maskedEntities: 0,
        },
        ...prev,
      ]);

      setProcessing(false);
      scrollToBottomSoon();
      return;
    }

    setPipeline((p) => ({ ...p, shield: "PASSED" }));

    // Step 2: The Scrubber (UI simulation)
    setPipeline((p) => ({ ...p, scrubber: "RUNNING" }));
    await delay(380);

    const { cleanText, mapping, maskedEntities } = scrubPII(trimmed);
    setPipeline((p) => ({ ...p, scrubber: "DONE" }));

    // Step 3: AI Fetch (UI simulation)
    setPipeline((p) => ({ ...p, ai: "RUNNING" }));
    await delay(700);

    const assistantDraftWithPlaceholders =
      "UI preview only (no backend yet).\n\n" +
      "I received your redacted message:\n" +
      `\"${cleanText}\"\n\n` +
      "Next step will send the clean text to the real orchestration API.";

    setPipeline((p) => ({ ...p, ai: "DONE" }));

    // Step 4: Re-hydration (UI simulation)
    setPipeline((p) => ({ ...p, rehydrate: "RUNNING" }));
    await delay(250);

    const assistantVisible = rehydrate(assistantDraftWithPlaceholders, mapping);
    setPipeline((p) => ({ ...p, rehydrate: "DONE" }));

    const latencyMs = Math.max(1, Math.round(performance.now() - startedAt));
    setLastMetrics({ latencyMs, maskedEntities });

    setMessages((prev) => [
      ...prev,
      {
        id: crypto.randomUUID(),
        role: "assistant",
        content: assistantVisible,
        meta: {
          verdict: "SAFE",
          security_score,
          latencyMs,
          maskedEntities,
        },
      },
    ]);

    setSecurityLogs((prev) => [
      {
        id: crypto.randomUUID(),
        ts: Date.now(),
        inputPreview: trimmed,
        verdict: "SAFE",
        security_score,
        maskedEntities,
        latencyMs,
      },
      ...prev,
    ]);

    setProcessing(false);
    scrollToBottomSoon();
  }

  const pipelineLabel: Record<PipelineStep, string> = {
    shield: "Shield",
    scrubber: "Scrubber",
    ai: "AI Fetch",
    rehydrate: "Re-hydration",
  };

  const adminStats = useMemo(() => {
    const total = securityLogs.length;
    const blocked = securityLogs.filter((l) => l.verdict === "ML_GUARD").length;
    const safe = securityLogs.filter((l) => l.verdict === "SAFE").length;

    const maskedSum = securityLogs.reduce(
      (acc, l) => acc + (l.maskedEntities ?? 0),
      0
    );

    const latencyValues = securityLogs
      .map((l) => l.latencyMs)
      .filter((v): v is number => typeof v === "number");

    const avgLatency =
      latencyValues.length > 0
        ? Math.round(latencyValues.reduce((a, b) => a + b, 0) / latencyValues.length)
        : undefined;

    const complianceScore =
      total > 0 ? Math.round((safe / total) * 100) : undefined;

    return {
      total,
      blocked,
      maskedSum,
      avgLatency,
      complianceScore,
    };
  }, [securityLogs]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Subtle security-themed background */}
      <div className="pointer-events-none fixed inset-0 opacity-60">
        <div className="absolute -top-24 left-1/2 h-96 w-[72rem] -translate-x-1/2 rounded-full bg-gradient-to-r from-cyan-500/10 via-emerald-500/5 to-indigo-500/10 blur-3xl" />
        <div className="absolute bottom-0 left-0 h-80 w-80 rounded-full bg-rose-500/5 blur-3xl" />
      </div>

      <div className="relative mx-auto flex min-h-screen max-w-[1400px] gap-4 p-4 md:p-6">
        {/* Sidebar */}
        <aside className="flex w-[280px] flex-col rounded-2xl border border-white/10 bg-slate-900/60 backdrop-blur">
          <div className="flex items-center justify-between gap-3 border-b border-white/10 px-4 py-4">
            <div className="flex items-center gap-3">
              <div className="grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br from-cyan-400/20 via-emerald-400/10 to-indigo-400/20 ring-1 ring-white/10">
                <div className="h-4 w-4 rounded-sm bg-cyan-300/80 shadow-[0_0_18px_rgba(34,211,238,0.35)]" />
              </div>
              <div className="leading-tight">
                <div className="text-sm font-semibold tracking-wide">
                  Sentinel AI
                </div>
                <div className="text-xs text-slate-400">Security Orchestrator</div>
              </div>
            </div>

            <span className="rounded-full border border-emerald-400/20 bg-emerald-400/10 px-2 py-1 text-[11px] font-medium text-emerald-200">
              Secure Mode
            </span>
          </div>

          <nav className="flex flex-col gap-1 p-2">
            <SidebarButton
              active={active === "chat"}
              title="AI Chat"
              subtitle="Screened conversations"
              onClick={() => setActive("chat")}
              icon={
                <svg
                  viewBox="0 0 24 24"
                  className="h-5 w-5"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.8"
                >
                  <path d="M7 8h10M7 12h7M9 20l-3 2v-4a7 7 0 1 1 2 2z" />
                </svg>
              }
            />
            <SidebarButton
              active={active === "logs"}
              title="Security Logs"
              subtitle="Verdicts & signals"
              onClick={() => setActive("logs")}
              icon={
                <svg
                  viewBox="0 0 24 24"
                  className="h-5 w-5"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.8"
                >
                  <path d="M4 5h16M4 12h16M4 19h16" />
                  <path d="M9 5v14" opacity="0.7" />
                </svg>
              }
            />
            <SidebarButton
              active={active === "admin"}
              title="Admin Dashboard"
              subtitle="Controls & metrics"
              onClick={() => setActive("admin")}
              icon={
                <svg
                  viewBox="0 0 24 24"
                  className="h-5 w-5"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.8"
                >
                  <path d="M4 13h7V4H4v9zm9 7h7V11h-7v9zM13 4h7v5h-7V4zM4 16h7v4H4v-4z" />
                </svg>
              }
            />
          </nav>

          <div className="mt-auto border-t border-white/10 p-4">
            <div className="rounded-xl border border-white/10 bg-slate-950/40 p-3">
              <div className="text-xs font-semibold text-slate-200">
                Orchestration
              </div>
              <div className="mt-2 space-y-2 text-xs text-slate-400">
                {(Object.keys(pipeline) as PipelineStep[]).map((k) => (
                  <PipelineRow key={k} label={pipelineLabel[k]} status={pipeline[k]} />
                ))}
              </div>
            </div>
          </div>
        </aside>

        {/* Main */}
        <main className="flex min-w-0 flex-1 flex-col overflow-hidden rounded-2xl border border-white/10 bg-slate-900/40 backdrop-blur">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 px-4 py-4 md:px-6">
            <div>
              <div className="text-sm font-semibold">{title}</div>
              <div className="text-xs text-slate-400">
                Security-first AI workspace • Dark Mode
              </div>
            </div>

            <div className="flex items-center gap-2">
              {typeof lastMetrics.latencyMs === "number" ? (
                <span className="hidden rounded-full border border-white/10 bg-slate-950/40 px-3 py-1 text-xs text-slate-300 md:inline">
                  Avg latency (local): {lastMetrics.latencyMs}ms
                </span>
              ) : null}
              {typeof lastMetrics.maskedEntities === "number" ? (
                <span className="hidden rounded-full border border-white/10 bg-slate-950/40 px-3 py-1 text-xs text-slate-300 md:inline">
                  Masked: {lastMetrics.maskedEntities}
                </span>
              ) : null}
              <span className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs text-cyan-200">
                Online
              </span>
            </div>
          </div>

          {/* Content */}
          {active === "chat" ? (
            <div className="flex min-h-0 flex-1 flex-col">
              {/* Alerts */}
              {alert ? (
                <div className="px-4 pt-4 md:px-6">
                  <div className="rounded-2xl border border-rose-400/20 bg-rose-500/10 p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="relative inline-flex h-2.5 w-2.5">
                            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-rose-400/60" />
                            <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-rose-400" />
                          </span>
                          <div className="text-sm font-semibold text-rose-100">
                            {alert.title}
                          </div>
                          <span className="rounded-full border border-rose-400/20 bg-rose-400/10 px-2 py-0.5 text-[11px] font-semibold text-rose-200">
                            {alert.verdict}
                          </span>
                        </div>
                        <div className="mt-1 text-sm text-rose-100/80">
                          {alert.description}
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={() => setAlert(null)}
                        className="shrink-0 rounded-xl border border-white/10 bg-slate-950/30 px-3 py-2 text-xs font-semibold text-slate-100 transition hover:bg-slate-950/50"
                      >
                        Dismiss
                      </button>
                    </div>
                  </div>
                </div>
              ) : null}

              {/* Messages */}
              <div
                ref={scrollRef}
                className="min-h-0 flex-1 overflow-y-auto px-4 py-6 md:px-6"
              >
                <div className="mx-auto flex w-full max-w-3xl flex-col gap-4">
                  {messages.map((m) => (
                    <div
                      key={m.id}
                      className={cx(
                        "group flex w-full gap-3",
                        m.role === "user" ? "justify-end" : "justify-start"
                      )}
                    >
                      {m.role !== "user" ? (
                        <div
                          className={cx(
                            "mt-1 h-8 w-8 shrink-0 rounded-lg ring-1",
                            m.role === "assistant"
                              ? "bg-gradient-to-br from-cyan-400/20 via-emerald-400/10 to-indigo-400/20 ring-white/10"
                              : "bg-rose-500/10 ring-rose-400/20"
                          )}
                        />
                      ) : null}

                      <div className="max-w-[85%]">
                        <div
                          className={cx(
                            "rounded-2xl border px-4 py-3 text-sm leading-relaxed shadow-sm",
                            m.role === "user"
                              ? "border-cyan-400/20 bg-cyan-400/10 text-slate-50"
                              : m.role === "assistant"
                                ? "border-white/10 bg-slate-950/40 text-slate-100"
                                : "border-rose-400/20 bg-rose-500/10 text-rose-50"
                          )}
                        >
                          <div className="whitespace-pre-wrap">{m.content}</div>
                        </div>

                        {m.meta?.verdict ? (
                          <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
                            <span
                              className={cx(
                                "rounded-full border px-2 py-0.5 font-semibold",
                                m.meta.verdict === "SAFE"
                                  ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-200"
                                  : "border-rose-400/20 bg-rose-400/10 text-rose-200"
                              )}
                            >
                              Verdict: {m.meta.verdict}
                            </span>
                            {typeof m.meta.security_score === "number" ? (
                              <span className="rounded-full border border-white/10 bg-slate-950/30 px-2 py-0.5">
                                security_score: {m.meta.security_score.toFixed(2)}
                              </span>
                            ) : null}
                            {typeof m.meta.maskedEntities === "number" ? (
                              <span className="rounded-full border border-white/10 bg-slate-950/30 px-2 py-0.5">
                                masked_entities: {m.meta.maskedEntities}
                              </span>
                            ) : null}
                            {typeof m.meta.latencyMs === "number" ? (
                              <span className="rounded-full border border-white/10 bg-slate-950/30 px-2 py-0.5">
                                latency: {m.meta.latencyMs}ms
                              </span>
                            ) : null}
                          </div>
                        ) : null}

                        {m.role === "security" && m.meta?.blockedReason ? (
                          <div className="mt-2 text-[11px] text-rose-100/70">
                            Reason: {m.meta.blockedReason}
                          </div>
                        ) : null}
                      </div>

                      {m.role === "user" ? (
                        <div className="mt-1 h-8 w-8 shrink-0 rounded-lg bg-slate-950/40 ring-1 ring-white/10" />
                      ) : null}
                    </div>
                  ))}

                  {/* Processing indicator */}
                  {processing ? (
                    <div className="mx-auto w-full max-w-3xl rounded-2xl border border-white/10 bg-slate-950/30 p-4">
                      <div className="flex items-center justify-between gap-3">
                        <div className="text-xs font-semibold text-slate-200">
                          Processing request
                        </div>
                        <div className="text-xs text-slate-400">
                          Shield → Scrubber → AI → Re-hydration
                        </div>
                      </div>
                      <div className="mt-3 grid gap-2 sm:grid-cols-4">
                        {(Object.keys(pipeline) as PipelineStep[]).map((k) => (
                          <div
                            key={k}
                            className="rounded-xl border border-white/10 bg-slate-950/30 px-3 py-2"
                          >
                            <div className="flex items-center justify-between">
                              <div className="text-[11px] font-semibold text-slate-200">
                                {pipelineLabel[k]}
                              </div>
                              <StatusPill status={pipeline[k]} />
                            </div>
                            <div className="mt-1 text-[11px] text-slate-500">
                              {pipeline[k] === "RUNNING"
                                ? "Running…"
                                : pipeline[k] === "PASSED"
                                  ? "Passed"
                                  : pipeline[k] === "BLOCKED"
                                    ? "Blocked"
                                    : pipeline[k] === "DONE"
                                      ? "Complete"
                                      : "Queued"}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              </div>

              {/* Composer */}
              <div className="border-t border-white/10 bg-slate-950/20 px-4 py-4 md:px-6">
                <div className="mx-auto w-full max-w-3xl">
                  <div className="rounded-2xl border border-white/10 bg-slate-950/40 p-2 shadow-[0_0_0_1px_rgba(255,255,255,0.03)]">
                    <div className="flex items-end gap-2">
                      <div className="flex-1">
                        <label className="sr-only" htmlFor="message">
                          Message Sentinel AI
                        </label>
                        <textarea
                          id="message"
                          value={draft}
                          disabled={processing}
                          onChange={(e) => setDraft(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                              e.preventDefault();
                              void sendLocalMessage();
                            }
                          }}
                          placeholder={
                            processing
                              ? "Processing…"
                              : "Message Sentinel AI… (Ctrl/⌘ + Enter to send)"
                          }
                          rows={1}
                          className="max-h-40 w-full resize-none bg-transparent px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none disabled:cursor-not-allowed disabled:opacity-70"
                        />
                      </div>

                      <button
                        type="button"
                        disabled={processing || draft.trim().length === 0}
                        onClick={() => void sendLocalMessage()}
                        className={cx(
                          "inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold transition focus:outline-none focus:ring-2 focus:ring-cyan-300/40",
                          processing || draft.trim().length === 0
                            ? "cursor-not-allowed border border-white/10 bg-slate-950/30 text-slate-400"
                            : "bg-gradient-to-r from-cyan-500/90 to-emerald-500/90 text-slate-950 shadow-[0_8px_24px_rgba(34,211,238,0.18)] hover:from-cyan-400/90 hover:to-emerald-400/90"
                        )}
                      >
                        {processing ? "Working" : "Send"}
                        <svg
                          viewBox="0 0 24 24"
                          className="h-4 w-4"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2"
                        >
                          <path d="M22 2L11 13" />
                          <path d="M22 2l-7 20-4-9-9-4 20-7z" />
                        </svg>
                      </button>
                    </div>

                    <div className="mt-2 flex items-center justify-between px-3 pb-1 text-[11px] text-slate-500">
                      <div className="flex items-center gap-2">
                        <span className="inline-flex items-center gap-1 rounded-full border border-white/10 bg-slate-950/40 px-2 py-0.5">
                          <span
                            className={cx(
                              "h-1.5 w-1.5 rounded-full",
                              processing ? "bg-cyan-300/80" : "bg-emerald-400/80"
                            )}
                          />
                          {processing ? "Pipeline running" : "Screening enabled"}
                        </span>
                        <span className="hidden sm:inline">
                          Try entering an email or a name; try "my password is …" to see a block
                        </span>
                      </div>
                      <div className="hidden sm:block">UI simulation</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : active === "logs" ? (
            <div className="flex min-h-0 flex-1 flex-col px-4 py-6 md:px-6">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="text-sm font-semibold text-slate-100">
                    Security Logs
                  </div>
                  <div className="mt-1 text-sm text-slate-400">
                    Real-time interaction ledger with verdicts and security signals.
                  </div>
                </div>
                <span className="rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-xs font-semibold text-emerald-200">
                  Live
                </span>
              </div>

              <div className="mt-4 overflow-hidden rounded-2xl border border-white/10 bg-slate-950/40">
                <div className="flex items-center justify-between gap-3 border-b border-white/10 px-4 py-3">
                  <div className="text-xs font-semibold text-slate-200">
                    Recent Events
                  </div>
                  <div className="text-xs text-slate-400">
                    Total: {adminStats.total} • Blocked: {adminStats.blocked}
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full min-w-[920px] text-left text-sm">
                    <thead className="bg-slate-950/30 text-[11px] uppercase tracking-wide text-slate-400">
                      <tr className="[&>th]:px-4 [&>th]:py-3">
                        <th>Time</th>
                        <th>Input</th>
                        <th>Verdict</th>
                        <th>security_score</th>
                        <th>masked_entities</th>
                        <th>latency</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/10">
                      {securityLogs.length === 0 ? (
                        <tr>
                          <td
                            colSpan={6}
                            className="px-4 py-10 text-center text-sm text-slate-500"
                          >
                            No logs yet. Send a message in AI Chat to generate events.
                          </td>
                        </tr>
                      ) : (
                        securityLogs.map((row) => (
                          <tr
                            key={row.id}
                            className="bg-transparent transition hover:bg-white/[0.03]"
                          >
                            <td className="px-4 py-3 text-xs text-slate-400">
                              {new Date(row.ts).toLocaleTimeString([], {
                                hour: "2-digit",
                                minute: "2-digit",
                                second: "2-digit",
                              })}
                            </td>
                            <td className="px-4 py-3">
                              <div className="max-w-[560px] truncate text-sm text-slate-200">
                                {row.inputPreview}
                              </div>
                            </td>
                            <td className="px-4 py-3">
                              <VerdictBadge verdict={row.verdict} />
                            </td>
                            <td className="px-4 py-3 text-xs text-slate-300">
                              {typeof row.security_score === "number"
                                ? row.security_score.toFixed(2)
                                : "—"}
                            </td>
                            <td className="px-4 py-3 text-xs text-slate-300">
                              {typeof row.maskedEntities === "number"
                                ? row.maskedEntities
                                : "—"}
                            </td>
                            <td className="px-4 py-3 text-xs text-slate-300">
                              {typeof row.latencyMs === "number"
                                ? `${row.latencyMs}ms`
                                : "—"}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex min-h-0 flex-1 flex-col px-4 py-6 md:px-6">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="text-sm font-semibold text-slate-100">
                    Admin Dashboard
                  </div>
                  <div className="mt-1 text-sm text-slate-400">
                    Live operational metrics for Sentinel AI.
                  </div>
                </div>
                <span className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs font-semibold text-cyan-200">
                  Security Dark Mode
                </span>
              </div>

              <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <StatCard
                  title="Threats Blocked"
                  value={adminStats.blocked}
                  sub="ML_GUARD blocks"
                  accent="rose"
                />
                <StatCard
                  title="Masked Entities"
                  value={adminStats.maskedSum}
                  sub="PII scrubbed"
                  accent="cyan"
                />
                <StatCard
                  title="Avg Latency"
                  value={
                    typeof adminStats.avgLatency === "number"
                      ? `${adminStats.avgLatency}ms`
                      : "—"
                  }
                  sub="Pipeline time (local sim)"
                  accent="emerald"
                />
                <StatCard
                  title="Compliance Score"
                  value={
                    typeof adminStats.complianceScore === "number"
                      ? `${adminStats.complianceScore}%`
                      : "—"
                  }
                  sub="SAFE / total"
                  accent="indigo"
                />
              </div>

              <div className="mt-6 rounded-2xl border border-white/10 bg-slate-950/40 p-5">
                <div className="flex items-center justify-between gap-3">
                  <div className="text-sm font-semibold text-slate-100">
                    Operational Notes
                  </div>
                  <span className="rounded-full border border-white/10 bg-slate-950/30 px-3 py-1 text-xs text-slate-300">
                    Live from Security Logs
                  </span>
                </div>
                <div className="mt-2 text-sm text-slate-400">
                  Metrics update in real time as interactions occur. Blocked messages
                  are labeled <span className="text-rose-200">ML_GUARD</span>; safe
                  messages are labeled <span className="text-emerald-200">SAFE</span>.
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

function SidebarButton(props: {
  active: boolean;
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      className={cx(
        "group flex w-full items-center gap-3 rounded-xl border px-3 py-3 text-left transition focus:outline-none focus:ring-2 focus:ring-cyan-300/30",
        props.active
          ? "border-cyan-400/25 bg-cyan-400/10"
          : "border-transparent hover:border-white/10 hover:bg-slate-950/30"
      )}
    >
      <div
        className={cx(
          "grid h-10 w-10 place-items-center rounded-xl ring-1 transition",
          props.active
            ? "bg-cyan-400/10 text-cyan-200 ring-cyan-300/20"
            : "bg-slate-950/30 text-slate-300 ring-white/10 group-hover:ring-white/20"
        )}
      >
        {props.icon}
      </div>
      <div className="min-w-0">
        <div className="truncate text-sm font-semibold text-slate-100">
          {props.title}
        </div>
        <div className="truncate text-xs text-slate-400">{props.subtitle}</div>
      </div>
    </button>
  );
}

function PipelineRow(props: { label: string; status: StepStatus }) {
  const pill = (() => {
    switch (props.status) {
      case "RUNNING":
        return "bg-cyan-400/10 text-cyan-200 border-cyan-300/20";
      case "PASSED":
      case "DONE":
        return "bg-emerald-400/10 text-emerald-200 border-emerald-300/20";
      case "BLOCKED":
        return "bg-rose-400/10 text-rose-200 border-rose-300/20";
      default:
        return "bg-slate-950/40 text-slate-400 border-white/10";
    }
  })();

  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-slate-300">{props.label}</span>
      <span className={cx("rounded-full border px-2 py-0.5 text-[11px]", pill)}>
        {props.status}
      </span>
    </div>
  );
}

function StatusPill(props: { status: StepStatus }) {
  const cls = (() => {
    switch (props.status) {
      case "RUNNING":
        return "border-cyan-300/20 bg-cyan-400/10 text-cyan-200";
      case "PASSED":
      case "DONE":
        return "border-emerald-300/20 bg-emerald-400/10 text-emerald-200";
      case "BLOCKED":
        return "border-rose-300/20 bg-rose-400/10 text-rose-200";
      default:
        return "border-white/10 bg-slate-950/40 text-slate-400";
    }
  })();

  return (
    <span className={cx("rounded-full border px-2 py-0.5 text-[11px] font-semibold", cls)}>
      {props.status === "IDLE" ? "QUEUED" : props.status}
    </span>
  );
}

function VerdictBadge(props: { verdict: LogVerdict }) {
  if (props.verdict === "SAFE") {
    return (
      <span className="inline-flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-2.5 py-1 text-[11px] font-semibold text-emerald-200">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400/80" />
        SAFE
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-rose-400/20 bg-rose-400/10 px-2.5 py-1 text-[11px] font-semibold text-rose-200">
      <span className="relative inline-flex h-2 w-2">
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-rose-400/60" />
        <span className="relative inline-flex h-2 w-2 rounded-full bg-rose-400" />
      </span>
      ML_GUARD
    </span>
  );
}

function StatCard(props: {
  title: string;
  value: number | string;
  sub: string;
  accent: "rose" | "cyan" | "emerald" | "indigo";
}) {
  const accentCls =
    props.accent === "rose"
      ? "from-rose-500/15 via-rose-500/5 to-transparent border-rose-400/15"
      : props.accent === "cyan"
        ? "from-cyan-500/15 via-cyan-500/5 to-transparent border-cyan-400/15"
        : props.accent === "emerald"
          ? "from-emerald-500/15 via-emerald-500/5 to-transparent border-emerald-400/15"
          : "from-indigo-500/15 via-indigo-500/5 to-transparent border-indigo-400/15";

  return (
    <div
      className={cx(
        "rounded-2xl border bg-gradient-to-br p-5 shadow-[0_0_0_1px_rgba(255,255,255,0.03)]",
        accentCls
      )}
    >
      <div className="text-xs font-semibold text-slate-300">{props.title}</div>
      <div className="mt-2 text-2xl font-semibold tracking-tight text-slate-100">
        {props.value}
      </div>
      <div className="mt-1 text-xs text-slate-400">{props.sub}</div>
    </div>
  );
}
