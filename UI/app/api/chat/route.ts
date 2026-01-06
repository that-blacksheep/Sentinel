import { NextResponse } from "next/server";

export const runtime = "nodejs";

type ShieldVerdict = "SAFE" | "UNSAFE";

type ShieldResponse = {
  verdict?: ShieldVerdict | string;
  security_score?: number;
  reason?: string;
  message?: string;
};

type ScrubberResponse = {
  text?: string;
  clean_text?: string;
  redacted_text?: string;
  mapping?: Record<string, string>;
  masked_entities?: number;
};

type ChatRequestBody = {
  message?: unknown;
};

async function postJson<TResponse>(
  url: string,
  body: unknown,
  opts?: { timeoutMs?: number }
): Promise<TResponse> {
  const timeoutMs = opts?.timeoutMs ?? 12_000;
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`POST ${url} failed (${res.status}): ${text || res.statusText}`);
    }

    return (await res.json()) as TResponse;
  } finally {
    clearTimeout(id);
  }
}

async function openAIChatCompletion(input: string): Promise<string> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    throw new Error("Missing OPENAI_API_KEY env var");
  }

  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content:
            "You are Sentinel AI, a security-first enterprise assistant. Be concise, professional, and helpful.",
        },
        { role: "user", content: input },
      ],
    }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `OpenAI chat.completions failed (${res.status}): ${text || res.statusText}`
    );
  }

  const data = (await res.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
  };

  const content = data.choices?.[0]?.message?.content;
  if (!content) throw new Error("OpenAI returned an empty response");
  return content;
}

export async function POST(req: Request) {
  const startedAt = performance.now();

  try {
    const body = (await req.json().catch(() => null)) as ChatRequestBody | null;
    const message = typeof body?.message === "string" ? body.message.trim() : "";

    if (!message) {
      return NextResponse.json(
        { ok: false, error: "Missing message" },
        { status: 400 }
      );
    }

    // Step 1: The Shield
    const shield = await postJson<ShieldResponse>(
      "http://127.0.0.1:8000/docs",
      { text: message }
    );

    const rawVerdict = shield.verdict ?? "UNSAFE";
    const verdict: ShieldVerdict = rawVerdict === "SAFE" ? "SAFE" : "UNSAFE";
    const security_score =
      typeof shield.security_score === "number" ? shield.security_score : undefined;

    if (verdict === "UNSAFE") {
      const latencyMs = Math.max(1, Math.round(performance.now() - startedAt));
      return NextResponse.json(
        {
          ok: false,
          verdict,
          security_score,
          alert: {
            title: "Security Violation",
            description:
              shield.reason ||
              shield.message ||
              "Your message was blocked by Sentinel Shield.",
          },
          latencyMs,
        },
        { status: 403 }
      );
    }

    // Step 2: The Scrubber
    const scrub = await postJson<ScrubberResponse>(
      "http://127.0.0.1:8001/docs",
      { text: message }
    );

    const cleanText =
      scrub.clean_text ?? scrub.redacted_text ?? scrub.text ?? message;

    const mapping: Record<string, string> =
      scrub.mapping && typeof scrub.mapping === "object" ? scrub.mapping : {};

    const maskedEntities =
      typeof scrub.masked_entities === "number"
        ? scrub.masked_entities
        : Object.keys(mapping).length;

    // Step 3: AI Fetch
    const assistant = await openAIChatCompletion(cleanText);

    const latencyMs = Math.max(1, Math.round(performance.now() - startedAt));

    return NextResponse.json({
      ok: true,
      verdict: "SAFE" as const,
      security_score,
      maskedEntities,
      mapping,
      assistant,
      latencyMs,
    });
  } catch (err) {
    const latencyMs = Math.max(1, Math.round(performance.now() - startedAt));
    const message =
      err instanceof Error ? err.message : "Unknown server error";

    return NextResponse.json(
      { ok: false, error: message, latencyMs },
      { status: 500 }
    );
  }
}
