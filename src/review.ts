/**
 * LLM review feature for opencode-dcg-plugin.
 *
 * When dcg blocks a command, this module asks an OpenCode LLM subsession to
 * review whether the command is safe despite matching a destructive pattern.
 * If the LLM approves, the command is allowed for that single invocation only.
 *
 * The review uses OpenCode's own session API (`client.session.create` +
 * `client.session.prompt`), so it works with whatever model/provider the user
 * has configured in OpenCode — no external API key required. A subsession
 * appears in the TUI as a side effect.
 *
 * Recent conversation context from the parent session is fetched via
 * `client.session.messages()` and included in the review prompt, so the LLM
 * understands what the agent was doing when it tried to run the command.
 */
import type {
  DcgDecision,
  DcgPluginConfig,
  ReviewResult,
  OpencodeSessionClient,
  Logger,
} from "./index.js";

// ---------------------------------------------------------------------------
// Context fetching
// ---------------------------------------------------------------------------

/**
 * Fetch recent messages from the parent session and format them as a
 * conversation summary so the review LLM has context for its safety judgment.
 * Returns null if the session ID is missing or the fetch fails.
 *
 * @param messageLimit  Max messages to fetch from the parent session.
 * @param maxChars       Max characters of context to include in the prompt.
 */
export async function fetchSessionContext(
  client: OpencodeSessionClient,
  sessionID: string | undefined,
  messageLimit: number,
  maxChars: number,
): Promise<string | null> {
  if (!sessionID) return null;

  let messages: Array<{
    info: { role: "user" | "assistant" };
    parts: Array<{ type: string; text?: string; tool?: string }>;
  }>;
  try {
    const result = await client.session.messages({
      path: { id: sessionID },
      query: { limit: messageLimit },
    });
    messages = result.data ?? [];
  } catch {
    return null; // Non-fatal — review proceeds without context
  }
  if (messages.length === 0) return null;

  const lines: string[] = [];
  let totalChars = 0;

  for (const msg of messages) {
    const role = msg.info.role === "user" ? "User" : "Assistant";

    // Extract text parts and tool-call names from the message
    const textParts: string[] = [];
    for (const part of msg.parts) {
      if (part.type === "text" && part.text) {
        textParts.push(part.text);
      } else if (part.type === "tool" && part.tool) {
        textParts.push(`[tool: ${part.tool}]`);
      }
    }

    if (textParts.length === 0) continue;
    const content = textParts.join(" ");
    const line = `${role}: ${content}`;

    // Stop if we'd exceed the character budget
    if (totalChars + line.length > maxChars) break;
    lines.push(line);
    totalChars += line.length;
  }

  if (lines.length === 0) return null;
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Prompt building
// ---------------------------------------------------------------------------

/**
 * System prompt instructing the LLM to act as a command safety reviewer.
 * The LLM is told to respond with ONLY a JSON object — no tools, no prose.
 */
export function buildSystemPrompt(): string {
  return [
    "You are a command safety reviewer for an AI coding assistant.",
    "A command was blocked by the destructive_command_guard (dcg) because it matched a destructive pattern.",
    "Your task is to review whether the command is safe to execute in the current context.",
    "",
    "Do not use any tools. Respond with ONLY a JSON object, no markdown or other text:",
    '  {"safe": true, "reasoning": "brief explanation"}',
    '  {"safe": false, "reasoning": "brief explanation"}',
    "",
    "Consider:",
    "- Is this a legitimate development operation in this context?",
    "- Could it cause irreversible data loss or system damage?",
    "- Is the command scoped appropriately for the working directory?",
    "- Even if the pattern is generally destructive, is this specific usage justified?",
    "",
    "Be conservative: when in doubt, respond with safe: false.",
  ].join("\n");
}

/**
 * Build the user-facing prompt containing the blocked command details.
 * If conversation context is provided, it's included so the review LLM
 * understands what the agent was doing when it tried to run the command.
 */
export function buildUserPrompt(
  command: string,
  decision: DcgDecision,
  directory: string,
  context?: string | null,
): string {
  const lines: string[] = [];

  if (context) {
    lines.push("Conversation context (what the agent was doing):");
    lines.push(context);
    lines.push("");
    lines.push("---");
    lines.push("");
  }

  lines.push(`Command: ${command}`);
  lines.push("");
  lines.push(`Blocked by rule: ${decision.rule_id ?? "unknown"}`);
  if (decision.severity) lines.push(`Severity: ${decision.severity}`);
  if (decision.reason) lines.push(`Reason: ${decision.reason}`);
  if (decision.explanation) {
    lines.push("");
    lines.push(`Explanation:\n${decision.explanation}`);
  }
  lines.push("");
  lines.push(`Working directory: ${directory}`);
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

/**
 * Parse the LLM's review response into a ReviewResult.
 *
 * Tries JSON first (stripping markdown code fences if present). Falls back to
 * keyword detection. Defaults to "not approved" (conservative) on any failure.
 */
export function parseReviewResponse(text: string): ReviewResult {
  const trimmed = text.trim();
  if (!trimmed) {
    return { approved: false, reasoning: "empty response" };
  }

  // Strip markdown code fences if present (```json ... ``` or ``` ... ```)
  const cleaned = trimmed
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```\s*$/i, "")
    .trim();

  // Try JSON extraction: find the first { ... } in the text
  const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
  if (jsonMatch) {
    try {
      const parsed = JSON.parse(jsonMatch[0]);
      if (typeof parsed === "object" && parsed !== null) {
        const safe = parsed.safe;
        const reasoning = parsed.reasoning;
        if (typeof safe === "boolean") {
          return {
            approved: safe,
            reasoning: typeof reasoning === "string" ? reasoning : undefined,
          };
        }
      }
    } catch {
      // Fall through to keyword detection
    }
  }

  // Fallback: keyword detection (conservative — deny signals take priority)
  const lower = trimmed.toLowerCase();
  const denyStems = [
    "unsafe", "danger", "deny", "block", "prevent", "reject",
    "forbid", "do not", "should not", "must not",
  ];
  const approveWords = ["safe", "approve", "allow", "yes", "legitimate", "justified"];
  const hasDeny = denyStems.some((s) => lower.includes(s));
  const hasApprove = approveWords.some((w) => new RegExp(`\\b${w}\\b`).test(lower));
  if (hasApprove && !hasDeny) {
    return { approved: true, reasoning: trimmed };
  }

  return { approved: false, reasoning: trimmed };
}

// ---------------------------------------------------------------------------
// Review command (creates OpenCode subsession)
// ---------------------------------------------------------------------------

/**
 * Ask an OpenCode LLM subsession to review a blocked command.
 *
 * Creates a new session, fetches recent conversation context from the parent
 * session, sends a prompt with a safety-review system prompt, and parses the
 * LLM's response. Throws on session/prompt errors (the caller should catch
 * and fall back to blocking the command).
 */
export async function reviewCommand(
  client: OpencodeSessionClient,
  command: string,
  decision: DcgDecision,
  config: DcgPluginConfig,
  directory: string,
  sessionID?: string,
  logger?: Logger,
): Promise<ReviewResult> {
  const review = config.review;

  // 0. Fetch conversation context from the parent session (non-fatal)
  const context = await fetchSessionContext(
    client,
    sessionID,
    review.contextMessageLimit,
    review.contextMaxChars,
  );
  if (config.debug && context) {
    logger?.(
      "debug",
      `[opencode-dcg-plugin] fetched ${context.length} chars of conversation context from session ${sessionID}`,
    );
  }

  // 1. Create a session
  const session = await client.session.create({
    body: { title: "DCG Safety Review" },
  });
  const sessionId = session.data?.id;
  if (!sessionId) {
    throw new Error("review: session.create returned no session id");
  }

  // 2. Send prompt with system instructions + conversation context
  const body: {
    agent?: string;
    model?: { providerID: string; modelID: string };
    system: string;
    parts: Array<{ type: "text"; text: string }>;
  } = {
    system: buildSystemPrompt(),
    parts: [{ type: "text", text: buildUserPrompt(command, decision, directory, context) }],
  };
  if (review.agent) body.agent = review.agent;
  if (review.model) body.model = review.model;

  const result = await client.session.prompt({
    path: { id: sessionId },
    body,
    signal: AbortSignal.timeout(review.timeoutMs),
  });

  // 3. Extract text from the first text part
  const text = result.data?.parts?.find((p) => p.type === "text")?.text ?? "";

  if (config.debug) {
    logger?.("debug", `[opencode-dcg-plugin] review response: ${text.slice(0, 200)}`);
  }

  return parseReviewResponse(text);
}

// ---------------------------------------------------------------------------
// Sentinel default export — see comment below.
// ---------------------------------------------------------------------------

/**
 * This file is imported by `./index.ts` (the real plugin entry) and is NOT
 * meant to be loaded as a standalone plugin. However, when the plugin is
 * installed via the file-based path (Option B in the README — copy `dist/*.js`
 * into `.opencode/plugins/`), OpenCode auto-discovers every `.js`/`.ts` file
 * in that directory as a separate plugin.
 *
 * OpenCode's plugin loader (v1.17.12) takes a v1 path when `mod.default` is
 * a plain object with `server`/`id`; otherwise it falls back to a legacy
 * path that iterates `Object.values(mod)` and calls every named function
 * export as a plugin. Without this default export, the legacy fallback would
 * invoke `buildUserPrompt` (and friends) with `(input, options, ...)` and
 * crash on the first line that touches `decision.rule_id` — producing a
 * noisy `level=ERROR` in the OpenCode log.
 *
 * Exporting a no-op `PluginModule` shape here satisfies the v1 path. The
 * legacy fallback is never reached, no hooks are registered from this file,
 * and the import in `index.ts` is unaffected. The error is non-fatal (the
 * loader swallows it via `Effect.catch`), but the log noise is misleading
 * and this fix removes it.
 */
export default {
  id: "opencode-dcg-plugin-review-internal",
  server: async () => ({}),
};
