import { describe, test, expect } from "bun:test";
import {
  buildSystemPrompt,
  buildUserPrompt,
  fetchSessionContext,
  parseReviewResponse,
} from "../src/review.ts";
import {
  loadConfig,
  createPlugin,
  type DcgPluginConfig,
  type DcgDecision,
  type ReviewResult,
} from "../src/index.ts";

// ---------------------------------------------------------------------------
// Review config via loadConfig
// ---------------------------------------------------------------------------

describe("loadConfig (review)", () => {
  test("review is disabled by default", () => {
    const c = loadConfig({});
    expect(c.review.enabled).toBe(false);
    expect(c.review.agent).toBe("general");
    expect(c.review.timeoutMs).toBe(60000);
    expect(c.review.contextMessageLimit).toBe(20);
    expect(c.review.contextMaxChars).toBe(4000);
    expect(c.review.model).toBeUndefined();
  });

  test("reads DCG_PLUGIN_REVIEW_ENABLED", () => {
    expect(loadConfig({ DCG_PLUGIN_REVIEW_ENABLED: "true" }).review.enabled).toBe(true);
    expect(loadConfig({ DCG_PLUGIN_REVIEW_ENABLED: "1" }).review.enabled).toBe(true);
    expect(loadConfig({}).review.enabled).toBe(false);
  });

  test("reads DCG_PLUGIN_REVIEW_MODEL", () => {
    expect(loadConfig({ DCG_PLUGIN_REVIEW_MODEL: "anthropic:claude-sonnet-4" }).review.model).toEqual({
      providerID: "anthropic",
      modelID: "claude-sonnet-4",
    });
    expect(loadConfig({ DCG_PLUGIN_REVIEW_MODEL: "openai:gpt-4o" }).review.model).toEqual({
      providerID: "openai",
      modelID: "gpt-4o",
    });
    expect(loadConfig({ DCG_PLUGIN_REVIEW_MODEL: "invalid" }).review.model).toBeUndefined();
    expect(loadConfig({ DCG_PLUGIN_REVIEW_MODEL: "" }).review.model).toBeUndefined();
  });

  test("reads DCG_PLUGIN_REVIEW_AGENT", () => {
    expect(loadConfig({ DCG_PLUGIN_REVIEW_AGENT: "general" }).review.agent).toBe("general");
    expect(loadConfig({}).review.agent).toBe("general");
  });

  test("reads DCG_PLUGIN_REVIEW_TIMEOUT_MS", () => {
    expect(loadConfig({ DCG_PLUGIN_REVIEW_TIMEOUT_MS: "30000" }).review.timeoutMs).toBe(30000);
    expect(loadConfig({}).review.timeoutMs).toBe(60000);
  });

  test("reads DCG_PLUGIN_REVIEW_CONTEXT_MESSAGES", () => {
    expect(loadConfig({ DCG_PLUGIN_REVIEW_CONTEXT_MESSAGES: "50" }).review.contextMessageLimit).toBe(50);
    expect(loadConfig({}).review.contextMessageLimit).toBe(20);
  });

  test("reads DCG_PLUGIN_REVIEW_CONTEXT_MAX_CHARS", () => {
    expect(loadConfig({ DCG_PLUGIN_REVIEW_CONTEXT_MAX_CHARS: "8000" }).review.contextMaxChars).toBe(8000);
    expect(loadConfig({}).review.contextMaxChars).toBe(4000);
  });
});

// ---------------------------------------------------------------------------
// buildSystemPrompt
// ---------------------------------------------------------------------------

describe("buildSystemPrompt", () => {
  test("instructs LLM to respond with JSON", () => {
    const prompt = buildSystemPrompt();
    expect(prompt).toContain("JSON");
    expect(prompt).toContain('"safe"');
    expect(prompt).toContain("command safety reviewer");
    expect(prompt).toContain("conservative");
  });

  test("tells LLM not to use tools", () => {
    const prompt = buildSystemPrompt();
    expect(prompt.toLowerCase()).toContain("do not use any tools");
  });
});

// ---------------------------------------------------------------------------
// buildUserPrompt
// ---------------------------------------------------------------------------

describe("buildUserPrompt", () => {
  const decision: DcgDecision = {
    decision: "deny",
    rule_id: "core.git:reset-hard",
    severity: "critical",
    reason: "destroys uncommitted changes",
    explanation: "git reset --hard discards ALL uncommitted changes.",
  };

  test("includes the command", () => {
    const prompt = buildUserPrompt("git reset --hard", decision, "/home/user/project");
    expect(prompt).toContain("git reset --hard");
  });

  test("includes rule and severity", () => {
    const prompt = buildUserPrompt("git reset --hard", decision, "/home/user/project");
    expect(prompt).toContain("core.git:reset-hard");
    expect(prompt).toContain("critical");
  });

  test("includes reason and explanation", () => {
    const prompt = buildUserPrompt("git reset --hard", decision, "/home/user/project");
    expect(prompt).toContain("destroys uncommitted changes");
    expect(prompt).toContain("discards ALL uncommitted changes");
  });

  test("includes working directory", () => {
    const prompt = buildUserPrompt("git reset --hard", decision, "/home/user/project");
    expect(prompt).toContain("/home/user/project");
  });

  test("works with minimal deny (no rule/reason)", () => {
    const prompt = buildUserPrompt("cmd", { decision: "deny" }, "/dir");
    expect(prompt).toContain("cmd");
    expect(prompt).toContain("unknown");
    expect(prompt).toContain("/dir");
  });

  test("includes conversation context when provided", () => {
    const prompt = buildUserPrompt(
      "git reset --hard",
      decision,
      "/home/user/project",
      "User: please clean up the build artifacts\nAssistant: I'll remove node_modules",
    );
    expect(prompt).toContain("Conversation context");
    expect(prompt).toContain("please clean up the build artifacts");
    expect(prompt).toContain("I'll remove node_modules");
    expect(prompt).toContain("---");
    // Command details still present after context
    expect(prompt).toContain("git reset --hard");
    expect(prompt).toContain("core.git:reset-hard");
  });

  test("omits context section when not provided", () => {
    const prompt = buildUserPrompt("git reset --hard", decision, "/dir");
    expect(prompt).not.toContain("Conversation context");
    expect(prompt).not.toContain("---");
  });

  test("omits context section when null", () => {
    const prompt = buildUserPrompt("git reset --hard", decision, "/dir", null);
    expect(prompt).not.toContain("Conversation context");
  });
});

// ---------------------------------------------------------------------------
// fetchSessionContext
// ---------------------------------------------------------------------------

import type { OpencodeSessionClient } from "../src/index.ts";

function makeMockClient(messages: Array<{
  info: { role: "user" | "assistant" };
  parts: Array<{ type: string; text?: string; tool?: string }>;
}>): OpencodeSessionClient {
  return {
    session: {
      create: async () => ({ data: { id: "review-session-1" } }),
      prompt: async () => ({ data: { parts: [{ type: "text", text: "" }] } }),
      messages: async () => ({ data: messages }),
    },
  };
}

function makeThrowingClient(): OpencodeSessionClient {
  return {
    session: {
      create: async () => ({ data: { id: "review-session-1" } }),
      prompt: async () => ({ data: { parts: [] } }),
      messages: async () => {
        throw new Error("network error");
      },
    },
  };
}

describe("fetchSessionContext", () => {
  test("returns null when sessionID is undefined", async () => {
    const client = makeMockClient([]);
    expect(await fetchSessionContext(client, undefined, 20, 4000)).toBeNull();
  });

  test("returns null when messages fetch throws", async () => {
    const client = makeThrowingClient();
    expect(await fetchSessionContext(client, "ses_123", 20, 4000)).toBeNull();
  });

  test("returns null when no messages", async () => {
    const client = makeMockClient([]);
    expect(await fetchSessionContext(client, "ses_123", 20, 4000)).toBeNull();
  });

  test("returns null when messages have no text or tool parts", async () => {
    const client = makeMockClient([
      { info: { role: "user" }, parts: [{ type: "step-start" }] },
    ]);
    expect(await fetchSessionContext(client, "ses_123", 20, 4000)).toBeNull();
  });

  test("formats user and assistant text messages", async () => {
    const client = makeMockClient([
      { info: { role: "user" }, parts: [{ type: "text", text: "clean up build" }] },
      { info: { role: "assistant" }, parts: [{ type: "text", text: "Running rm -rf dist/" }] },
    ]);
    const ctx = await fetchSessionContext(client, "ses_123", 20, 4000);
    expect(ctx).toContain("User: clean up build");
    expect(ctx).toContain("Assistant: Running rm -rf dist/");
  });

  test("includes tool call names as [tool: name]", async () => {
    const client = makeMockClient([
      { info: { role: "assistant" }, parts: [{ type: "tool", tool: "bash" }] },
    ]);
    const ctx = await fetchSessionContext(client, "ses_123", 20, 4000);
    expect(ctx).toContain("[tool: bash]");
  });

  test("truncates to character limit", async () => {
    const longText = "x".repeat(3000);
    const client = makeMockClient([
      { info: { role: "user" }, parts: [{ type: "text", text: longText }] },
      { info: { role: "assistant" }, parts: [{ type: "text", text: longText }] },
    ]);
    const ctx = await fetchSessionContext(client, "ses_123", 20, 4000);
    // Should be under the 4000 char limit
    expect(ctx!.length).toBeLessThan(4500);
    // Should include at least the first message
    expect(ctx).toContain("User:");
  });

  test("respects custom maxChars", async () => {
    const client = makeMockClient([
      { info: { role: "user" }, parts: [{ type: "text", text: "short message one" }] },
      { info: { role: "assistant" }, parts: [{ type: "text", text: "short message two" }] },
    ]);
    // With a very small limit, only the first message should fit
    const ctx = await fetchSessionContext(client, "ses_123", 20, 25);
    expect(ctx).toContain("User: short message one");
    expect(ctx).not.toContain("Assistant: short message two");
  });

  test("skips messages with no text/tool parts", async () => {
    const client = makeMockClient([
      { info: { role: "user" }, parts: [{ type: "step-start" }] },
      { info: { role: "assistant" }, parts: [{ type: "text", text: "hello" }] },
    ]);
    const ctx = await fetchSessionContext(client, "ses_123", 20, 4000);
    expect(ctx).not.toContain("User:");
    expect(ctx).toContain("Assistant: hello");
  });
});

// ---------------------------------------------------------------------------
// parseReviewResponse
// ---------------------------------------------------------------------------

describe("parseReviewResponse", () => {
  test("parses valid JSON with safe=true", () => {
    const result = parseReviewResponse('{"safe": true, "reasoning": "legit cleanup"}');
    expect(result.approved).toBe(true);
    expect(result.reasoning).toBe("legit cleanup");
  });

  test("parses valid JSON with safe=false", () => {
    const result = parseReviewResponse('{"safe": false, "reasoning": "too dangerous"}');
    expect(result.approved).toBe(false);
    expect(result.reasoning).toBe("too dangerous");
  });

  test("parses JSON wrapped in markdown code fences", () => {
    const result = parseReviewResponse('```json\n{"safe": true, "reasoning": "ok"}\n```');
    expect(result.approved).toBe(true);
    expect(result.reasoning).toBe("ok");
  });

  test("extracts JSON from surrounding prose", () => {
    const result = parseReviewResponse(
      'Here is my review:\n{"safe": false, "reasoning": "no"}\nThat is all.',
    );
    expect(result.approved).toBe(false);
  });

  test("parses JSON without reasoning field", () => {
    const result = parseReviewResponse('{"safe": true}');
    expect(result.approved).toBe(true);
    expect(result.reasoning).toBeUndefined();
  });

  test("returns not approved on empty response", () => {
    const result = parseReviewResponse("");
    expect(result.approved).toBe(false);
    expect(result.reasoning).toBe("empty response");
  });

  test("falls back to keyword detection for approve", () => {
    const result = parseReviewResponse("This command is safe to run.");
    expect(result.approved).toBe(true);
  });

  test("falls back to keyword detection for deny", () => {
    const result = parseReviewResponse("This is dangerous, do not allow.");
    expect(result.approved).toBe(false);
  });

  test("defaults to not approved on unparseable text", () => {
    const result = parseReviewResponse("I cannot determine the answer.");
    expect(result.approved).toBe(false);
  });

  test("does not approve when both approve and deny keywords present", () => {
    const result = parseReviewResponse("This is safe but also dangerous");
    expect(result.approved).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// createPlugin with review
// ---------------------------------------------------------------------------

const baseConfig: DcgPluginConfig = {
  enabled: true,
  failMode: "open",
  timeoutMs: 5000,
  tools: ["bash"],
  binary: "dcg",
  debug: false,
  review: {
    enabled: true,
    agent: "general",
    timeoutMs: 60000,
    contextMessageLimit: 20,
    contextMaxChars: 4000,
  },
};

function makeMockCheck(decision: DcgDecision) {
  return async () => decision;
}

function makeMockReview(result: ReviewResult) {
  return async () => result;
}

function makeMockReviewThrow(err: Error) {
  return async () => {
    throw err;
  };
}

describe("createPlugin with review", () => {
  const denyDecision: DcgDecision = {
    decision: "deny",
    rule_id: "core.git:reset-hard",
    severity: "critical",
    reason: "destroys uncommitted changes",
  };

  test("allows command when review approves", async () => {
    const hooks = await createPlugin(
      baseConfig,
      makeMockCheck(denyDecision),
      makeMockReview({ approved: true, reasoning: "safe in this context" }),
    );
    const handler = hooks["tool.execute.before"]!;
    await expect(
      handler({ tool: "bash" }, { args: { command: "git reset --hard" } }),
    ).resolves.toBeUndefined();
  });

  test("blocks command when review rejects", async () => {
    const hooks = await createPlugin(
      baseConfig,
      makeMockCheck(denyDecision),
      makeMockReview({ approved: false, reasoning: "too dangerous" }),
    );
    const handler = hooks["tool.execute.before"]!;
    await expect(
      handler({ tool: "bash" }, { args: { command: "git reset --hard" } }),
    ).rejects.toThrow(/DCG blocked a destructive command/);
  });

  test("blocks command when review throws", async () => {
    const hooks = await createPlugin(
      baseConfig,
      makeMockCheck(denyDecision),
      makeMockReviewThrow(new Error("session creation failed")),
    );
    const handler = hooks["tool.execute.before"]!;
    await expect(
      handler({ tool: "bash" }, { args: { command: "git reset --hard" } }),
    ).rejects.toThrow(/DCG blocked a destructive command/);
  });

  test("still blocks when no review function provided", async () => {
    const hooks = await createPlugin(baseConfig, makeMockCheck(denyDecision));
    const handler = hooks["tool.execute.before"]!;
    await expect(
      handler({ tool: "bash" }, { args: { command: "git reset --hard" } }),
    ).rejects.toThrow(/DCG blocked a destructive command/);
  });
});
