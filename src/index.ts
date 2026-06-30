/**
 * opencode-dcg-plugin
 *
 * OpenCode plugin that intercepts shell commands executed by the `bash` tool
 * and blocks destructive ones using the destructive_command_guard (dcg) binary.
 *
 * DCG is a Rust-based command guard: https://github.com/Dicklesworthstone/destructive_command_guard
 *
 * The plugin shells out to `dcg --robot test "<command>"`, which returns JSON on
 * stdout with a `decision` field of "allow" or "deny", and exits 0 / 1
 * respectively. When a command is denied, the `tool.execute.before` hook throws
 * an Error to abort the tool call.
 *
 * Optionally, when the review agent is enabled (DCG_PLUGIN_REVIEW_ENABLED=true),
 * a blocked command is sent to an OpenCode LLM subsession for a second opinion.
 * If the LLM deems the command safe, the command is allowed for that single
 * invocation only — the next run is re-checked by dcg from scratch. This uses
 * OpenCode's own model infrastructure — no external API key required.
 *
 * Rule/pack configuration (which commands are considered destructive) is managed
 * entirely by dcg itself via `~/.config/dcg/config.toml` or `.dcg.toml`. This
 * plugin only controls its own integration behavior (timeout, fail mode, tool
 * scope, review agent) via `DCG_PLUGIN_*` environment variables.
 */
import { spawn } from "node:child_process";
import { reviewCommand } from "./review.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Result of a dcg check for a single command. */
export interface DcgDecision {
  decision: "allow" | "deny";
  command?: string;
  rule_id?: string;
  pack_id?: string;
  pattern_name?: string;
  reason?: string;
  explanation?: string;
  severity?: "critical" | "high" | "medium" | "low";
}

/** Plugin behavior configuration. */
export interface DcgPluginConfig {
  /** Master kill-switch. When false, the plugin is a no-op. */
  enabled: boolean;
  /** "open" = allow on dcg error/timeout (default); "closed" = deny. */
  failMode: "open" | "closed";
  /** Timeout in ms for a single dcg invocation. */
  timeoutMs: number;
  /** Tool names whose `args.command` should be checked (default: ["bash"]). */
  tools: string[];
  /** Name or path of the dcg binary. */
  binary: string;
  /** When true, log dcg stderr and decision details to console.warn. */
  debug: boolean;
  /** LLM review agent configuration (second-opinion override). */
  review: ReviewConfig;
}

/** Configuration for the LLM review agent. */
export interface ReviewConfig {
  /** When true, blocked commands are sent to an LLM for review before throwing. */
  enabled: boolean;
  /** Model to use (format: { providerID, modelID }). If unset, uses the agent's default. */
  model?: { providerID: string; modelID: string };
  /** OpenCode agent to use for the review subsession (default: "general"). */
  agent: string;
  /** Timeout in ms for the LLM review (default: 60000). */
  timeoutMs: number;
  /** Max number of parent session messages to include as context (default: 20). */
  contextMessageLimit: number;
  /** Max characters of conversation context to include in the prompt (default: 4000). */
  contextMaxChars: number;
}

/** Result of an LLM review of a blocked command. */
export interface ReviewResult {
  approved: boolean;
  reasoning?: string;
}

/** A function that checks a command and returns a dcg decision. */
export type CheckFn = (command: string, config: DcgPluginConfig) => Promise<DcgDecision>;

/** Minimal OpenCode client interface for session creation and prompting. */
export interface OpencodeSessionClient {
  session: {
    create(options?: {
      body?: { title?: string };
    }): Promise<{ data?: { id?: string } }>;
    prompt(options: {
      path: { id: string };
      body: {
        agent?: string;
        model?: { providerID: string; modelID: string };
        system?: string;
        parts: Array<{ type: "text"; text: string }>;
      };
      signal?: AbortSignal;
    }): Promise<{
      data?: { parts?: Array<{ type: string; text?: string }> };
    }>;
    messages(options: {
      path: { id: string };
      query?: { limit?: number };
    }): Promise<{
      data?: Array<{
        info: { role: "user" | "assistant" };
        parts: Array<{ type: string; text?: string; tool?: string }>;
      }>;
    }>;
  };
}

/** A function that reviews a blocked command and returns approval + reasoning. */
export type ReviewFn = (
  command: string,
  decision: DcgDecision,
  config: DcgPluginConfig,
  sessionID?: string,
) => Promise<ReviewResult>;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type EnvMap = Record<string, string | undefined>;

function envBool(env: EnvMap, name: string, fallback: boolean): boolean {
  const v = env[name];
  if (v === undefined || v === "") return fallback;
  return /^(1|true|yes|on)$/i.test(v);
}

function envInt(env: EnvMap, name: string, fallback: number): number {
  const v = env[name];
  if (v === undefined || v === "") return fallback;
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function envList(env: EnvMap, name: string, fallback: string[]): string[] {
  const v = env[name];
  if (!v) return fallback;
  return v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function envStr(env: EnvMap, name: string, fallback: string): string {
  const v = env[name];
  return v !== undefined && v !== "" ? v : fallback;
}

/** Parse a "providerID:modelID" string into a model reference. */
function parseModel(s: string): { providerID: string; modelID: string } | undefined {
  const idx = s.indexOf(":");
  if (idx < 0) return undefined;
  const providerID = s.slice(0, idx).trim();
  const modelID = s.slice(idx + 1).trim();
  if (!providerID || !modelID) return undefined;
  return { providerID, modelID };
}

/**
 * Load plugin config from environment variables.
 *
 * Recognized variables (all optional, prefix `DCG_PLUGIN_`):
 *   DCG_PLUGIN_ENABLED   — "false"/"0" disables the plugin entirely.
 *   DCG_PLUGIN_FAIL_MODE — "open" (default) or "closed".
 *   DCG_PLUGIN_TIMEOUT_MS — positive integer (default 5000).
 *   DCG_PLUGIN_TOOLS     — comma-separated tool names (default "bash").
 *   DCG_PLUGIN_BINARY    — path/name of the dcg binary (default "dcg").
 *   DCG_PLUGIN_DEBUG     — "true"/"1" to log dcg stderr and decisions.
 *   DCG_PLUGIN_REVIEW_ENABLED — "true"/"1" to enable LLM review of blocked commands.
 *   DCG_PLUGIN_REVIEW_MODEL  — "providerID:modelID" (e.g., "anthropic:claude-sonnet-4").
 *   DCG_PLUGIN_REVIEW_AGENT  — OpenCode agent for review subsession (default "general").
 *   DCG_PLUGIN_REVIEW_TIMEOUT_MS — timeout for LLM review (default 60000).
 *   DCG_PLUGIN_REVIEW_CONTEXT_MESSAGES — max parent session messages (default 20).
 *   DCG_PLUGIN_REVIEW_CONTEXT_MAX_CHARS — max context chars in prompt (default 4000).
 *
 * Note: dcg's own bypass (`DCG_BYPASS=1`) is handled by dcg itself — when set,
 * dcg returns "allow" and the plugin naturally lets the command through.
 */
export function loadConfig(env: EnvMap = process.env): DcgPluginConfig {
  return {
    enabled: envBool(env, "DCG_PLUGIN_ENABLED", true),
    failMode: envStr(env, "DCG_PLUGIN_FAIL_MODE", "open") === "closed" ? "closed" : "open",
    timeoutMs: envInt(env, "DCG_PLUGIN_TIMEOUT_MS", 5000),
    tools: envList(env, "DCG_PLUGIN_TOOLS", ["bash"]),
    binary: envStr(env, "DCG_PLUGIN_BINARY", "dcg"),
    debug: envBool(env, "DCG_PLUGIN_DEBUG", false),
    review: {
      enabled: envBool(env, "DCG_PLUGIN_REVIEW_ENABLED", false),
      model: parseModel(envStr(env, "DCG_PLUGIN_REVIEW_MODEL", "")),
      agent: envStr(env, "DCG_PLUGIN_REVIEW_AGENT", "general"),
      timeoutMs: envInt(env, "DCG_PLUGIN_REVIEW_TIMEOUT_MS", 60000),
      contextMessageLimit: envInt(env, "DCG_PLUGIN_REVIEW_CONTEXT_MESSAGES", 20),
      contextMaxChars: envInt(env, "DCG_PLUGIN_REVIEW_CONTEXT_MAX_CHARS", 4000),
    },
  };
}

// ---------------------------------------------------------------------------
// dcg invocation
// ---------------------------------------------------------------------------

let missingBinaryWarned = false;

/** Build a decision for error/timeout cases, honoring fail-mode. */
function errorDecision(kind: string, config: DcgPluginConfig, detail?: string): DcgDecision {
  if (!config) {
    return {
      decision: "allow",
      reason: `dcg error (no config): ${kind}${detail ? `: ${detail}` : ""}`,
    };
  }
  const reason =
    kind === "spawn"
      ? `dcg binary not available${detail ? `: ${detail}` : ""}`
      : kind === "timeout"
        ? `dcg check timed out after ${config.timeoutMs}ms`
        : `dcg returned unparseable output${detail ? `: ${detail}` : ""}`;
  return {
    decision: config.failMode === "closed" ? "deny" : "allow",
    reason,
  };
}

function tryParseJson(text: string): Record<string, unknown> | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  try {
    const parsed = JSON.parse(trimmed);
    return typeof parsed === "object" && parsed !== null ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * Run `dcg --robot test <command>` and return the parsed decision.
 *
 * - Exit 0 + JSON  → decision from JSON (typically "allow")
 * - Exit 1 + JSON  → decision from JSON (typically "deny", with rule/severity)
 * - Spawn error    → fail-open/closed decision (ENOENT etc.)
 * - Timeout        → fail-open/closed decision
 * - Non-JSON stdout → fail-open/closed decision
 */
export function runDcg(command: string, config: DcgPluginConfig): Promise<DcgDecision> {
  return new Promise((resolve) => {
    let proc: ReturnType<typeof spawn>;
    try {
      proc = spawn(config.binary, ["--robot", "test", command], {
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env },
      });
    } catch (err) {
      resolve(errorDecision("spawn", config, errMsg(err)));
      return;
    }

    let stdout = "";
    let stderr = "";
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try {
        proc.kill("SIGKILL");
      } catch {
        /* ignore */
      }
      resolve(errorDecision("timeout", config));
    }, config.timeoutMs);

    proc.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    proc.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    proc.on("error", (err: NodeJS.ErrnoException) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err.code === "ENOENT" && !missingBinaryWarned) {
        missingBinaryWarned = true;
        console.warn(
          `[opencode-dcg-plugin] dcg binary "${config.binary}" not found. ` +
            `Commands will ${config.failMode === "closed" ? "be blocked" : "pass through unchecked"}. ` +
            `Install dcg or set DCG_PLUGIN_BINARY. ` +
            `See https://github.com/Dicklesworthstone/destructive_command_guard`,
        );
      }
      resolve(errorDecision("spawn", config, err.message));
    });

    proc.on("close", (code: number | null, signal: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);

      const parsed = tryParseJson(stdout);
      if (parsed && typeof parsed.decision === "string") {
        if (config.debug) {
          const d = parsed as unknown as DcgDecision;
          console.warn(
            `[opencode-dcg-plugin] ${d.decision} — ${command}` +
              (d.rule_id ? ` (${d.rule_id})` : "") +
              (stderr ? `\n  stderr: ${stderr.trim()}` : ""),
          );
        }
        resolve(parsed as unknown as DcgDecision);
        return;
      }

      // Non-JSON output — honor fail-mode for all cases (including exit 0).
      if (signal) {
        resolve(errorDecision("spawn", config, `dcg killed by signal ${signal}`));
      } else {
        resolve(errorDecision("parse", config, stderr || stdout || `exit code ${code}`));
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Block-message formatting
// ---------------------------------------------------------------------------

/**
 * Format the error message shown when dcg denies a command.
 * Includes the rule, severity, reason, explanation, and a follow-up tip.
 */
export function formatBlockMessage(command: string, d: DcgDecision): string {
  if (!d) {
    return `DCG blocked a destructive command.\n\n  Command:  ${command}\n\n  Rule:     unknown\n\n  Reason:   dcg returned an invalid or empty decision.`;
  }
  const parts: string[] = ["DCG blocked a destructive command.", ""];

  parts.push(`  Command:  ${command}`);

  const ruleLabel = d.rule_id ?? "unknown";
  const severityTag = d.severity ? ` [${d.severity}]` : "";
  parts.push(`  Rule:     ${ruleLabel}${severityTag}`);

  if (d.pack_id || d.pattern_name) {
    const meta = [d.pack_id, d.pattern_name].filter(Boolean).join(" / ");
    parts.push(`  Pack:     ${meta}`);
  }

  if (d.reason) {
    parts.push("");
    parts.push(d.reason);
  }

  if (d.explanation) {
    parts.push("");
    parts.push(d.explanation);
  }

  parts.push("");
  parts.push("Run `dcg explain` with the command for full details.");
  return parts.join("\n");
}

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

/**
 * Build the hook handlers for the given config + check function.
 * If a review function is provided, blocked commands are sent for LLM review
 * before throwing — if the reviewer approves, the command is allowed.
 * Exported for testing; use `DcgGuard` for the real plugin.
 */
export async function createPlugin(config: DcgPluginConfig, check: CheckFn, review?: ReviewFn) {
  if (!config.enabled) return {};

  return {
    "tool.execute.before": async (
      input: { tool: string; sessionID?: string; callID?: string },
      output: { args?: Record<string, unknown> },
    ) => {
      if (!config.tools.includes(input.tool)) return;

      const command = output?.args?.command;
      if (typeof command !== "string" || command.trim() === "") return;

      const decision = await check(command, config);
      if (decision && decision.decision === "deny") {
        if (review) {
          try {
            const result = await review(command, decision, config, input.sessionID);
            if (result.approved) {
              if (config.debug) {
                console.warn(
                  `[opencode-dcg-plugin] command approved by review agent: ${command}` +
                    (result.reasoning ? ` (${result.reasoning})` : ""),
                );
              }
              return; // Allow this single invocation; next run is re-checked
            }
          } catch (err) {
            if (config.debug) {
              console.warn(`[opencode-dcg-plugin] review failed, blocking: ${errMsg(err)}`);
            }
            // Fall through to throw — safe default is to block
          }
        }
        throw new Error(formatBlockMessage(command, decision));
      }
    },
  };
}

/**
 * OpenCode plugin entry point.
 *
 * Register in `opencode.json`:
 *   { "plugin": ["opencode-dcg-plugin"] }
 *
 * Or place the built file in `.opencode/plugins/`.
 *
 * When DCG_PLUGIN_REVIEW_ENABLED is true, blocked commands are sent to an
 * OpenCode LLM subsession for a second opinion. If approved, the command is
 * allowed for that single invocation only — the next run is re-checked by
 * dcg and re-reviewed if blocked again.
 */
export const DcgGuard = async (context: {
  project: unknown;
  client: unknown;
  $: unknown;
  directory: string;
  worktree: string;
}) => {
  const config = loadConfig();

  const review: ReviewFn | undefined = config.review.enabled
    ? (command, decision, cfg, sessionID) =>
        reviewCommand(
          context.client as OpencodeSessionClient,
          command,
          decision,
          cfg,
          context.directory,
          sessionID,
        )
    : undefined;

  return createPlugin(config, runDcg, review);
};

/**
 * OpenCode's plugin loader (v1.17+) expects a `default` export. Most
 * OpenCode plugins (e.g. oh-my-opencode-slim) export the plugin function
 * itself as `default`; re-export `DcgGuard` here so the plugin is
 * importable as both a named and default export.
 */
export default DcgGuard;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function errMsg(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
