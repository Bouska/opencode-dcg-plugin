import { describe, test, expect } from "bun:test";
import { writeFileSync, chmodSync, unlinkSync, rmSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  loadConfig,
  createPlugin,
  formatBlockMessage,
  runDcg,
  probeBinary,
  type DcgPluginConfig,
  type DcgDecision,
  type CheckFn,
} from "../src/index.ts";

// ---------------------------------------------------------------------------
// loadConfig
// ---------------------------------------------------------------------------

describe("loadConfig", () => {
  test("returns sensible defaults", () => {
    const c = loadConfig({});
    expect(c.enabled).toBe(true);
    expect(c.failMode).toBe("open");
    expect(c.timeoutMs).toBe(5000);
    expect(c.tools).toEqual(["bash"]);
    expect(c.binary).toBe("dcg");
    expect(c.debug).toBe(false);
  });

  test("reads DCG_PLUGIN_ENABLED", () => {
    expect(loadConfig({ DCG_PLUGIN_ENABLED: "false" }).enabled).toBe(false);
    expect(loadConfig({ DCG_PLUGIN_ENABLED: "0" }).enabled).toBe(false);
    expect(loadConfig({ DCG_PLUGIN_ENABLED: "no" }).enabled).toBe(false);
    expect(loadConfig({ DCG_PLUGIN_ENABLED: "true" }).enabled).toBe(true);
    expect(loadConfig({ DCG_PLUGIN_ENABLED: "1" }).enabled).toBe(true);
    expect(loadConfig({ DCG_PLUGIN_ENABLED: "yes" }).enabled).toBe(true);
    expect(loadConfig({ DCG_PLUGIN_ENABLED: "y" }).enabled).toBe(true);
    expect(loadConfig({ DCG_PLUGIN_ENABLED: "off" }).enabled).toBe(false);
    expect(loadConfig({ DCG_PLUGIN_ENABLED: "n" }).enabled).toBe(false);
    expect(loadConfig({ DCG_PLUGIN_ENABLED: " 1 " }).enabled).toBe(true);
    expect(loadConfig({ DCG_PLUGIN_ENABLED: " " }).enabled).toBe(true);
    expect(loadConfig({ DCG_PLUGIN_ENABLED: "" }).enabled).toBe(true);
  });

  test("reads DCG_PLUGIN_FAIL_MODE", () => {
    expect(loadConfig({ DCG_PLUGIN_FAIL_MODE: "closed" }).failMode).toBe("closed");
    expect(loadConfig({ DCG_PLUGIN_FAIL_MODE: "open" }).failMode).toBe("open");
    expect(loadConfig({ DCG_PLUGIN_FAIL_MODE: "nonsense" }).failMode).toBe("open");
  });

  test("reads DCG_PLUGIN_TIMEOUT_MS", () => {
    expect(loadConfig({ DCG_PLUGIN_TIMEOUT_MS: "1500" }).timeoutMs).toBe(1500);
    expect(loadConfig({ DCG_PLUGIN_TIMEOUT_MS: "0" }).timeoutMs).toBe(5000);
    expect(loadConfig({ DCG_PLUGIN_TIMEOUT_MS: "-5" }).timeoutMs).toBe(5000);
    expect(loadConfig({ DCG_PLUGIN_TIMEOUT_MS: "abc" }).timeoutMs).toBe(5000);
  });

  test("reads DCG_PLUGIN_TOOLS", () => {
    expect(loadConfig({ DCG_PLUGIN_TOOLS: "bash,task" }).tools).toEqual(["bash", "task"]);
    expect(loadConfig({ DCG_PLUGIN_TOOLS: " bash , task " }).tools).toEqual(["bash", "task"]);
    expect(loadConfig({ DCG_PLUGIN_TOOLS: "" }).tools).toEqual(["bash"]);
  });

  test("reads DCG_PLUGIN_BINARY", () => {
    expect(loadConfig({ DCG_PLUGIN_BINARY: "/usr/local/bin/dcg" }).binary).toBe(
      "/usr/local/bin/dcg",
    );
    expect(loadConfig({ DCG_PLUGIN_BINARY: "" }).binary).toBe("dcg");
  });

  test("reads DCG_PLUGIN_DEBUG", () => {
    expect(loadConfig({ DCG_PLUGIN_DEBUG: "true" }).debug).toBe(true);
    expect(loadConfig({ DCG_PLUGIN_DEBUG: "1" }).debug).toBe(true);
    expect(loadConfig({ DCG_PLUGIN_DEBUG: "false" }).debug).toBe(false);
    expect(loadConfig({}).debug).toBe(false);
  });

  test("reads DCG_PLUGIN_STRICT_MISSING", () => {
    expect(loadConfig({}).strictMissing).toBe(false);
    expect(loadConfig({ DCG_PLUGIN_STRICT_MISSING: "true" }).strictMissing).toBe(true);
    expect(loadConfig({ DCG_PLUGIN_STRICT_MISSING: "1" }).strictMissing).toBe(true);
    expect(loadConfig({ DCG_PLUGIN_STRICT_MISSING: "false" }).strictMissing).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// formatBlockMessage
// ---------------------------------------------------------------------------

describe("formatBlockMessage", () => {
  test("includes command, rule, and severity", () => {
    const msg = formatBlockMessage("git reset --hard", {
      decision: "deny",
      rule_id: "core.git:reset-hard",
      severity: "critical",
      reason: "destroys uncommitted changes",
    });
    expect(msg).toContain("git reset --hard");
    expect(msg).toContain("core.git:reset-hard");
    expect(msg).toContain("[critical]");
    expect(msg).toContain("destroys uncommitted changes");
    expect(msg).toContain("dcg explain");
  });

  test("includes pack and pattern when present", () => {
    const msg = formatBlockMessage("rm -rf /", {
      decision: "deny",
      rule_id: "core.filesystem:rm-rf-root",
      pack_id: "core.filesystem",
      pattern_name: "rm-rf-root-home",
      severity: "critical",
      reason: "dangerous",
    });
    expect(msg).toContain("core.filesystem");
    expect(msg).toContain("rm-rf-root-home");
  });

  test("includes explanation when present", () => {
    const msg = formatBlockMessage("dd if=/dev/zero of=/dev/sda", {
      decision: "deny",
      rule_id: "system.disk:dd-to-device",
      severity: "critical",
      reason: "overwrites a disk device",
      explanation: "This will destroy all data on the target device.",
    });
    expect(msg).toContain("This will destroy all data");
  });

  test("works with minimal deny (no rule/reason)", () => {
    const msg = formatBlockMessage("some-command", { decision: "deny" });
    expect(msg).toContain("some-command");
    expect(msg).toContain("unknown");
    expect(msg).toContain("dcg explain");
  });
});

// ---------------------------------------------------------------------------
// createPlugin (with mock check function)
// ---------------------------------------------------------------------------

const baseConfig: DcgPluginConfig = {
  enabled: true,
  failMode: "open",
  timeoutMs: 5000,
  tools: ["bash"],
  binary: "dcg",
  debug: false,
  strictMissing: false,
  review: {
    enabled: false,
    model: undefined,
    agent: "general",
    timeoutMs: 60000,
    contextMessageLimit: 20,
    contextMaxChars: 4000,
  },
};

function makeMockCheck(decision: DcgDecision): CheckFn {
  return async () => decision;
}

describe("createPlugin", () => {
  test("returns empty hooks when disabled", async () => {
    const hooks = await createPlugin({ ...baseConfig, enabled: false }, makeMockCheck({ decision: "allow" }));
    expect(hooks).toEqual({});
  });

  test("passes through non-configured tools without calling check", async () => {
    let called = false;
    const check: CheckFn = async () => {
      called = true;
      return { decision: "allow" };
    };
    const hooks = await createPlugin(baseConfig, check);
    const handler = hooks["tool.execute.before"];
    expect(handler).toBeDefined();
    await handler!({ tool: "read" }, { args: { filePath: "x.ts" } });
    expect(called).toBe(false);
  });

  test("passes through bash with empty/missing command", async () => {
    let called = false;
    const check: CheckFn = async () => {
      called = true;
      return { decision: "allow" };
    };
    const hooks = await createPlugin(baseConfig, check);
    const handler = hooks["tool.execute.before"]!;

    await handler({ tool: "bash" }, { args: { command: "" } });
    await handler({ tool: "bash" }, { args: { command: "   " } });
    await handler({ tool: "bash" }, { args: {} });
    await handler({ tool: "bash" }, {});
    expect(called).toBe(false);
  });

  test("allows when check returns allow", async () => {
    const hooks = await createPlugin(baseConfig, makeMockCheck({ decision: "allow" }));
    const handler = hooks["tool.execute.before"]!;
    await expect(handler({ tool: "bash" }, { args: { command: "ls -la" } })).resolves.toBeUndefined();
  });

  test("throws when check returns deny", async () => {
    const hooks = await createPlugin(baseConfig, makeMockCheck({
      decision: "deny",
      rule_id: "core.git:reset-hard",
      severity: "critical",
      reason: "destroys uncommitted changes",
    }));
    const handler = hooks["tool.execute.before"]!;
    await expect(
      handler({ tool: "bash" }, { args: { command: "git reset --hard" } }),
    ).rejects.toThrow(/DCG blocked a destructive command/);
  });

  test("includes rule info in thrown error", async () => {
    const hooks = await createPlugin(baseConfig, makeMockCheck({
      decision: "deny",
      rule_id: "core.filesystem:rm-rf-root",
      severity: "critical",
      reason: "rm -rf on root is dangerous",
    }));
    const handler = hooks["tool.execute.before"]!;
    try {
      await handler({ tool: "bash" }, { args: { command: "rm -rf /" } });
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(Error);
      const msg = (err as Error).message;
      expect(msg).toContain("rm -rf /");
      expect(msg).toContain("core.filesystem:rm-rf-root");
      expect(msg).toContain("rm -rf on root is dangerous");
    }
  });

  test("respects custom tools list", async () => {
    let called = false;
    const check: CheckFn = async () => {
      called = true;
      return { decision: "allow" };
    };
    const hooks = await createPlugin({ ...baseConfig, tools: ["bash", "task"] }, check);
    const handler = hooks["tool.execute.before"]!;
    await handler({ tool: "task" }, { args: { command: "echo hi" } });
    expect(called).toBe(true);
  });

  test("throws a clear one-shot error when dcg binary is missing", async () => {
    const ctx = {
      binaryProbe: { probed: true, missing: true, binary: "fake-dcg" },
      logger: () => {},
    };
    let calls = 0;
    const check: CheckFn = async () => {
      calls++;
      return { decision: "allow" };
    };
    const hooks = await createPlugin(baseConfig, check, undefined, ctx);
    const handler = hooks["tool.execute.before"]!;

    // First call throws the missing-binary error and does NOT call check.
    await expect(
      handler({ tool: "bash" }, { args: { command: "ls" } }),
    ).rejects.toThrow(/dcg binary "fake-dcg" not available/);
    expect(calls).toBe(0);

    // Subsequent calls fall through (no re-throw, check runs normally).
    await expect(
      handler({ tool: "bash" }, { args: { command: "ls" } }),
    ).resolves.toBeUndefined();
    expect(calls).toBe(1);
  });

  test("does not throw when binary probe has not completed yet", async () => {
    const ctx = {
      binaryProbe: { probed: false, missing: false, binary: "dcg" },
      logger: () => {},
    };
    const hooks = await createPlugin(baseConfig, makeMockCheck({ decision: "allow" }), undefined, ctx);
    const handler = hooks["tool.execute.before"]!;
    await expect(
      handler({ tool: "bash" }, { args: { command: "ls" } }),
    ).resolves.toBeUndefined();
  });

  test("does not throw when probe says binary is present", async () => {
    const ctx = {
      binaryProbe: { probed: true, missing: false, binary: "dcg" },
      logger: () => {},
    };
    const hooks = await createPlugin(baseConfig, makeMockCheck({ decision: "allow" }), undefined, ctx);
    const handler = hooks["tool.execute.before"]!;
    await expect(
      handler({ tool: "bash" }, { args: { command: "ls" } }),
    ).resolves.toBeUndefined();
  });

  test("with strictMissing=true, throws on EVERY command when binary is missing", async () => {
    const ctx = {
      binaryProbe: { probed: true, missing: true, binary: "fake-dcg" },
      logger: () => {},
    };
    const strictConfig = { ...baseConfig, strictMissing: true };
    let calls = 0;
    const check: CheckFn = async () => {
      calls++;
      return { decision: "allow" };
    };
    const hooks = await createPlugin(strictConfig, check, undefined, ctx);
    const handler = hooks["tool.execute.before"]!;

    // First call throws.
    await expect(
      handler({ tool: "bash" }, { args: { command: "ls" } }),
    ).rejects.toThrow(/dcg binary "fake-dcg" not available/);
    // Second call ALSO throws (unlike default behavior).
    await expect(
      handler({ tool: "bash" }, { args: { command: "ls -la" } }),
    ).rejects.toThrow(/dcg binary "fake-dcg" not available/);
    // Third call still throws.
    await expect(
      handler({ tool: "bash" }, { args: { command: "echo hi" } }),
    ).rejects.toThrow(/dcg binary "fake-dcg" not available/);
    // The check function is NEVER called while the binary is missing.
    expect(calls).toBe(0);
  });

  test("with strictMissing=true, does not throw when binary is present", async () => {
    const ctx = {
      binaryProbe: { probed: true, missing: false, binary: "dcg" },
      logger: () => {},
    };
    const strictConfig = { ...baseConfig, strictMissing: true };
    const hooks = await createPlugin(strictConfig, makeMockCheck({ decision: "allow" }), undefined, ctx);
    const handler = hooks["tool.execute.before"]!;
    await expect(
      handler({ tool: "bash" }, { args: { command: "ls" } }),
    ).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// runDcg (integration — requires dcg binary)
// ---------------------------------------------------------------------------

const dcgPath = typeof Bun !== "undefined" ? Bun.which("dcg") : null;
const dcgAvailable = dcgPath != null;

describe.skipIf(!dcgAvailable)("runDcg integration", () => {
  const config: DcgPluginConfig = {
    ...baseConfig,
    timeoutMs: 10000,
    binary: dcgPath ?? "dcg",
  };

  test("allows a safe command", async () => {
    const result = await runDcg("ls -la", config);
    expect(result.decision).toBe("allow");
  });

  test("denies rm -rf /", async () => {
    const result = await runDcg("rm -rf /", config);
    expect(result.decision).toBe("deny");
    expect(result.rule_id).toBeDefined();
    expect(result.severity).toBe("critical");
    expect(result.reason).toBeTruthy();
  });

  test("denies git reset --hard", async () => {
    const result = await runDcg("git reset --hard HEAD~5", config);
    expect(result.decision).toBe("deny");
    expect(result.rule_id).toContain("git");
    expect(result.reason).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// runDcg error paths
// ---------------------------------------------------------------------------

describe("runDcg error handling", () => {
  test("fail-open on missing binary", async () => {
    const result = await runDcg("ls", {
      ...baseConfig,
      binary: "/nonexistent/path/dcg-12345",
      timeoutMs: 2000,
    });
    expect(result.decision).toBe("allow");
    expect(result.reason).toContain("not available");
  });

  test("fail-closed on missing binary", async () => {
    const result = await runDcg("ls", {
      ...baseConfig,
      binary: "/nonexistent/path/dcg-12345",
      failMode: "closed",
      timeoutMs: 2000,
    });
    expect(result.decision).toBe("deny");
    expect(result.reason).toContain("not available");
  });
});

// ---------------------------------------------------------------------------
// probeBinary
// ---------------------------------------------------------------------------

describe("probeBinary", () => {
  test("returns false for a present, runnable binary", async () => {
    const missing = await probeBinary(process.execPath, 2000);
    expect(missing).toBe(false);
  });

  test("returns true for a nonexistent binary (ENOENT)", async () => {
    const missing = await probeBinary("/nonexistent/dcg-12345", 2000);
    expect(missing).toBe(true);
  });

  test("returns true for a non-executable file (EACCES)", async () => {
    // Skip when running as root — root bypasses the exec bit and the test
    // would no longer exercise the EACCES branch.
    const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
    if (isRoot) return;

    const dir = mkdtempSync(join(tmpdir(), "dcg-probe-"));
    const file = join(dir, "not-executable");
    writeFileSync(file, "not a binary");
    chmodSync(file, 0o644);
    try {
      const missing = await probeBinary(file, 2000);
      expect(missing).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
