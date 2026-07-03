# opencode-dcg-plugin

An [OpenCode](https://opencode.ai) plugin that blocks destructive shell commands before they execute, using the [destructive_command_guard](https://github.com/Dicklesworthstone/destructive_command_guard) (dcg) binary.

When the AI agent runs a `bash` command, this plugin calls `dcg --robot test "<command>"` to check it. If dcg flags the command as destructive, the tool call is aborted with an informative error. Safe commands pass through with ~25ms of overhead.

## Prerequisites

**Install dcg** — see the [dcg README](https://github.com/Dicklesworthstone/destructive_command_guard#installation) for full instructions. Quick install:

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh" | bash -s -- --easy-mode
```

Verify it works:

```bash
dcg --version
dcg --robot test "rm -rf /"   # should print JSON with "decision": "deny"
```

## Installation

### Option A — `opencode plugin` CLI (recommended)

The official OpenCode CLI installs the plugin and registers it in `opencode.json` in one step:

```bash
# project-level (writes to ./opencode.json)
opencode plugin opencode-dcg-plugin

# global (writes to ~/.config/opencode/opencode.json)
opencode plugin --global opencode-dcg-plugin

# pin a specific version
opencode plugin opencode-dcg-plugin@0.3.0

# replace an existing install
opencode plugin --force opencode-dcg-plugin
```

Under the hood this runs `bun add` into `~/.cache/opencode/node_modules/` and appends `"opencode-dcg-plugin"` to the `plugin` array of your `opencode.json`. The plugin auto-loads on the next OpenCode start.

### Option B — npm (manual fallback)

Use this if the CLI is unavailable or you prefer to manage the config by hand:

```bash
# in your project root (or global config)
npm install opencode-dcg-plugin
```

Then add to your `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-dcg-plugin"]
}
```

### Option C — local file (development only)

Build the plugin and copy the output into your `.opencode/plugins/` directory:

```bash
git clone https://github.com/Bouska/opencode-dcg-plugin.git
cd opencode-dcg-plugin
bun install && bun run build
cp dist/opencode-dcg-plugin.js /path/to/project/.opencode/plugins/dcg-guard.js
```

OpenCode auto-loads `.js`/`.ts` files placed in `.opencode/plugins/`. The build produces a single bundled `opencode-dcg-plugin.js` — the LLM review feature is inlined into the same file, so only one copy is needed. **Do not combine this with Option A or B** — they use separate load paths.

### Uninstalling

The current `opencode plugin` CLI only installs. To remove the plugin:

1. Delete `"opencode-dcg-plugin"` from the `plugin` array in `opencode.json`.
2. Delete the package cache: `rm -rf ~/.cache/opencode/node_modules/opencode-dcg-plugin`.
3. If you used Option C, delete the copied file from `.opencode/plugins/`.

> **Note:** A richer subcommand set (`plugin add | list | update | remove`) is tracked in [opencode #7611](https://github.com/anomalyco/opencode/issues/7611).

## How it works

```
agent calls bash tool with command
        │
        ▼
┌─────────────────────────────────┐
│  tool.execute.before hook       │
│  extract output.args.command    │
└───────────────┬─────────────────┘
                │
                ▼
┌─────────────────────────────────┐
│  spawn: dcg --robot test <cmd>  │
│  parse JSON stdout              │
└───────────────┬─────────────────┘
                │
        ┌───────┴───────┐
        ▼               ▼
   "allow"          "deny"
        │               │
        │               ▼
        │       throw Error
        │       (command aborted)
        ▼
   command executes
```

The plugin is a thin adapter — all rule/pack configuration (which commands are destructive, severity levels, allowlists) is managed by dcg itself via `~/.config/dcg/config.toml` or a project-level `.dcg.toml`. See the [dcg configuration docs](https://github.com/Dicklesworthstone/destructive_command_guard#configuration).

## Plugin configuration

The plugin reads its own behavior from environment variables (all optional):

| Variable | Default | Description |
|---|---|---|
| `DCG_PLUGIN_ENABLED` | `true` | Set to `false`/`0` to disable the plugin entirely. |
| `DCG_PLUGIN_FAIL_MODE` | `open` | `open` = allow commands if dcg errors or times out. `closed` = block them. |
| `DCG_PLUGIN_TIMEOUT_MS` | `5000` | Timeout in milliseconds for a single dcg invocation. |
| `DCG_PLUGIN_TOOLS` | `bash` | Comma-separated tool names to check (e.g. `bash,task`). |
| `DCG_PLUGIN_BINARY` | `dcg` | Name or full path of the dcg binary. |
| `DCG_PLUGIN_DEBUG` | `false` | Set to `true`/`1` to emit dcg decisions and stderr via the structured logger. Note: this currently surfaces only in OpenCode's logs panel; plugin log delivery via `client.app.log()` has known issues upstream (see [opencode #5793](https://github.com/anomalyco/opencode/issues/5793), [#7301](https://github.com/anomalyco/opencode/issues/7301)). |
| `DCG_PLUGIN_STRICT_MISSING` | `false` | Set to `true`/`1` to throw on **every** command when the dcg binary is missing. Default: throw once on the first command, then fall through to `failMode` so the user's workflow isn't blocked. Use this in environments where the plugin silently no-opping is unacceptable. **Note:** the dcg probe runs asynchronously at plugin init with a 2s cap; the first command(s) can pass through unchecked if dcg is slow to probe. |

### LLM review agent (optional)

When enabled, blocked commands are sent to an OpenCode LLM subsession for a second opinion. If the LLM deems the command safe, the command is allowed for that single invocation only — the next run is re-checked by dcg and re-reviewed if blocked again. This uses OpenCode's own model infrastructure — no external API key required. A subsession appears in the TUI during review.

| Variable | Default | Description |
|---|---|---|
| `DCG_PLUGIN_REVIEW_ENABLED` | `false` | Set to `true`/`1` to enable LLM review of blocked commands. |
| `DCG_PLUGIN_REVIEW_MODEL` | _(agent default)_ | Model in `providerID:modelID` format (e.g. `anthropic:claude-sonnet-4`). |
| `DCG_PLUGIN_REVIEW_AGENT` | `general` | OpenCode agent to use for the review subsession. |
| `DCG_PLUGIN_REVIEW_TIMEOUT_MS` | `60000` | Timeout in ms for the LLM review. |
| `DCG_PLUGIN_REVIEW_CONTEXT_MESSAGES` | `20` | Max parent session messages to include as context. |
| `DCG_PLUGIN_REVIEW_CONTEXT_MAX_CHARS` | `4000` | Max characters of conversation context in the prompt. |

If the review fails (session error, timeout, unparseable response), the command is blocked — the safe default is to respect dcg's original denial.

> **Security note — prompt injection.** The review LLM receives conversation context from the parent session (see `DCG_PLUGIN_REVIEW_CONTEXT_MESSAGES`), and that context is partially agent/user-controlled. A sufficiently crafted command, prior message, or rule override can prompt-inject the review LLM into approving a destructive command with no human in the loop. The default is `DCG_PLUGIN_REVIEW_ENABLED=false` for a reason: leave it disabled in any environment where the conversation history is not fully trusted, and treat any "approved by review" command as if you had approved it yourself.

> **Note:** The default agent (`general`) must be enabled in your OpenCode config. If you've disabled it (e.g. `opencode.json` → `agent.general.disable: true`), the review will fail. Either re-enable it, or set `DCG_PLUGIN_REVIEW_AGENT` to an enabled agent (e.g. `build`, or a custom agent you've defined in `.opencode/agents/`).

dcg's own bypass is also respected: if `DCG_BYPASS` is set in your **environment** before starting OpenCode, the plugin skips its own dcg invocation and allows every command. This is a **performance optimization, not a security control** — dcg's per-spawn env re-spread already returns "allow" when `DCG_BYPASS` is set, so the plugin's short-circuit saves the per-command spawn cost (~5–50ms per bash call) without changing what gets blocked. The one scenario where the plugin's short-circuit does something dcg alone cannot: when `dcg` is not installed and `DCG_BYPASS` is set, the plugin passes through silently instead of throwing a missing-binary error. The `DCG_BYPASS` env var must be set on the user side, not on the command side.

> **Note — value contract.** The plugin and dcg recognize the **same** set of values for `DCG_BYPASS` — `1`, `true`, `yes`, `y`, `on` (case-insensitive, trimmed). Falsy values (`0`, `false`, `no`, `n`, `off`) and anything else keep both layers active. There is no documented divergence between the two parsers.

### Example

```bash
# Fail closed (block on any dcg error), 3s timeout, also check "task" tool
export DCG_PLUGIN_FAIL_MODE=closed
export DCG_PLUGIN_TIMEOUT_MS=3000
export DCG_PLUGIN_TOOLS=bash,task

# Block every command when dcg is missing (no silent fail-open)
export DCG_PLUGIN_STRICT_MISSING=true

# Enable LLM review with a specific model
export DCG_PLUGIN_REVIEW_ENABLED=true
export DCG_PLUGIN_REVIEW_MODEL=anthropic:claude-sonnet-4
```

## Development

```bash
bun install          # install dev dependencies
bun run typecheck    # tsc --noEmit
bun test             # run tests (includes dcg integration tests if dcg is in PATH)
bun run build        # bundle to dist/opencode-dcg-plugin.js
```

## Acknowledgements

This plugin builds on the work of two prior reference implementations:

- [jms830/opencode-dcg-plugin](https://github.com/jms830/opencode-dcg-plugin) — the original OpenCode plugin for dcg by Jordan Stout.
- [Alex Mikhalev's gist](https://gist.github.com/AlexMikhalev/bc7cc0f237bdb2a6fade347aba203acb) — a corrected variant that identified and fixed the hook-registration bug in the original, along with a helpful writeup of the OpenCode plugin API.

Both provided the core integration pattern (spawning `dcg`, JSON parsing, throwing to block) that this plugin refines and extends with configurable fail-mode, timeouts, graceful dcg-not-found handling, and TypeScript types.

## Disclaimer

This plugin is not built by the OpenCode team and is not affiliated with OpenCode in any way.

## License

MIT
