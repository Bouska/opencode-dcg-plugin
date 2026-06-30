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

### Option A — npm (recommended)

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

### Option B — local file

Build the plugin and copy the output into your `.opencode/plugins/` directory:

```bash
git clone https://github.com/pablo/opencode-dcg-plugin
cd opencode-dcg-plugin
bun install && bun run build
cp dist/index.js  /path/to/project/.opencode/plugins/dcg-guard.js
cp dist/review.js /path/to/project/.opencode/plugins/review.js
```

OpenCode auto-loads `.js`/`.ts` files placed in `.opencode/plugins/`. Both files are required: `index.js` imports `./review.js` for the optional LLM review feature. (OpenCode will also auto-load `review.js` as a separate plugin entry; it has no `default` export, so it is silently dropped — harmless.)

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
| `DCG_PLUGIN_DEBUG` | `false` | Set to `true`/`1` to log dcg decisions and stderr to the console. |

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

dcg's own bypass is also respected: if `DCG_BYPASS=1` is set, dcg returns "allow" for everything and commands pass through.

### Example

```bash
# Fail closed (block on any dcg error), 3s timeout, also check "task" tool
export DCG_PLUGIN_FAIL_MODE=closed
export DCG_PLUGIN_TIMEOUT_MS=3000
export DCG_PLUGIN_TOOLS=bash,task

# Enable LLM review with a specific model
export DCG_PLUGIN_REVIEW_ENABLED=true
export DCG_PLUGIN_REVIEW_MODEL=anthropic:claude-sonnet-4
```

## Development

```bash
bun install          # install dev dependencies
bun run typecheck    # tsc --noEmit
bun test             # run tests (includes dcg integration tests if dcg is in PATH)
bun run build        # compile to dist/
```

## Acknowledgements

This plugin builds on the work of two prior reference implementations:

- [jms830/opencode-dcg-plugin](https://github.com/jms830/opencode-dcg-plugin) — the original OpenCode plugin for dcg by Jordan Stout.
- [Alex Mikhalev's gist](https://gist.github.com/AlexMikhalev/bc7cc0f237bdb2a6fade347aba203acb) — a corrected variant that identified and fixed the hook-registration bug in the original, along with a helpful writeup of the OpenCode plugin API.

Both provided the core integration pattern (spawning `dcg`, JSON parsing, throwing to block) that this plugin refines and extends with configurable fail-mode, timeouts, graceful dcg-not-found handling, and TypeScript types.

## License

MIT
