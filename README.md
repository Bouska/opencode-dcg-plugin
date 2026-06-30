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
cp dist/index.js /path/to/project/.opencode/plugins/dcg-guard.js
```

OpenCode auto-loads `.js`/`.ts` files placed in `.opencode/plugins/`.

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

dcg's own bypass is also respected: if `DCG_BYPASS=1` is set, dcg returns "allow" for everything and commands pass through.

### Example

```bash
# Fail closed (block on any dcg error), 3s timeout, also check "task" tool
export DCG_PLUGIN_FAIL_MODE=closed
export DCG_PLUGIN_TIMEOUT_MS=3000
export DCG_PLUGIN_TOOLS=bash,task
```

## Development

```bash
bun install          # install dev dependencies
bun run typecheck    # tsc --noEmit
bun test             # run tests (includes dcg integration tests if dcg is in PATH)
bun run build        # compile to dist/
```

## License

MIT
