# Agent marks

binbun shows these marks only inside the app, as the avatar of an agent while it
is connected. They never appear in marketing images, promotional screenshots or
binbun's own branding. Agents not listed here get the Bot glyph with their name
(Gemini CLI included).

## Source: T3 Code (owner's choice, 2026-11-15)

By the owner's decision of 2026-11-15, binbun uses **T3 Code's harness list and
T3 Code's icons** for it, plus omp (see its entry). T3 Code is MIT-licensed
(<https://github.com/pingdotgg/t3code>, "Copyright (c) 2026 T3 Tools Inc."),
read at commit `3ee4aa62ec0ed16375e3f28c8ad2138a44ebaa88` (2026-11-15). The
harness list is T3's provider registry,
`packages/client-runtime/src/providerClients.ts`: Codex, Claude, Cursor, Grok,
fx, OpenCode, Antigravity, Kiro, Muse Code, Pi.

The MIT licence covers T3's code and drawings. It grants nothing for the
vendors' trademarks, so each entry below keeps that vendor's own terms.

How the files were made:

- **Provider-package icons** (Cursor, Grok, fx, OpenCode, Kiro, Muse, Pi):
  `packages/provider-<id>/src/client.ts` defines
  `icon: { viewBox, fill: { light, dark }, paths }` (type `ProviderIcon` in
  `packages/provider-core/src/client.ts`). Each was written out as a standalone
  SVG the way T3's renderer (`apps/web/src/components/chat/ProviderPackageIcon.tsx`)
  draws it. `-light.svg` uses `fill.light` (T3's light theme), `-dark.svg` uses
  `fill.dark`. Per-path `fill`, `fillRule` and `gradient` (as a
  `userSpaceOnUse` `linearGradient`) are kept. When light and dark are equal,
  there is one file. Path data and colours are unchanged.
- **Codex**: T3 has no package icon for Codex. Its path comes from the `OpenAI`
  component in `apps/web/src/components/Icons.tsx` (`fill-current`). T3 colours
  it `text-black dark:text-white`
  (`apps/web/src/components/chat/ProviderInstanceIcon.tsx`), so
  `codex-light.svg` is `#000` and `codex-dark.svg` is `#fff`. The path is
  identical to T3's marketing file `openai_dark.svg`.
- **Claude, Antigravity**: these are byte-identical copies of T3's marketing files,
  `apps/marketing/public/harnesses/claude-ai-icon.svg` and `antigravity.svg`
  (the same files are served at <https://t3.codes/harnesses/>). They keep
  their own colours, so there is one file each.

| id | Files | Colour |
|---|---|---|
| `codex` | `codex-light.svg`, `codex-dark.svg` | OpenAI Blossom, `#000` / `#fff` |
| `claude-code` | `claude-code.svg` | Claude spark, `#D97757` |
| `cursor` | `cursor-light.svg`, `cursor-dark.svg` | cube, `#26251E` / `#EDECEC` |
| `grok` | `grok-light.svg`, `grok-dark.svg` | Grok glyph, `#0F0F0F` / `#F5F5F5` |
| `fx` | `fx-light.svg`, `fx-dark.svg` | "fx" glyph, `#0F0F0F` / `#F5F5F5` |
| `opencode` | `opencode-light.svg`, `opencode-dark.svg` | ink `#211E1E` + inner `#CFCECD` / ink `#F1ECEC` + inner `#4B4646` |
| `antigravity` | `antigravity.svg` | Antigravity arch, multicolour gradient (masks + filters) |
| `kiro` | `kiro.svg` | ghost on a `#9046FF` tile |
| `muse` | `muse.svg` | Meta infinity mark, blue gradients |
| `pi` | `pi-light.svg`, `pi-dark.svg` | Pi block glyph, `#0F0F0F` / `#F5F5F5` |
| `omp` | `omp.svg` | `currentColor` block-art glyph (not from T3) |

Every file was rendered with `rsvg-convert` on its theme's background and
checked by eye.

**How the avatars draw them** (`gui/view/src/agents.rs`): like a person's
default picture, the agent's mark sits large on its key-coloured circle where
the initial goes, in the initials' ink (white or near-black, whichever reads
on the circle). The mark's shape is drawn as a mask: the `-light` file of a
pair (the same shape as `-dark`), or a one-file mark itself. Claude and
Antigravity keep their own colours only where every one of them reads on the
circle. Each mark is centred and sized by its ink, not its file's box (the
boxes pad the drawings unevenly): the table holds each file's ink bounds,
and the app serves the file with its `viewBox` replaced by a square on the
ink's centre (`Mark::frame`), drawn over the whole circle; a test renders
each served file and checks that its ink is centred. Two single-colour
forms are made from the vendor's paths, with the path data unchanged:

- `kiro-mono.svg`: the ghost of `kiro.svg` with its two eyes cut out
  (even-odd). There is no tile, and the box is cropped to the ghost.
- `opencode-mono.svg`: the two paths of `opencode-*.svg`. The inner shade is
  at a quarter of the ink, as the published files shade it.

## Per-vendor terms

- **Codex (OpenAI)**: <https://openai.com/brand/#usage-terms>. OpenAI grants a
  revocable, non-exclusive permission if you follow its guidelines: use the
  mark only when it relates directly to OpenAI services, use it exactly as
  provided, do not imply endorsement, do not make it more prominent than your
  own marks, and do not add colours to the Blossom. T3's path is the Blossom
  without OpenAI's clear-space box. Questions go to partnercomms@openai.com.
- **Claude Code (Anthropic)**: <https://www.anthropic.com/legal/trademark-guidelines>
  says: "You may only use our trademarks as specifically permitted by us and
  only in materials we approve beforehand." The Consumer Terms forbid using
  Anthropic logos with other products without written permission.
  **⚠ Requires prior approval as written** (marketing@anthropic.com).
  Bundled by the owner's decision, the owner accepting the risk.
- **Cursor (Anysphere)**: <https://cursor.com/brand> offers the assets "to
  represent Cursor consistently and accurately" and has no licence or
  permission clause. T3's colours match Cursor's kit (`CUBE_2D_LIGHT`
  `#26251e`, `CUBE_2D_DARK` `#edecec`). This is nominative use; no explicit
  grant was found.
- **Grok (xAI / SpaceXSI)**: <https://x.ai/legal/brand-guidelines> (dated
  2025-02-14) says marks may be used "only to accurately refer to us or our
  services", must not imply endorsement, and must not be used in product
  names. Logos may be used only "exactly as provided at the download link …
  without any alteration". xAI may revoke permission at any time. **⚠** T3's
  glyph is not xAI's file. The kit
  (<https://data.x.ai/logos/SpaceXAI_Grok_Assets.zip>) returned HTTP 403 on
  2026-11-15, so the shapes could not be compared. Questions go to
  legal@x.ai.
- **fx (Vercel Labs)**: <https://github.com/vercel-labs/fx> is Apache-2.0
  (code only). Vercel's brand page (<https://vercel.com/geist/brands>) does not
  list an fx mark. For Vercel marks it allows truthful descriptive use and
  requires prior written permission for "all other uses … including in
  connection with … software … that utilize our open source code". **⚠
  Unclear** whether the fx glyph counts as a Vercel mark. Questions go to
  brand@vercel.com.
- **OpenCode (Anomaly)**: <https://opencode.ai/brand> says do not suggest
  endorsement, do not use the marks in product names or on merchandise, and do
  not recolour, swap tones or stretch the logo. No permission is needed for
  identifying use. T3's drawing is the same logo on a `0 0 32 40` grid with
  T3's greys, which are close to but not the same as the brand files' greys.
- **Antigravity (Google)**: Google's brand rules
  (<https://about.google/brand-resource-center/brand-elements>) say that to
  use a Google product icon "in your work", you request permission through the
  Partner Marketing Hub. No Antigravity-specific brand kit was found. **⚠
  Permission flag**, the same as for any Google product icon. The T3 file's
  mask and filter ids (`lobe-icons-antigravity-…`) suggest it was taken from
  LobeHub's icon set [INFERENCE].
- **Kiro (AWS)**: kiro.dev has no brand page (`/brand` returns 404). The AWS
  Trademark Guidelines (<https://aws.amazon.com/trademark-guidelines/>)
  define "AWS Marks" to include "all other names and logos associated with AWS
  products". The only logo they license generally is "Powered by AWS", and
  they forbid altering logo images. **⚠ Permission flag:** the Kiro logo is
  not covered by any published grant.
- **Muse Code (Meta)**: T3's Muse icon is Meta's infinity logo in its blue
  gradient. Meta's trademark page (<https://www.meta.com/brand/resources/meta/our-trademarks/>)
  says: "You may only use our trademarks with our permission, including as
  authorized by any brand guidelines we may publish." **⚠ Permission flag.**
- **Pi (Earendil)**: Pi has no published logo-use terms. Earendil enforces its
  trademark (<https://rfc.earendil.com/0015>; US application 99752393 for
  PI). T3's glyph is not Pi's coloured primary logo. **⚠ Unclear.** Questions
  go to rfc@earendil.com. Bundled by the owner's decision.
- **omp**: not a T3 harness. Source:
  <https://github.com/can1357/oh-my-pi> (MIT),
  `packages/tui/src/prompt/welcome.ts`, the `PI_LOGO` block art, drawn cell
  for cell as an SVG in `currentColor`. The `▒` cells are drawn at
  `fill-opacity` 0.45. The owner states that omp allows this use.

## MCP client identity (`initialize` → `params.clientInfo`)

Checked on 2026-11-15. "Observed" means a logging stdio server
(`fake_mcp.py` in scratch) received the request from the real binary.

| Harness | `clientInfo.name` | Where found |
|---|---|---|
| Codex | `codex-mcp-client` (title `Codex`) | <https://github.com/openai/codex/blob/main/codex-rs/codex-mcp/src/rmcp_client.rs> |
| Claude Code | `claude-code` (title `Claude Code`) | shipped binary, npm `@anthropic-ai/claude-code-linux-x64@2.1.325` |
| Cursor IDE | `cursor-vscode` | Cursor 3.30.14 `.deb`, `extensions/cursor-mcp/dist/main.js` |
| Cursor CLI (`agent`) | `Cursor` | CLI bundle 2026.11.13-eacade1, `dist-package/index.js` |
| Grok | `grok-shell-<server name>`, e.g. `grok-shell-binbun` | <https://github.com/xai-org/grok-build> `crates/codegen/xai-grok-mcp/src/servers.rs`, `make_client_info`: `Implementation::new(format!("grok-shell-{server_name}"), VERSION)`. Stdio uses the plain `initialize` handshake (`2025-11-25`). Match on the prefix `grok-shell-`. |
| fx | `fx` | <https://github.com/vercel-labs/fx> `src/core/mcp_host/runtime.zig` (`.info = .{ .name = "fx", … }`). It first sends `server/discover` with the same name in `_meta`, then falls back to `initialize`. |
| OpenCode | `opencode` | <https://github.com/anomalyco/opencode/blob/dev/packages/server/src/routes.ts> |
| Antigravity | `antigravity-client` (version `v1.0.0`) | Observed: Antigravity CLI 1.5.9 (`cli_linux_x64.tar.gz` from the manifest of <https://antigravity.google/cli/install.sh>). It sends `server/discover`, then `initialize` (`2025-11-25`) after a `-32601`. The same string is in the binary. App and IDE share the config file; their name was not observed. |
| Kiro CLI | `Q DEV CLI` | Static: `kiro-cli` 3.3.0 (`kirocli-x86_64-linux.tar.gz` from `prod.download.cli.kiro.dev`) holds two inline `"Q DEV CLI"` + `"1.0.0"` constructions. Source of the predecessor: <https://github.com/aws/amazon-q-developer-cli> `crates/chat-cli/src/mcp_client/client.rs` (`Implementation { name: "Q DEV CLI", version: "1.0.0" }`). Not observed: the CLI refuses MCP commands without a login. |
| Muse Code | `tbh` (version `0.1.0`) | Observed: `muse` 1.4.20-R8619.1 (channel `muse-stable`, via <https://dev.meta.ai/install.sh>), `muse exec --provider echo`, `initialize` with protocol `2025-06-18`. |
| Pi | `pi` | <https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/extensions/mcp/runtime.ts> |
| omp | `omp-coding-agent` | <https://github.com/can1357/oh-my-pi/blob/main/packages/coding-agent/src/mcp/client.ts> |

All of these harnesses can connect to MCP servers over stdio. Proxies such as
`mcp-remote` may append text to the name, for example
`cursor-vscode (via mcp-remote 0.1.37)`.

## Registering binbun (`/abs/binbun mcp`, stdio)

- **Codex** (<https://developers.openai.com/codex/mcp>):
  `codex mcp add binbun -- /abs/binbun mcp` → `~/.codex/config.toml`
  ```toml
  [mcp_servers.binbun]
  command = "/abs/binbun"
  args = ["mcp"]
  ```
- **Claude Code** (<https://code.claude.com/docs/en/mcp>):
  `claude mcp add --scope user binbun -- /abs/binbun mcp`. The project file
  is `.mcp.json`:
  ```json
  { "mcpServers": { "binbun": { "command": "/abs/binbun", "args": ["mcp"] } } }
  ```
- **Cursor** (<https://cursor.com/docs/mcp>): there is no shell command. Use
  `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project):
  ```json
  { "mcpServers": { "binbun": { "type": "stdio", "command": "/abs/binbun", "args": ["mcp"] } } }
  ```
- **Grok** (<https://docs.x.ai/build/features/mcp-servers>):
  `grok mcp add binbun -- /abs/binbun mcp` → `~/.grok/config.toml`. Add
  `--scope project` to write `.grok/config.toml`. Grok also reads
  `~/.claude.json`, `.cursor/mcp.json` and `.mcp.json`.
  ```toml
  [mcp_servers.binbun]
  command = "/abs/binbun"
  args = ["mcp"]
  ```
- **fx** (<https://fx.sh/docs/capabilities/mcp>):
  `fx mcp add binbun -- /abs/binbun mcp` → `~/.fx/mcp.json`. Add `--project`
  to write `.mcp.json`; project servers need `fx mcp approve binbun`.
  ```json
  { "mcpServers": { "binbun": { "type": "stdio", "command": ["/abs/binbun", "mcp"] } } }
  ```
- **OpenCode** (<https://opencode.ai/docs/mcp-servers>):
  `opencode mcp add binbun --global -- /abs/binbun mcp` →
  `~/.config/opencode/opencode.json(c)`
  ```jsonc
  { "$schema": "https://opencode.ai/config.json",
    "mcp": { "servers": { "binbun": { "type": "local", "command": ["/abs/binbun", "mcp"] } } } }
  ```
- **Antigravity** (<https://antigravity.google/docs/mcp>): the CLI command is
  `agy mcp add binbun /abs/binbun mcp` (flags go before the name). It writes
  `~/.gemini/config/mcp_config.json`, the file shared by Antigravity App, IDE
  and CLI. The workspace file is `.agents/mcp_config.json`. In the App and the
  IDE you can also edit the file through Customizations or MCP Servers → View
  raw config.
  ```json
  { "mcpServers": { "binbun": { "command": "/abs/binbun", "args": ["mcp"] } } }
  ```
- **Kiro** (<https://kiro.dev/docs/reference/cli-commands/>,
  <https://kiro.dev/docs/mcp/configuration/>):
  `kiro-cli mcp add --name binbun --scope global --command /abs/binbun --args mcp`
  → `~/.kiro/settings/mcp.json`. The workspace file is
  `.kiro/settings/mcp.json`.
  ```json
  { "mcpServers": { "binbun": { "command": "/abs/binbun", "args": ["mcp"] } } }
  ```
- **Muse Code** (<https://meta-models.github.io/muse-code-sdk/latest/guides/extend/mcp-servers/>):
  there is no add command (`muse mcp` only has `login` and `logout`). Edit
  `~/.config/muse/settings.json` (or `$XDG_CONFIG_HOME/muse/settings.json`), or
  a project `.mcp.json` in a trusted workspace:
  ```json
  { "schema_version": 1,
    "mcpServers": { "binbun": { "type": "stdio", "command": "/abs/binbun", "args": ["mcp"] } } }
  ```
- **Pi** (<https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/mcp.md>):
  `pi mcp add binbun -- /abs/binbun mcp` → `~/.pi/agent/mcp.json`. Add `-l`
  to write `.pi/mcp.json`.
  ```json
  { "mcpServers": { "binbun": { "command": "/abs/binbun", "args": ["mcp"] } } }
  ```
- **omp** (<https://omp.sh/docs/mcp>): use `/mcp add` inside omp, or edit
  `~/.omp/agent/mcp.json` (user) or `.omp/mcp.json` (project). stdio is the
  default when `type` is omitted. Check the server with `/mcp test binbun`.
  ```json
  { "mcpServers": { "binbun": { "command": "/abs/binbun", "args": ["mcp"] } } }
  ```
