+++
title = "Agents"
weight = 95
+++

An AI agent works on a binary through the `binbun` Python package, the same API as your scripts. An agent that can run shell commands uses the package directly. A host that only calls tools uses `binbun mcp`, which runs the agent's Python for it. In a window, the agent is a participant with its own name, avatar and cursor, and its edits are its own undo steps.

Bring your own harness. binbun includes no model and needs no AI account: you use the agent you already have, with your own subscription, model and settings, and binbun gives it the tools. The agent talks to people in address threads.

## Python

Install the package in the interpreter the agent's shell uses:

```sh
pip install binbun
```

Without a window, `binbun.open` analyses the binary in the agent's own process. This example uses the source repository's checked-in fixture; `project=False` keeps the agent's changes out of the saved project.

```python
import binbun

with binbun.open("tests/fixtures/program-x86_64.elf", project=False) as db:
    f = db.functions.get_by_name("classify")
    print(f.decompile().text)
```

To work in the window you have open, the agent connects as itself:

```python
import binbun

db = binbun.connect(agent="Codex")
```

The name is the one the window shows. An agent should give its harness's name as **File → Connect an Agent…** lists it (`Codex`, `Claude Code`, `Cursor`): binbun recognises the harnesses' own client names too (`codex-mcp-client` is `Codex`) and draws the harness's mark on the avatar. Gemini CLI and any name not in that list get a generic agent glyph. Without `agent`, the connection is an ordinary script's.

[Python](@/docs/python.md) covers the working model: transactions, undo, remote and local connections. The [reference](@/docs/reference/python.md) lists every object and argument.

## MCP hosts

`binbun mcp` is an MCP server on standard input and output. It listens on nothing; the host starts it. Register it once in the agent's harness:

| Harness | Setup |
| --- | --- |
| Codex | `codex mcp add binbun -- binbun mcp` |
| Claude Code | `claude mcp add --scope user binbun -- binbun mcp` |
| Cursor | the entry below, in `~/.cursor/mcp.json` |
| Grok | `grok mcp add binbun -- binbun mcp` |
| Fx | `fx mcp add binbun -- binbun mcp` |
| OpenCode | `opencode mcp add binbun --global -- binbun mcp` |
| Antigravity | `agy mcp add binbun binbun mcp` |
| Kiro | `kiro-cli mcp add --name binbun --scope global --command binbun --args mcp` |
| Muse | the entry below, in `~/.config/muse/settings.json` |
| Pi | `pi mcp add binbun -- binbun mcp` |
| omp | the entry below, in `~/.omp/agent/mcp.json` |
| Gemini CLI | `gemini mcp add -s user binbun binbun mcp` |

The entry for a config file goes under its `mcpServers`:

```json
{
  "mcpServers": {
    "binbun": {
      "type": "stdio",
      "command": "binbun",
      "args": ["mcp"]
    }
  }
}
```

These forms find `binbun` on the host's search path. **File → Connect an Agent…** shows each harness's command or entry for the binbun you are running, ready to copy: by the path the search path gives when the first `binbun` there is this one (a link there still works after an update), else by its absolute path. On Windows the setup runs the command, `bin\binbun.exe` beside the app.

### The two tools

`python` runs code in a persistent interpreter: variables, imports and functions survive between calls until the interpreter restarts. `db`, `here`, `current_function` and `selection` are predefined as in the console, read from the window before each call, so `here` is your cursor and `current_function` the function you are looking at. The value of a final expression and printed output are returned. A call can give an `intent`, a few words that label its undo step.

`api` describes the installed Python API. With no query it gives a short digest; with a dotted name such as `Function.decompile`, that name's signature and docstring; with words, the names that match them.

The interpreter is your own Python with `binbun` installed: `python3`, or the one named by `--python` or `BINBUN_PYTHON`. A call's output is cut to 20,000 characters by default (`max_chars`), keeping its start and end around a marker. `Out[n]` keeps cell `n`'s whole output, and `Out[n].result` its value. A call that runs past its `timeout` (120 seconds by default) or that the host cancels is interrupted. If the interpreter is still busy three seconds later, it is killed and a new one started, and the next result says `interpreter: "restarted"` because earlier variables are gone.

### Which binary

With no file, `binbun mcp` works in the running binbun window. It opens the same binary again in the interpreter and follows the window's changes; its writes are made in the window. If several binaries are open, it works on the one whose window had the focus last, and each result names it. `db = binbun.connect("libc.so.6")` in a call switches to another open binary. `--database` (the binary's path) or `--socket` (a window's script socket) chooses one when the server starts.

`binbun mcp FILE` opens FILE itself, without a window.

The agent is named from the MCP handshake: a listed harness by its name (`Codex`, `Claude Code`, `Cursor`, `Gemini CLI`, `OpenCode`, `Pi`, `omp`), another client by the name it reports.

## In the window

An agent connected to a window is a participant whether or not the project is shared. Its avatar sits among the participants at the top of the window while it is connected, and its cursor shows where its code works.

Its edits are applied directly and attributed to it in the history and in **Why…**. Each `python` call is one undo step labelled with the agent's name and the call's intent, else its first line (`Codex: Rename helpers of main`); a Python connection's writes are grouped as a script's are. Undo them as any other step.

The agent's identity is its own, not yours. Your binbun makes it at first use and keeps it, so an agent of the same name is the same participant in every project.

In a [shared project](@/docs/collaboration.md), the agent is a member with the Agent role. It edits as an editor does and is shown as an agent. The owner can limit it like any member: make it a viewer, or remove it.

## Talking to people

There is no chat from an agent. It opens a thread, or replies in one, at the address the remark is about, attaches the evidence it rests on, and mentions whom it is for. `db.session.members` lists who is in the session, people and agents, each with `name`, `kind` (`"person"` or `"agent"`), `role`, `online`, `you` and `key`; `db.session.members["alice"]` finds one by name or key. The evidence is the query results themselves (C lines, `db.xrefs.to_ea(…)`, `f.verify()`, an item of `f.why().items`, a string, a call, or the agent's own words as a `str`), each quoted when the post is made:

```python
alice = db.session.members["alice"]
db.threads.create(
    f,
    "This parses the config file; renamed to parse_config.",
    evidence=[db.xrefs.to_ea(f)],
    mentions=[alice],
)
```

A thread is about what `create` is given: a function, a line of C, a variable, a string, a suggestion, a type (`binbun.Anchor.type(key)`) or an address. `mentions` takes members of `db.session.members`.

An edit can be put to people as a suggestion instead of made. The writes inside a `db.suggestion` block are recorded, not applied, and become one suggestion with its rationale and evidence when the block ends; someone accepts or dismisses it:

```python
c = f.decompile()
with db.suggestion("Name parse_config", rationale="opens and parses the config file",
                   evidence=[db.xrefs.to_ea(f), c.lines[3:5], f.verify()]):
    db.functions.set_name(f, "parse_config")
    c.variable("v1").rename("path")
```

Each write is checked as it is made, so one that would be refused raises at its line, and an exception leaving the block makes no suggestion. `thread=` attaches the suggestion to a thread; `db.suggestion(supersedes=s, …)` makes a new version of suggestion `s`.

## Safety

The code runs with your user's rights and is not sandboxed. Strings, names and code in the binary come from the program you are analysing, and an agent can be misled by instructions planted in them. Review what an agent proposes to run on an untrusted sample.
