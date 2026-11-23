#!/usr/bin/env python3
r"""Binary Ninja on a whole file, through the MCP server its GUI hosts.

    binja_mcp.py FILE OUT [URL]

Binary Ninja Free has no API and no headless mode, but its GUI serves MCP
over HTTP once its `MCP\Start Server` action is run (or the setting
`ui.mcp.enabled` is on); `MCP\Copy Connection Info` gives the URL
(default here http://127.0.0.1:24642/mcp, or BINJA_MCP; no token).
This opens a copy of FILE (alone in a directory: Binary Ninja loads a
debug file it finds beside a binary), waits for its analysis, and writes
into OUT, as the benchmark reads Ghidra's export:

- `functions.c`: each function's Pseudo C after a `//@bench ADDRESS` line
  (`//@failed WHY` for one it gave none for), as the server gives it but
  for the tag icons it puts before tagged lines;
- `header.h`: what its C refers to, as declarations: `<stdbool.h>`,
  `<stddef.h>`, `<stdint.h>` and Binary Ninja's own names for integer
  types (`int128_t`, `uint128_t`, `wchar16`, `wchar32`), then the view's
  types, its data variables and its functions' prototypes, each in the
  text Binary Ninja gives for its type, with the name put in;
- `names.txt`: the base it loaded the file at (hex), then `ADDRESS NAME`
  lines for its symbols, functions and data variables;
- `version.txt` (`BINJA --version`, default
  /opt/binaryninja-free/binaryninja) and `seconds.txt`: wall-clock
  seconds from opening the file to the last function's Pseudo C. For
  that time the server's process has its threads on the CPUs this script
  may use (as the benchmark pins every tool), put back after. Its
  startup is not in the time (the GUI is up already), a request per
  function is.

Addresses in `functions.c` are the file's own (Binary Ninja's less the
base it loaded a position-independent file at).
"""

import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request

PAGE = 1000


class Mcp:
    """A JSON-RPC session with an MCP server over HTTP."""

    def __init__(self, url):
        self.url = url
        self.session = None
        self.count = 0
        self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "binbun-bench", "version": "0"},
            },
        )
        self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def post(self, body):
        request = urllib.request.Request(
            self.url,
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        if self.session:
            request.add_header("Mcp-Session-Id", self.session)
        with urllib.request.urlopen(request, timeout=4 * 3600) as response:
            self.session = response.headers.get("MCP-Session-Id") or self.session
            data = response.read().decode()
            stream = "event-stream" in response.headers.get("Content-Type", "")
        if not data.strip():
            return None
        if stream:
            events = [line[5:] for line in data.split("\n") if line.startswith("data:")]
            return json.loads(events[-1]) if events else None
        return json.loads(data)

    def request(self, method, params):
        self.count += 1
        reply = self.post({"jsonrpc": "2.0", "id": self.count, "method": method, "params": params})
        if reply is None or "error" in reply:
            raise RuntimeError(f"{method}: {reply}")
        return reply["result"]

    def call(self, tool, **arguments):
        """A tool's text: JSON where it is, else its Markdown."""
        result = self.request("tools/call", {"name": tool, "arguments": arguments})
        text = "".join(part.get("text", "") for part in result.get("content", []))
        if text.lstrip().startswith("{"):
            try:
                return json.loads(text)
            except ValueError:
                pass
        return text

    def rows(self, tool, **arguments):
        """Every row of a paginated table tool, as dictionaries by column."""
        offset = 0
        while offset is not None:
            text = self.call(tool, offset=offset, limit=PAGE, **arguments)
            if not isinstance(text, str):
                raise TypeError(f"{tool}: {text}")
            columns = None
            for line in text.split("\n"):
                if not line.startswith("| "):
                    continue
                cells = [cell.strip() for cell in re.split(r"(?<!\\)\|", line.strip()[1:-1])]
                if columns is None:
                    columns = cells
                elif not set(line) <= set("|- "):
                    yield dict(zip(columns, cells))
            found = re.search(r"^nextOffset: (\d+)$", text, flags=re.MULTILINE)
            offset = int(found.group(1)) if found else None


def pin(url):
    """Puts the threads of the process serving `url` on this process's CPUs:
    each thread's CPUs before, to put back."""
    port = urllib.parse.urlparse(url).port
    listening = subprocess.run(
        ["ss", "-ltnpH", f"sport = :{port}"], capture_output=True, text=True, check=False
    ).stdout
    found = re.search(r"pid=(\d+)", listening)
    if not found:
        raise RuntimeError(f"no process of this user listens on port {port}: its time cannot be pinned")
    mine = os.sched_getaffinity(0)
    before = {}
    for task in os.listdir(f"/proc/{found.group(1)}/task"):
        try:
            before[int(task)] = os.sched_getaffinity(int(task))
            os.sched_setaffinity(int(task), mine)
        except OSError:
            pass
    return before


def unpin(before):
    for task, cpus in before.items():
        try:
            os.sched_setaffinity(task, cpus)
        except OSError:
            pass


def link_base(path):
    """The lowest address an ELF file's segments load at (0 for another file)."""
    with open(path, "rb") as file:
        head = file.read(64)
        if head[:4] != b"\x7fELF" or head[4] != 2:
            return None
        order = "<" if head[5] == 1 else ">"
        offset, = struct.unpack_from(order + "Q", head, 32)
        size, count = struct.unpack_from(order + "HH", head, 54)
        lowest = None
        for index in range(count):
            file.seek(offset + index * size)
            header = file.read(size)
            kind, = struct.unpack_from(order + "I", header, 0)
            address, = struct.unpack_from(order + "Q", header, 16)
            if kind == 1:
                lowest = address if lowest is None else min(lowest, address)
        return None if lowest is None else lowest & ~0xFFF


def declaration(definition, name):
    """`name` declared with Binary Ninja's type text `definition`, which has
    no name in it: `T (* const)(A)` is `T (* const name)(A)`, `T (*[3])(A)`
    is `T (* name[3])(A)`, a function type `T(A) __noreturn` is `T name(A)
    __noreturn`, `T[4]` is `T name[4]`. None where the text is no type of
    an object or function
    (`void`), or a function returning a pointer to one (the name would go
    inside the declarator)."""
    if definition == "void":
        return None
    paren = definition.find("(")
    if paren >= 0 and definition.startswith("(*", paren):
        close = definition.find(")", paren)
        if close < 0 or "(" in definition[paren + 1 : close]:
            return None
        array = definition.find("[", paren, close)
        at = array if array >= 0 else close
        return f"{definition[:at].rstrip()} {name}{definition[at:]}"
    if paren >= 0:
        return f"{definition[:paren].rstrip()} {name}{definition[paren:]}"
    array = re.match(r"^(.*?)((?:\[[0-9a-fx]*\])+)$", definition)
    if array:
        return f"{array.group(1)} {name}{array.group(2)}"
    return f"{definition} {name}"


def types_header(mcp):
    """The view's types as C, each after those it refers to."""
    sources, uses = {}, {}
    for row in mcp.rows("bn_type_list"):
        info = mcp.call("bn_type_info", type=row["type"])
        if isinstance(info, dict) and info.get("type", {}).get("source"):
            sources[row["type"]] = info["type"]["source"]
            uses[row["type"]] = info.get("outgoingDirectTypeReferences", [])
    lines, done = [], set()

    def emit(name, path):
        if name in done or name not in sources:
            return
        done.add(name)
        for used in uses[name]:
            if used not in path:
                emit(used, path | {used})
        lines.append(sources[name])

    tags = sorted(set(re.findall(r"\b(struct|union) (\w+)", "\n".join(sources.values()))))
    lines.extend(f"{kind} {tag};" for kind, tag in tags)
    for name in sources:
        emit(name, {name})
    return lines


def main():
    path, out = sys.argv[1], sys.argv[2]
    url = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("BINJA_MCP", "http://127.0.0.1:24642/mcp")
    binja = os.environ.get("BINJA", "/opt/binaryninja-free/binaryninja")
    os.makedirs(out, exist_ok=True)
    alone = os.path.join(out, "input")
    shutil.rmtree(alone, ignore_errors=True)
    os.makedirs(alone)
    copy = os.path.join(alone, os.path.basename(path))
    shutil.copyfile(path, copy)

    mcp = Mcp(url)
    before = pin(url)
    try:
        header, names, base, seconds = decompiled(mcp, copy, out)
    finally:
        unpin(before)
    with open(os.path.join(out, "header.h"), "w") as file:
        file.write("\n".join(header) + "\n")
    with open(os.path.join(out, "names.txt"), "w") as file:
        file.write(f"{base:x}\n")
        file.writelines(f"{address:x} {name}\n" for name, address in sorted(names.items()))
    version = subprocess.run([binja, "--version"], capture_output=True, text=True, check=False).stdout.strip()
    with open(os.path.join(out, "version.txt"), "w") as file:
        file.write((version.removeprefix("Binary Ninja ") or "unknown") + "\n")
    with open(os.path.join(out, "seconds.txt"), "w") as file:
        file.write(f"{seconds:.1f}\n")
    shutil.rmtree(alone, ignore_errors=True)


def decompiled(mcp, copy, out):
    """Opens `copy`, writes `functions.c` into `out`, closes it: the header's
    lines, the names, the base and the seconds opening, analysing and
    decompiling took (what the header is made from is asked for after)."""
    started = time.time()
    opened = mcp.call("bn_open_item_open", path=os.path.abspath(copy), setActive=True)
    if not isinstance(opened, dict) or "openItem" not in opened:
        raise RuntimeError(f"not opened: {opened}")
    item = opened["openItem"]["handle"]
    try:
        views = [view for view in opened.get("binaryViews", []) if view.get("viewType") != "Raw"]
        view = next((v for v in views if v.get("recommended")), views[0] if views else None)
        if view is None:
            raise RuntimeError("no view of the file")
        mcp.call("bn_binary_view_set_active", binaryView=view["handle"])
        mcp.call("bn_analysis_update_and_wait")
        info = mcp.call("bn_binary_view_info")["binaryView"]
        linked = link_base(copy)
        base = int(info["start"], 16) - linked if linked is not None else 0

        functions = list(mcp.rows("bn_function_list"))
        names = {}
        prototypes = []
        with open(os.path.join(out, "functions.c"), "w") as text:
            for row in functions:
                address = int(row["function"], 16)
                names.setdefault(row["name"], address)
                declared = declaration(row["definition"], row["name"])
                if declared and re.fullmatch(r"[A-Za-z_]\w*", row["name"]):
                    prototypes.append(f"{declared};")
                text.write(f"//@bench {address - base:x}\n")
                body, offset = [], 0
                while offset is not None:
                    page = mcp.call("bn_function_decompile", function=row["function"], offset=offset, limit=PAGE)
                    if not isinstance(page, str):
                        body = None
                        text.write(f"//@failed {page.get('errorMessage', page)}\n")
                        break
                    block = re.search(
                        r"^`{3,}bn-pseudoc\n(.*?)\n`{3,}$", page, flags=re.DOTALL | re.MULTILINE
                    )
                    # The server puts a tagged line's tag icons before it
                    # (a globe, a question mark, a warning sign): no part
                    # of the Pseudo C.
                    lines = block.group(1) if block else ""
                    body.append(re.sub(r"^[^\x00-\x7f]+", "", lines, flags=re.MULTILINE))
                    found = re.search(r"^nextOffset: (\d+)$", page, flags=re.MULTILINE)
                    offset = int(found.group(1)) if found else None
                if body is not None:
                    text.write("\n".join(body) + "\n")
        seconds = time.time() - started
        defined = set(names)
        for row in mcp.rows("bn_symbol_list"):
            names.setdefault(row["name"], int(row["symbol"], 16))
        # Binary Ninja's own names for integer types C names otherwise,
        # then the view's types, its data variables (but where a function
        # has the name) and its functions.
        header = [
            "#include <stdbool.h>",
            "#include <stddef.h>",
            "#include <stdint.h>",
            "typedef __int128 int128_t;",
            "typedef unsigned __int128 uint128_t;",
            "typedef uint16_t wchar16;",
            "typedef uint32_t wchar32;",
        ]
        header.extend(types_header(mcp))
        by_address = {address: name for name, address in names.items()}
        for row in mcp.rows("bn_data_variable_list"):
            address = int(row["datavar"], 16)
            name = by_address.get(address, f"data_{address:x}")
            names.setdefault(name, address)
            declared = declaration(row["definition"], name)
            if declared and name not in defined and re.fullmatch(r"[A-Za-z_]\w*", name):
                header.append(f"extern {declared};")
        header.extend(prototypes)
    finally:
        mcp.call("bn_open_item_close", openItem=item, save="discard")
    return header, names, base, seconds


if __name__ == "__main__":
    main()
