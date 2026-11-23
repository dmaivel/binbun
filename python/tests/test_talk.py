"""Threads and suggestions from Python: a script connected through
``binbun.connect()`` asks the person, a script of theirs connected to the
served database is told they are mentioned, asks ``f.why``, answers with a
suggestion resting on that evidence and supersedes it; the person accepts
part of it, and the history names both; an agent of its own identity
mentions the person and is answered; threads are opened about functions,
lines, variables, strings, addresses and types, answered, edited,
resolved and deleted in process and read the same over the socket; a
suggestion's block records its writes instead of making them, in process
and over the socket."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest

import binbun
from conftest import FIXTURE


@pytest.fixture()
def window(tmp_path: Path) -> Iterator[tuple[binbun.Database, binbun.Server]]:
    """The fixture with a project of its own, served as a window is
    (``serve(ui=True)``, as the console's tests do)."""
    with binbun.open(FIXTURE, project=tmp_path / "project", debug="none") as db:
        db.wait(binbun.Stage.CALLERS)
        with db.serve(ui=True) as server:
            yield db, server


HELPER = """
import sys, binbun
db = binbun.connect(socket=sys.argv[1], mode="local", author="script:helper")
events = db.events.subscribe(binbun.Mentioned)
print("ready", flush=True)
mention = None
while mention is None:
    event = events.get(timeout=60)
    assert event is not None, "never mentioned"
    if event.mention == binbun.Mention(key=db.identity):
        mention = event
thread = db.threads.get(mention.thread)
f = db.functions[thread.anchor.address]
why = next(item for item in f.why().items if item.var is not None)
with db.suggestion(
    "Name classify",
    rationale="Its result is a sign: " + why.type,
    evidence=[why, "It returns -1, 0 or 1."],
    thread=thread,
) as first:
    db.functions.set_name(f, "classify_sign")
    db.comments.set_at(f, "the sign")
    assert f.name == "classify", "a suggestion's write was made"
with db.suggestion(supersedes=first.suggestion, rationale="A shorter name.") as second:
    db.functions.set_name(f, "sign_of")
    db.comments.set_at(f, "-1, 0 or 1")
asker = db.session.members[mention.author.key]
thread.reply("sign_of, see the suggestion", reply_to=mention.post, mentions=[asker])
print(first.suggestion.id, second.suggestion.id, mention.author.key, mention.author.via, flush=True)
db.close()
"""


def test_a_script_told_of_a_mention_asks_why_suggests_and_supersedes_and_a_person_accepts_part(
    window: tuple[binbun.Database, binbun.Server], tmp_path: Path
) -> None:
    db, server = window
    classify = db.functions.get_by_name("classify")
    assert classify is not None
    script = tmp_path / "helper.py"
    script.write_text(textwrap.dedent(HELPER))
    helper = subprocess.Popen(
        [sys.executable, str(script), server.socket],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert helper.stdout is not None
        assert helper.stdout.readline().strip() == "ready", helper.stderr.read() if helper.stderr else ""
        # Another script asks the person, over the socket.
        with binbun.connect(socket=server.socket, author="script:asker") as asker:
            thread = asker.threads.create(
                asker.functions[classify.entry],
                "what does this return?",
                quote="int classify(int)",
                mentions=[asker.session.members[db.identity]],
            )
            out, err = helper.communicate(timeout=120)
    finally:
        if helper.poll() is None:
            helper.kill()
    assert helper.returncode == 0, err
    first_id, second_id, by_key, by_via = out.split()
    # The helper was told who asked: the other script.
    assert (by_key, by_via) == (db.identity, "script:asker")
    assert thread.anchor.kind == "function" and thread.anchor.address == classify.entry
    assert thread.opened_by == binbun.Author(db.identity, "script:asker")
    assert thread.posts[0].mentions == (binbun.Mention(key=db.identity),)
    # The helper's answer: a reply and its two versions in the thread.
    thread = db.threads.get(thread.id)
    assert thread is not None
    assert [p.body for p in thread.posts][1] == "sign_of, see the suggestion"
    assert thread.posts[1].author == binbun.Author(db.identity, "script:helper")
    assert thread.posts[1].reply_to == thread.posts[0].id
    assert thread.posts[1].mentions == (binbun.Mention(key=db.identity),)
    assert thread.suggestions == (first_id, second_id)
    first, second = db.suggestions.get(first_id), db.suggestions.get(second_id)
    assert first is not None and second is not None
    assert first.state == "superseded" and first.superseded_by == second_id
    assert [s.id for s in db.suggestions.pending()] == [second_id]
    assert second.supersedes == first_id and second.author == binbun.Author(db.identity, "script:helper")
    # The new version keeps the label, evidence and thread it did not give.
    assert (second.label, second.rationale, second.thread) == ("Name classify", "A shorter name.", thread.id)
    assert [(e.kind, e.value) for e in second.edits] == [
        ("function_name", "sign_of"),
        ("comment", "-1, 0 or 1"),
    ]
    # Its evidence, quoted by the server, rests on f.why; asked again now,
    # it still holds.
    why, words = second.evidence
    assert why.kind == "why" and why.quote is not None and "classify" not in why.quote
    assert words.quote == "It returns -1, 0 or 1."
    assert [r.stale for r in second.recheck()] == [False, False]
    # Nothing is written until the person accepts: the name, not the
    # comment. One undo step, the person's, naming the script.
    assert classify.name == "classify"
    done = second.accept([0])
    assert isinstance(done, binbun.HistoryEntry)
    assert done.author == binbun.Author(db.identity, "accept")
    assert done.suggested_by == binbun.Author(db.identity, "script:helper")
    assert classify.name == "sign_of"
    assert db.comments.get_at(classify.entry) is None
    latest = db.history[0]
    assert latest.id == done.id and latest.author == done.author and latest.suggested_by == done.suggested_by
    made = next(entry for entry in db.history if entry.label == "Supersede suggestion")
    assert made.author == binbun.Author(db.identity, "script:helper") and made.suggested_by is None
    accepted = second.refresh()
    assert accepted.state == "accepted" and accepted.accepted == (0,)
    assert accepted.decided_by == binbun.Author(db.identity, "accept")
    with pytest.raises(binbun.ConversationError):
        accepted.accept()
    # Undone, the suggestion waits again.
    db.undo()
    assert classify.name == "classify"
    assert second.refresh().state == "pending"


def test_threads_are_written_in_process_told_and_read_the_same_over_the_socket(
    window: tuple[binbun.Database, binbun.Server],
) -> None:
    """Threads in process: opened on a C line, answered, edited, resolved,
    a post deleted; told as ``ThreadChanged`` (and ``Mentioned`` when a
    script's post mentions this identity); read the same through
    ``connect()``."""
    db, server = window
    loop_sum = db.functions.get_by_name("loop_sum")
    assert loop_sum is not None
    document = db.decompile(loop_sum)
    line = next(l for l in document.lines if l.addresses)
    address = line.addresses[0]
    events = db.events.subscribe(binbun.ThreadChanged, binbun.Mentioned)
    thread = db.threads.create(line, "Why a loop?", quote=line.text)
    assert thread.anchor.kind == "line" and thread.anchor.address == address
    told = events.get(timeout=10)
    assert isinstance(told, binbun.ThreadChanged) and told.threads == [thread.id]
    # A script's post mentioning this identity is told as Mentioned.
    with binbun.connect(socket=server.socket, author="script:asker") as asker:
        asked = asker.threads.post(thread.id, "A loop?", mentions=[asker.session.members[db.identity]])
    assert asked.author == binbun.Author(db.identity, "script:asker")
    told = events.get(timeout=10)
    assert isinstance(told, binbun.ThreadChanged) and told.threads == [thread.id]
    mentioned = events.get(timeout=10)
    assert isinstance(mentioned, binbun.Mentioned)
    assert (mentioned.thread, mentioned.post, mentioned.body) == (thread.id, asked.id, "A loop?")
    assert mentioned.author == asked.author
    assert mentioned.mention == binbun.Mention(key=db.identity)
    answer = thread.reply("It sums.", reply_to=asked)
    assert answer.id != asked.id and answer.reply_to == asked.id
    edited = answer.edit("It sums the array.")
    assert edited.body == "It sums the array." and edited.edited is not None
    gone = thread.posts[0].delete()
    assert gone.deleted and gone.body == "" and not gone.removed_by_owner
    assert gone.deleted_by == thread.posts[0].author
    with pytest.raises(binbun.ConversationError):
        gone.edit("again")
    resolved = thread.resolve()
    assert resolved.resolved
    assert [t.id for t in db.threads.at(address)] == [thread.id]
    assert [t.id for t in db.threads.in_function(loop_sum)] == [thread.id]
    assert [t.id for t in db.threads.in_function(loop_sum.entry)] == [thread.id]
    assert db.threads.at(address + 0x10_0000) == []
    # Conversation is no undo step.
    assert db.undo() is None
    # The same over the socket.
    with binbun.connect(socket=server.socket) as remote:
        assert remote.identity == db.identity
        there = remote.threads.get(thread.id)
        assert there is not None
        assert [(p.body, p.deleted) for p in there.posts] == [
            ("", True),
            ("A loop?", False),
            ("It sums the array.", False),
        ]
        assert there.posts[0].deleted_by == gone.deleted_by
        assert there.resolved and there.anchor == resolved.anchor
        assert there.anchor.address == address
        assert [t.id for t in remote.threads.in_function(remote.functions[loop_sum.entry])] == [thread.id]
        chain, seq, n = thread.id.split(":")
        assert remote.threads.get(f"{chain}:{int(seq) + 100}:{n}") is None
        with pytest.raises(binbun.ProtocolError):
            remote.threads.get("00:1:0")


def test_an_agents_mention_is_told_in_process_and_to_a_local_client_and_answered(
    window: tuple[binbun.Database, binbun.Server],
) -> None:
    """An agent connected with an identity of its own (``agent=``) posts,
    mentioning the person: told as ``Mentioned`` (by the agent) in the
    served process and to a client following it (``mode="local"``, whose
    copy tells the server's mentions); the person's reply is a post of its
    own beside the agent's."""
    db, server = window
    loop_sum = db.functions.get_by_name("loop_sum")
    assert loop_sum is not None
    thread = db.threads.create(loop_sum, "Why a loop?")
    here = db.events.subscribe(binbun.Mentioned)
    local = binbun.connect(socket=server.socket, mode="local", author="script:follower")
    try:
        assert isinstance(local, binbun.Database)
        there = local.events.subscribe(binbun.Mentioned)
        with binbun.connect(socket=server.socket, agent="Codex") as codex:
            agent = codex._connection.agent
            assert agent is not None and agent != db.identity
            assert codex.session.members["Codex"].key == agent
            asked = codex.threads.post(thread.id, "A loop?", mentions=[codex.session.members[db.identity]])
        assert asked.author == binbun.Author(agent, "agent")
        mentioned = here.get(timeout=10)
        assert isinstance(mentioned, binbun.Mentioned)
        assert (mentioned.post, mentioned.author) == (asked.id, asked.author)
        assert mentioned.mention == binbun.Mention(key=db.identity)
        # The person answers the agent, mentioning it.
        answer = thread.reply("It sums.", reply_to=asked, mentions=[db.session.members[agent]])
        assert answer.id != asked.id and answer.reply_to == asked.id
        assert [p.body for p in db.threads.get(thread.id).posts] == ["Why a loop?", "A loop?", "It sums."]  # type: ignore[union-attr]
        followed = there.get(timeout=30)
        assert isinstance(followed, binbun.Mentioned), "the local client was not told the agent's mention"
        assert (followed.post, followed.author) == (asked.id, asked.author)
    finally:
        local.close()


def test_a_thread_is_about_a_function_a_line_a_variable_a_string_an_address_or_a_type(
    window: tuple[binbun.Database, binbun.Server],
) -> None:
    """``threads.create(about)``: the anchor each object makes; an address
    is the instruction a recovered block holds there, else the data item;
    what no instruction made, and what is no object at an address, is
    refused."""
    db, server = window
    classify = db.functions.get_by_name("classify")
    assert classify is not None
    document = db.decompile(classify)
    line = next(l for l in document.lines if l.addresses)
    variable = document.variables[0]
    string = db.strings.get_all()[0]
    key = db.types.define("struct pair { int a; int b; };")

    def kind(about: object) -> tuple[str, int | None]:
        anchor = db.threads.create(about, "About this.").anchor
        return anchor.kind, anchor.address

    assert kind(classify) == ("function", classify.entry)
    assert kind(line) == ("line", line.addresses[0])
    assert kind(line.addresses[0]) == ("instruction", line.addresses[0])
    assert kind(variable) == ("variable", classify.entry)
    assert kind(string) == ("data", string.address)
    assert kind(string.address) == ("data", string.address)
    assert kind(binbun.Anchor.type(key)) == ("type", None)
    assert sorted(t.anchor.kind for t in db.threads.in_function(classify)) == [
        "function",
        "instruction",
        "line",
        "variable",
    ]
    # A line no instruction made has nothing to anchor to.
    bare = next(l for l in document.lines if not l.addresses)
    with pytest.raises(ValueError, match="no instruction"):
        db.threads.create(bare, "No.")
    for wrong in ("classify", 1.5, None):
        with pytest.raises(TypeError, match="a thread is about"):
            db.threads.create(wrong, "No.")  # type: ignore[arg-type]
    # Mentions are members, never agent names or Mentions read back.
    for wrong_mentions in (["script:x"], [binbun.Mention("script:x")], "script:x"):
        with pytest.raises(TypeError, match="mention"):
            db.threads.create(classify, "No.", mentions=wrong_mentions)  # type: ignore[arg-type]
    # Over the socket: a function, an address; a C line as text has no
    # instructions to anchor to.
    with binbun.connect(socket=server.socket) as remote:
        there = remote.functions[classify.entry]
        assert remote.threads.create(there, "Remote.").anchor.kind == "function"
        assert remote.threads.create(string.address, "Remote.").anchor.kind == "data"
        with pytest.raises(TypeError, match="RemoteCLine"):
            remote.threads.create(remote.decompile(there).lines[1], "No.")
        with pytest.raises(TypeError, match="mention"):
            remote.threads.create(there, "No.", mentions=["script:x"])  # type: ignore[list-item]


def test_a_suggestion_block_records_its_writes_and_accepting_it_makes_them(
    window: tuple[binbun.Database, binbun.Server],
) -> None:
    """In process: the writes made in ``with db.suggestion(...)`` are
    recorded, not made, each checked as it is made; an exception leaving
    the block makes no suggestion; a transaction inside it is refused; a
    new version keeps what it does not give; accepting makes the writes,
    naming who suggested them."""
    db, _ = window
    classify = db.functions.get_by_name("classify")
    loop_sum = db.functions.get_by_name("loop_sum")
    assert classify is not None and loop_sum is not None
    thread = db.threads.create(classify, "A name?")
    with db.suggestion(
        "Name classify", rationale="Its result is a sign.", evidence=["It returns -1, 0 or 1."], thread=thread
    ) as s:
        assert isinstance(s, binbun.SuggestionDraft) and s.suggestion is None
        db.functions.set_name(classify, "sign_of")
        db.comments.set_at(classify, "the sign")
        assert classify.name == "classify" and db.comments.get_at(classify) is None
    assert classify.name == "classify" and db.comments.get_at(classify) is None
    made = s.suggestion
    assert made is not None and made.state == "pending" and made.thread == thread.id
    assert (made.label, made.rationale) == ("Name classify", "Its result is a sign.")
    assert [(e.kind, e.address, e.value) for e in made.edits] == [
        ("function_name", classify.entry, "sign_of"),
        ("comment", classify.entry, "the sign"),
    ]
    assert made.author.key == db.identity
    assert db.threads.get(thread.id).suggestions == (made.id,)  # type: ignore[union-attr]
    assert db.threads.create(made, "Why a sign?").anchor.kind == "suggestion"
    # An exception leaving the block makes none and writes nothing.
    count = len(db.suggestions)
    with pytest.raises(RuntimeError, match="changed my mind"):
        with db.suggestion("Never made") as dropped:
            db.functions.set_name(loop_sum, "never")
            raise RuntimeError("changed my mind")
    assert dropped.suggestion is None and len(db.suggestions) == count and loop_sum.name == "loop_sum"
    # A refused write raises at its line and is not recorded.
    with db.suggestion("Name loop_sum", rationale="It sums.") as named:
        db.functions.set_name(loop_sum, "summed")
        with pytest.raises(binbun.CDeclarationError):
            db.functions.set_prototype(loop_sum, "int loop_sum(")
    assert named.suggestion is not None
    assert [(e.kind, e.value) for e in named.suggestion.edits] == [("function_name", "summed")]
    # A transaction, an undo or another suggestion inside the block is refused.
    for inner in (lambda: db.transaction("Inside").__enter__(), db.undo, lambda: db.suggestion("Inner").__enter__()):
        with pytest.raises(binbun.TransactionError):
            with db.suggestion("Nested"):
                inner()
    with pytest.raises(ValueError, match="no write"):
        with db.suggestion("Empty"):
            pass
    assert len(db.suggestions) == count + 1
    # A new version keeps the label, rationale, evidence and thread.
    with db.suggestion(supersedes=made) as again:
        db.functions.set_name(classify, "sign")
    second = again.suggestion
    assert second is not None and second.supersedes == made.id
    assert (second.label, second.rationale, second.thread) == (made.label, made.rationale, made.thread)
    assert [e.quote for e in second.evidence] == [e.quote for e in made.evidence]
    old = made.refresh()
    assert old.state == "superseded" and old.superseded_by == second.id
    # Accepted: written, one undo step naming who suggested it.
    entry = second.accept()
    assert isinstance(entry, binbun.HistoryEntry)
    assert isinstance(entry.suggested_by, binbun.Author) and entry.suggested_by == second.author
    assert entry.author == binbun.Author(db.identity, "accept")
    assert classify.name == "sign" and db.history[0].id == entry.id
    # Dismissed, with a reason.
    dismissed = named.suggestion.dismiss("Not yet.")
    assert dismissed.state == "dismissed" and dismissed.reason == "Not yet."
    assert loop_sum.name == "loop_sum"


def test_a_suggestion_over_the_socket_records_its_writes_and_threads_are_told(
    window: tuple[binbun.Database, binbun.Server],
) -> None:
    """Over the socket: ``ThreadChanged`` comes as the event class it is in
    process; a suggestion's block records its writes (the server checks
    them at its end); a transaction or a definition inside it is refused;
    accepting makes the writes in the server."""
    db, server = window
    loop_sum = db.functions.get_by_name("loop_sum")
    assert loop_sum is not None
    with binbun.connect(socket=server.socket, author="script:remote") as remote:
        queue = remote.events.subscribe(binbun.ThreadChanged)
        thread = db.threads.create(loop_sum, "A name?")
        told = queue.get(timeout=30)
        assert isinstance(told, binbun.ThreadChanged) and told.threads == [thread.id]
        with pytest.raises(binbun.CapabilityError):
            remote.events.subscribe(binbun.Progress)
        there = remote.functions[loop_sum.entry]
        with remote.suggestion("Name loop_sum", rationale="It sums.", thread=thread) as s:
            remote.functions.set_name(there, "summed")
            remote.comments.set_at(there, "sums")
        assert loop_sum.name == "loop_sum" and there.name == "loop_sum"
        assert remote.comments.get_at(there) is None
        made = s.suggestion
        assert made is not None and made.thread == thread.id
        assert made.author == binbun.Author(db.identity, "script:remote")
        assert [(e.kind, e.value) for e in made.edits] == [("function_name", "summed"), ("comment", "sums")]
        # An exception leaving the block makes none; a transaction or a
        # definition inside it is refused.
        count = len(remote.suggestions)
        with pytest.raises(RuntimeError):
            with remote.suggestion("Never made"):
                remote.functions.set_name(there, "never")
                raise RuntimeError("changed my mind")
        with pytest.raises(binbun.TransactionError):
            with remote.suggestion("Nested"):
                with remote.transaction("Inside"):
                    pass
        with pytest.raises(binbun.CapabilityError):
            with remote.suggestion("Define"):
                remote.types.define("struct pair { int a; int b; };")
        assert len(remote.suggestions) == count and loop_sum.name == "loop_sum"
        # A new version, then accepted over the socket.
        with remote.suggestion(supersedes=made) as again:
            remote.functions.set_name(there, "sum_of")
        second = again.suggestion
        assert second is not None and (second.label, second.rationale) == ("Name loop_sum", "It sums.")
        assert made.refresh().state == "superseded"
        entry = second.accept()
        assert entry is not None and entry.suggested_by == binbun.Author(db.identity, "script:remote")
        assert there.name == "sum_of" and loop_sum.name == "sum_of"


def test_query_results_are_the_evidence_and_members_are_mentioned_in_process_and_over_the_socket(
    window: tuple[binbun.Database, binbun.Server],
) -> None:
    """Evidence is the query results as they were got, each recorded as
    what it points at and quoted when the post is made; mentions are
    members, looked up by name or key; the same over the socket."""
    db, server = window
    classify = db.functions.get_by_name("classify")
    assert classify is not None
    document = db.decompile(classify)
    to = db.xrefs.to_ea(classify)
    assert isinstance(to, binbun.XrefsTo) and to.to_ea == classify.entry and to == classify.xrefs_to()
    call = next(x for x in to if x.is_call)
    why = next(item for item in classify.why().items if item.var is not None)
    string = db.strings.get_all()[0]
    me = db.session.members[db.identity]
    assert me.you and db.session.members[me.name] == me and db.session.members[0] == me
    with pytest.raises(KeyError):
        db.session.members["nobody at all"]
    thread = db.threads.create(classify, "What does it rest on?")
    post = thread.reply(
        "On these.",
        evidence=[document.lines[1], document.lines[1:3], to, call, classify.verify(), why, string, "My words."],
        mentions=[me],
    )
    assert [e.kind for e in post.evidence] == [
        "lines",
        "lines",
        "xrefs_to",
        "call",
        "verification",
        "why",
        "string",
        "text",
    ]
    assert post.evidence[1].data["lines"] == [1, 2]
    assert post.evidence[2].data["to"] == f"{classify.entry:#x}"
    assert post.evidence[3].data["site"] == f"{call.from_ea:#x}"
    assert all(e.quote is not None for e in post.evidence)
    assert document.lines[1].text in (post.evidence[0].quote or "")
    assert post.evidence[7].quote == "My words."
    assert post.mentions == (binbun.Mention(key=db.identity),)
    # What is not a query result is refused, naming what is.
    for wrong in ([42], [[document.lines[0], call]], "My words.", to):
        with pytest.raises(TypeError, match="evidence"):
            thread.reply("No.", evidence=wrong)  # type: ignore[arg-type]
    for wrong_mentions in ([42], ["script:x"], [binbun.Mention("script:x")], me):
        with pytest.raises(TypeError, match="mention"):
            thread.reply("No.", mentions=wrong_mentions)  # type: ignore[arg-type]
    # A name several members have is refused, naming their keys.
    twins = binbun.Members(
        binbun.Member(key, "ann", "person", None, True) for key in ("aa" * 32, "bb" * 32)
    )
    with pytest.raises(binbun.AmbiguousError, match="aa+, bb+"):
        twins["ann"]
    assert twins["bb" * 32].key == "bb" * 32 and len(twins) == 2
    # Over the socket: the C as text has the same lines, cited the same.
    with binbun.connect(socket=server.socket) as remote:
        there = remote.decompile(remote.functions[classify.entry], timeout=60)
        assert there.function == remote.functions[classify.entry]
        assert [line.text for line in there.lines] == [line.text for line in document.lines]
        posted = remote.threads.post(
            thread.id,
            "Over the socket.",
            evidence=[there.lines[1:3], "Mine."],
            mentions=[remote.session.members[db.identity]],
        )
    assert [e.data for e in posted.evidence] == [post.evidence[1].data, {"kind": "text", "text": "Mine."}]
    assert posted.evidence[0].quote == post.evidence[1].quote
    assert posted.mentions == post.mentions
