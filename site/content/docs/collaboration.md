+++
title = "Collaboration"
weight = 80
+++

A shared project synchronises edits, cursors, chat and address threads. Members analyse the same bytes locally. Edits travel over the links between members, direct or through a relay that forwards the encrypted traffic; a member linked to no one exchanges nothing until they link again.

Chat is kept in memory only, the last 100 messages, and binbun never saves it; what the others see, they can still copy. It stays readable after a session stops, and the next session starts with an empty chat. Address threads are part of the project and are saved with it.

## Share and join

1. Open the binary and choose **File → Share…**. Under **Members**, paste the identity card of each person joining and choose **Editor** or **Viewer**; they are members before anyone connects. Start sharing and copy the ticket to them.
2. They choose **File → Join…**, paste it and select the same binary. The start page also offers **Join…**.
3. Anyone else holding the ticket asks to join. Each request gets a card showing who asks and their key's fingerprint, and requests that arrive together are shown together. Check each person's identity and choose their role, or deny them. A display name alone is not an identity check. A request left unanswered for five minutes is refused; the person can ask again. **Admit people admitted before without asking** lets those you admitted before back in with no card.
4. Enable sending the binary or debug file only if you want to distribute it. These options are off by default. If a joiner lacks a binary you offer, the Join dialog can fetch it.

A ticket contains connection and project information, not the project's decryption key. A ticket holder the owner has not added gets in only through the host's approval, and only while that share is active. Treat it as information about the session, not as a secret that grants unrestricted access.

**File → Copy My Identity Card** copies the public identity card. The owner's **Members** controls can add a person from their card. The CLI prints the key, fingerprint and card too:

```sh
binbun id
```

A person added from their card is a member before they connect: when they join, the link is let in with no request to answer. Check the card's fingerprint with them by another channel first; the card is what is added, not a name. On the command line too:

```sh
binbun share tests/fixtures/program-x86_64.elf --add CARD --role viewer
```

Anyone else holding the ticket is asked about on standard input: `binbun share` prints who asks, with their fingerprint, and a request id to answer by (`e ID` admits as an editor, `v ID` as a viewer, `n ID` refuses). With `--yes` it admits every ticket holder without asking. `add CARD` typed while sharing adds a person too.

The identity's private key stays in binbun's data directory, readable by anyone who can read your files. Keep it when moving your installation; do not put it in a public dotfiles repository.

## Where a joined project lives

Joining a share puts it in a project of its own for that share, beside any project of yours for the same binary, which joining neither reads nor changes. The owner's share is their project itself; when sharing, the owner chooses which of its earlier history goes with the share (**History** in the Share dialog, `--history` on the command line). The app titles a joined share's project with its owner, "bash, shared by Ann", in the window and in Recent, which reopens each file in the project it was opened in. When a binary has several projects, opening it in the app offers them, the most recently changed first; with one, it opens it. `binbun share` and `binbun edit` open the most recently changed and say which; `--share ID` (the start of the share's name, after the `@` in its project's directory name) chooses a share's project, and `--private` your own.

While a join is under way, before the share's membership and key have arrived, the window takes no edits and says so. After that, an edit made while no member is linked and synced is kept as not yet shared, shown to you and told to no one; it is judged when a link next syncs. With a link synced, an edit your role may not make is refused at once and never shown. An edit refused when judged leaves your project and is listed as not in this project, with its values; so are edits made after a removal you had not yet heard of, once your copy of the membership takes the removal. In the app, the status bar counts both, and the session panel's **Your edits** lists them: an edit not in this project can be copied out, or brought in again as a new change of yours where your role allows.

Your earlier analysis of the binary stays out of the share unless you bring it. In the app, open the share's project and choose **File → Bring From Your Own Project…**: it lists the values of your own project with who wrote them, yours chosen at first, and brings those chosen as one new change of yours. On the command line, `binbun bring FILE --list` lists the values of your private project with who wrote them; `binbun bring FILE --all` (or numbers from the list) writes those of yours (`--others` adds other authors' and agents') into the share's project as one new change of yours, signed now and labelled as brought, carrying nothing of the private project's history. The share takes it the next time you join, judged by your role there as any edit is.

## Roles and shared work

| Role | Permission |
| --- | --- |
| Owner | Edit and manage membership. |
| Editor | Edit the analysis. |
| Viewer | Read and participate in threads; no analysis edits. |
| Agent | Edit as an editor does, shown as an [agent](@/docs/agents.md). |

A peer that joins you on another engine build is view-only to you even if it would otherwise be an editor: while it is linked to you, you take none of its edits made on that build, by whichever route they reach you; once it is no longer linked to you, you do. Only the sharing side applies this, to those who joined it; a peer that joined does not apply it to its host, and an edit from a peer on another build linked only to someone else is taken. This keeps builds that may read the binary differently from mixing their edits live; it is a compatibility rule, not a protection against a member running a modified binbun. Use matching builds when working together.

Click a person's avatar to follow their cursor. Your own navigation stops following. **Window → Session**, **Threads**, **Conflicts** and **History** expose the shared work and its authors. Concurrent changes to the same item can remain a conflict rather than silently deleting one author's contribution. Removal or reduced permissions cannot erase plaintext a member already received.

Any member can share the project too. Their share lets in the members their copy of the membership names without asking anyone; only the owner admits a person who is not yet a member. A member the owner added from their identity card can therefore join, while the owner is away, with the ticket of any member who is sharing the project and has received that addition.

## Whom you trust

Admitting someone gives them the project: everything in it, and everything added while they are a member. Encryption keeps the project from relay operators, not from members. Removing a member stops new edits reaching them from the peers that have taken the removal; a peer that has not yet heard of it, being offline, cannot enforce it until it does. Removal cannot take back what they already received. A removed member who connects again is sent the membership records up to and including their own removal, and nothing later.

Within that, each member is held to their role. Every edit, chat message, cursor and introduction is signed by its author and checked by every peer, so a member cannot write in someone else's name, edit while a viewer, or change another person's bookmarks. Two different edits signed by one author for the same place in their history are a fork: a peer that holds both, and that author's start, freezes that author's chain from there, keeping neither version, and passes the two signed heads on as evidence. Linked peers tell each other how far each person's history goes and the hash there, and ask for what they lack, so a fork is found once peers holding its two sides link and the evidence reaches them. The earlier history the owner lists when sharing is fixed by the share's first record and cannot fork. Membership records and project data are sent only to a key the connection itself proves and the membership names; a ticket, card or name proves no one.

Admit people you trust with the project and with your machine's time on it. Every message is limited in size before it is decoded (a request to join to 16 KiB, sync messages to 2 MiB, one change to 1 MiB); each link, project and process has ceilings on the memory, streams and work it can take, and people who are not members yet get only a bounded share until they are let in. The work a fork or a removal causes grows with the history it affects and is done in bounded steps. These bounds are not a proof that no input can crash binbun. A member can still make a great deal of valid history, ask for it again and again, or keep your peer busy within its limits. That is not defended against; the remedy is to remove them, after which they are a stranger to the project.

Joining checks that the project is about the same binary as the one you have open before any of its edit history is exchanged (the membership records come first) or a project is adopted for it; a mismatch ends the join.

## Known limits

- A project bundle without a log cannot be merged into a share; bring its values instead.
- A removed member cannot import changes from a file into the share's project.
- "Most recently changed" is judged from the project's files, so it can differ from the one you opened last.
- A Bring is not yet shared until you next join; it is then judged by your role, as any edit is.
- Bringing from your own project is refused while that project is open in another binbun; close it there first.
- A link whose single write takes longer than 30 seconds is closed; on a very slow connection, link again to go on.
- Within one share, a member who stops reading can delay what others are sent by up to 30 seconds before their link is closed.
- A very long history the owner lists when sharing can be refused to a new member while other long histories are being checked, and is checked when it is next offered.

## LAN-only and relay choices

A local share can be started without using a relay:

```sh
binbun share tests/fixtures/program-x86_64.elf --lan-only
```

The command stays open and prints a ticket; add the people joining with `--add CARD`, or answer their requests as they come. Use the `join` command with that ticket and the binary path on the other machine. The host and joiner accept `quit` on standard input to leave; quitting waits up to five seconds for the members linked to say they have taken your shared changes, then reports who did, who was still linked without saying so, and whose link went first. That is what they said, not proof the changes are on their disk; edits not yet shared are not counted. Do not use `--yes` on an untrusted network: it admits every ticket holder automatically, as editors unless a different role is supplied.

LAN-only disables relays and router port mapping and enables mDNS. A joiner using that ticket inherits those choices unless explicitly overridden. This is a transport configuration, not a firewall: restrict interfaces with `--bind` and use network policy when direct reachability must be limited.

The default relay is binbun's, at `us-east.relay.binbun.org`. Peers prefer a direct path when available and use the relay when they have none.

- On the command line, `--relay` accepts `binbun`, `n0` for n0's public relays, `none`, or another relay's URL.
- In the app, **File → Settings… → Collaboration → Relay** chooses binbun, n0 or **Custom** with a URL. The Share and Join dialogs' **Reach** row then offers that relay, **No relay** or **LAN only**.

mDNS is otherwise opt-in with `--mdns`; router port mapping is otherwise on and can be disabled with `--no-portmap`.

## What a relay receives

A relay receives endpoint public keys, network addresses and ports, which endpoints exchange data, timing and traffic volume. It does not receive the binary, comments or project plaintext. The connection is encrypted end to end, and project data has its own encryption beneath it. Encryption does not hide traffic metadata or protect against an authorised member copying data.

binbun's relay runs the configuration in `scripts/relay`. It logs errors only to a separate in-memory journal, bounded to 2 days or 16 MB. Metrics are aggregate counters on loopback. Certificates and the certificate authority account key remain on disk. n0 and other relay operators can choose different logging; inspect their policy.

## Host your own relay

The [relay scripts](https://github.com/dmaivel/binbun/tree/main/scripts/relay) provision an Ubuntu 24.04 host over SSH. They install the pinned iroh-relay release with checked SHA-256s, a restricted system user, a hardened systemd service and firewall rules. They are provisioning scripts that use root on the destination, not a desktop setting.

1. Obtain a reachable Linux host and a DNS name you control. The scripts have pinned binaries for x86-64 and AArch64.
2. In `scripts/relay/config.toml`, replace the supplied hostnames with yours. Set the Let's Encrypt contact or provide it through `RELAY_EMAIL` when installing. Point the DNS records at the host before starting the service.
3. Allow TCP 443 for the relay and certificate validation, TCP 80 for the captive-portal probe, and UDP 7842 for QUIC address discovery. Keep metrics port 9090 private. Allow SSH from your administration network.
4. Run `scripts/relay/install.sh` with the SSH destination as its single argument. An unqualified destination uses the `ubuntu` account; the destination needs non-interactive sudo. `RELAY_SSH` can supply the SSH command and options.
5. Run `scripts/relay/check.sh` with your hostname. Its `--ssh` option selects the administration destination; `--ip` reaches a new address before DNS caches have caught up. It checks the service, certificate, relay protocol and ports.
6. Set the clients' relay URL to your HTTPS hostname with the `--relay` option, or with **Custom** in the app's **Relay** setting. Keep the relay release compatible with binbun's iroh version; the installer checks its pin against `Cargo.lock`.

The supplied limits allow 2 MiB/s per endpoint with an 8 MiB burst. They are not a connection-rate limit. Keep infrastructure flow logging and host-level monitoring consistent with the privacy policy you give your users.
