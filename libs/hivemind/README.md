# HiveMind

Bot-to-bot communication protocol over Wizard101's in-game directed chat. Two independent WizWalker bots can coordinate using whispers as the transport layer.

## Requirements

- Windows 10/11
- Python 3.11+
- Two or more Wizard101 clients running, logged into the same area

> Directed chat is delivered by GID to any player who is online and loaded,
> so no buddy/friend relationship between the accounts is required.

## Installation

```bash
# Clone repos
git clone https://github.com/Deimos-Wizard101/wizwalker.git
git clone https://github.com/Deimos-Wizard101/hivemind.git

# Checkout the chat hooks PR #25 (or use development after it merges)
cd wizwalker
git fetch origin pull/25/head:chat-and-buddy-hooks
git checkout chat-and-buddy-hooks

# Install wizwalker in dev mode
pip install -e .

# Install hivemind in dev mode
cd ../hivemind
pip install -e .
```

## Usage

Run the example on **both** clients (two separate terminals):

```bash
cd hivemind
python examples/ping_pong.py
```

Each bot prints its GID on startup. Use option `2` on one bot to send a PING to the other bot's GID. The receiving bot auto-replies with PONG.

```
=== HiveMind PING/PONG ===
  1      - Get your GID
  2      - Send PING to a GID
  Ctrl+C - Exit

> 2
  Target GID: 12345
  Sending PING to 12345...
  PING sent!
[HiveMind] Received PONG from 12345
[HiveMind] Got PONG from 12345, peer is alive
```

## Discovery

Bots find each other without knowing GIDs in advance. Activating HiveMind
makes a bot stand out unmistakably from a legit player through **two**
signals it must show together:

1. **Magic grid position.** It teleports to the nearest point whose two
   horizontal coordinates are *both* multiples of `MAGIC_FACTOR` (1024),
   including 0. Reaching such a point by chance is statistically negligible.
2. **Beacon yaw.** It writes a reserved yaw to its own body encoding its role:

```
MASTER_YAW   2.7182818   "I am the master"
SLAVE_YAW    3.1415926   "I am a slave"
CONFIRM_YAW  1.6180339   reserved (message confirmation / future use)
```

> **Axes.** WizWalker `XYZ` is **Z-up**: `.x`/`.y` are the horizontal ground
> plane (gridded), `.z` is height (left for the game to terrain-snap). The
> spec's "X and Z" are these two horizontal axes; the spec's vertical "Y" is
> WizWalker `.z`.

The server replicates both position and orientation to nearby clients, so
a scanning bot walks its own entity list, filters to `Player Object`
entities, and accepts a peer only when it is **on the magic grid AND
facing a role yaw** -- neither signal alone qualifies. From that entity it
reads `character_id` (the GID to whisper) and the grid cell (horizontal
position divided by `MAGIC_FACTOR`).

It then opens a DM handshake to authenticate the sighting:

```
HELLO     [role, qx, qy]   greet a spotted peer, claim own role + cell
HELLO_ACK [role, qx, qy]   reply; both sides now have a confirmed peer
```

A peer is `confirmed` once a valid HELLO/HELLO_ACK is exchanged, and
`bound` once the claimed grid cell matches the entity actually seen on the
grid (anti-spoof). Run `examples/discovery_demo.py master` and
`... slave` on two co-located clients to see it work.

The teleport onto the grid is collision-aware: pass a `grid_resolver`
(Deimos wires `teleport_math.find_walkable_magic_point`, which solves the
zone's collision geometry restricted to grid intersections) so the bot
never snaps into a wall. Without one it falls back to the plain nearest
multiple.

## Bot distribution & team-up

Once peers are confirmed, the master hands out work by **index**, not by
shipping bot text over chat:

```
BOT_OFFER  [bot_index]   master -> slave: run bot #N for the current zone
BOT_ACCEPT [bot_index]   slave -> master: user confirmed
BOT_REJECT [bot_index]   slave -> master: user declined / no handler
```

`bot_index` is the position in the current zone's compatible-bot list
(Deimos's `bot_registry` ordering). The slave resolves that index for its
own zone and **prompts the user in Deimos to confirm before executing** --
the library never runs anything on its own.

The slave side runs a small offer state machine:

- offers are only entertained while **seeking** (`start_seeking()` — the
  "looking for team up" trigger, which also clears the reject blocklist);
- accepting **locks** the client to that peer; every later offer is
  auto-rejected until `cancel_lock()` (GUI) or the client stops;
- a peer the user **rejects** is blocklisted for the current zone (cleared
  on zone change or the next `start_seeking()`);
- offers that arrive while a prompt is open **queue** and are shown in turn.

While the team assembles, `pin_to_grid(required_clients)` holds the bot in
place + beacon yaw via continual re-teleport until the bot's `@clients`
count is met (then it auto-releases); `unpin()` cancels the hold.

```python
protocol = HiveMindProtocol(
    client, role=Role.SLAVE,
    grid_resolver=lambda c: find_walkable_magic_point(c, MAGIC_FACTOR),
)

async def confirm(sender_gid, bot_index):
    return await prompt_user_in_deimos(sender_gid, bot_index)  # -> bool

protocol.on_bot_offer = confirm          # slave: decide accept/reject
protocol.on_bot_accepted = on_accepted   # master: a slave said yes
protocol.on_bot_rejected = on_rejected   # master: a slave said no

protocol.start_seeking()                 # slave: look for team-ups
# master side, after discovery:
await protocol.offer_bot(bot_index)      # to every confirmed peer
```

## Session lifecycle

Peers announce execution state to each other (broadcast to all confirmed peers):

```
SESSION_PAUSE    we are pausing execution
SESSION_RESUME   we are resuming execution
SESSION_END      we are ending execution (done coordinating)
SESSION_LEFT     we are leaving / disconnecting gracefully
```

```python
await protocol.announce_pause()    # / announce_resume() / announce_end() / announce_leave()
protocol.on_peer_pause  = on_pause   # async fn(sender_gid); also _resume / _end / _left
```

`END` and `LEFT` mean the sender is no longer participating, so the receiver
drops it from the peer table and **releases any lock to it** (`locked_to`). A
peer that vanishes *without* announcing is still caught by `check_peers()`
(keepalive) and reported via `on_peer_lost`.

## Steganographic wire format (ChatStegCipher)

The `HM ...` format is trivially fingerprintable. `ChatStegCipher` instead
renders each message as a short sentence built **only** from words in a
reference corpus (`data/chatlog_p1.txt`), drawn to match that corpus's
statistical distribution -- so the output is, by construction, a sample of the
same bigram model real player chat follows.

```python
from hivemind import HiveMindProtocol, ChatStegCipher, Role
protocol = HiveMindProtocol(client, role=Role.MASTER, encoder=ChatStegCipher())
# ChatStegCipher().encode(MessageType.HELLO, 0, 3, -4) -> "thank they bachelors acting 98767 we about"
```

How it works:

- A **bigram model** over the corpus vocabulary (+ end-of-sentence) is built
  deterministically with integer-only math, so both clients derive identical
  frequency tables. The vendored corpus is pre-filtered to the **intersection of
  the chat log and the game's approved-word whitelist** (`logs/ChatWhiteList.txt`),
  so every word the cipher can emit is guaranteed to pass the in-game chat filter
  uncensored. Vocabulary = ~1,650 whitelisted `[a-z0-9]` words.
- The message (type + args) is serialized, checksummed, and **whitened** with a
  shared-key keystream so its bits look uniform (this is also the key/cipher
  layer). Both clients must share the same key.
- A **no-renormalization rANS coder** (exact Python big-int arithmetic) turns
  the whitened bits into words by *decoding* them through the model, and the
  receiver recovers them by *encoding* the words back. EOS is suppressed while
  the state is large, so the whole payload is consumed and decoding terminates
  with a small residue the receiver finds by trialing a few hundred candidates
  against the checksum.

Measured against the whitelist-filtered corpus: unigram entropy ~**8.9**
bits/word, sentences average ~5-8 words (corpus median 3), always `<= 79` chars,
every emitted word is on the chat whitelist, and real corpus lines never
false-decode.
Both clients must run with the same vendored corpus; bundle `data/chatlog_p1.txt`
when packaging (e.g. add it to the PyInstaller spec).

> Not yet addressed: **timing**. The handshake/keepalive *cadence* is its own
> side channel that steg doesn't cover -- see the timing note below.

## Architecture

```
ChatEncoder        MessageType + int args <-> compact alphanumeric tokens
                   (PING -> "HM P0", HELLO -> "HM H0 <role> <qx> <qy>")
ChatStegCipher     MessageType + int args <-> corpus-distributed sentence
                   (drop-in encoder; both clients share corpus + key)
MessageDispatcher  Routes decoded (MessageType, args) to async handlers
HiveMindDiscovery  Teleports onto the magic grid + writes role beacon yaw;
                   scans entity list for on-grid, role-beaconing peers
HiveMindProtocol   Wraps WizWalker client: send/recv loop + discovery +
                   handshake + grid hold + bot-offer state machine,
                   maintains the confirmed/bound peer table
```

## Liveness

No timer. Call `await protocol.check_peers()` **between bot instructions**.
A peer still visible in the entity list is self-evidently online, so no chat
is sent. Only for a peer that has gone **out of range** (entity unreadable)
do we fall back to a `KEEPALIVE [seq]` whisper; the peer replies
`KEEPALIVE_ACK [seq]`. If a peer is still out of range and hasn't ACKed by
the next `check_peers()`, it is dropped and `on_peer_lost(gid)` fires. This
keeps chat traffic near zero while everyone is co-located.

## Future

- **Timing cover** - jitter / piggybacking so message *cadence* (handshake
  bursts, out-of-range keepalives) isn't itself a fingerprint
- **ChatFilter** - Validates messages against the game's approved word list (via Katsuba + Root.wad)
- Zone negotiation, realm coordination, and meetup protocol messages
