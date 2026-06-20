# HiveMind

Bot-to-bot communication protocol over Wizard101's in-game directed chat. Two independent WizWalker bots can coordinate using whispers as the transport layer.

## Requirements

- Windows 10/11
- Python 3.11+
- Two Wizard101 clients running (accounts must be on each other's buddy list)

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

## Architecture

```
ChatEncoder       Maps MessageType enums to compact tokens (PING -> "P0")
MessageDispatcher Routes decoded MessageType to async handler functions
HiveMindProtocol  Wraps WizWalker client with send/receive/dispatch loop
```

## Future

- **ChatStegCipher** - Encodes tokens into natural-sounding sentences using a shared key
- **ChatFilter** - Validates messages against the game's approved word list (via Katsuba + Root.wad)
- Zone negotiation, realm coordination, and meetup protocol messages
