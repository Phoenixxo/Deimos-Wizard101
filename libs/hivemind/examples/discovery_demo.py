"""HiveMind discovery + handshake demo.

Run on 2+ game clients standing in the same area. Each bot writes its
role beacon yaw, then scans the entity list for peers and opens a DM
handshake (HELLO/HELLO_ACK) with each one it spots.

Pass the role on the command line:

    python examples/discovery_demo.py master
    python examples/discovery_demo.py slave

Prerequisites (same as ping_pong.py): the accounts must be on each
other's buddy list so directed chat is delivered, and the chat hooks
must be active.

Controls:
  1      - List confirmed peers
  Ctrl+C - Stop and unhook
"""

import asyncio
import sys

from wizwalker import ClientHandler
from hivemind import HiveMindProtocol, Role


async def main():
    role = Role.MASTER if (len(sys.argv) > 1 and sys.argv[1].lower() == "master") else Role.SLAVE

    handler = ClientHandler()
    clients = handler.get_new_clients()
    if not clients:
        print("No game clients found.")
        return

    client = clients[0]
    print(f"Attached to client (PID: {client._pymem.process_id}) as {role.name}")

    protocol = None
    try:
        print("Activating hooks...")
        await client.activate_hooks()
        await client.hook_handler.activate_chat_send_hook()
        await client.hook_handler.activate_chat_hook(wait_for_ready=False)

        print("Starting HiveMind protocol (discovery on)...")
        protocol = HiveMindProtocol(client, role=role)

        loop = asyncio.get_event_loop()

        if role is Role.SLAVE:
            # Slave decides on incoming bot offers by prompting on the console.
            # (In Deimos this callback is a real in-app confirmation dialog.)
            async def confirm_bot(sender_gid, bot_index):
                answer = await loop.run_in_executor(
                    None, lambda: input(f"\n  Master {sender_gid} offers bot #{bot_index}. Run it? [y/N] ").strip().lower()
                )
                return answer == "y"
            protocol.on_bot_offer = confirm_bot
        else:
            async def accepted(sender_gid, bot_index):
                print(f"  -> {sender_gid} will run bot #{bot_index}")
            async def rejected(sender_gid, bot_index):
                print(f"  -> {sender_gid} declined bot #{bot_index}")
            protocol.on_bot_accepted = accepted
            protocol.on_bot_rejected = rejected

        await protocol.start(discover=True)

        if role is Role.SLAVE:
            # Actively look for team-ups so incoming offers are entertained.
            protocol.start_seeking()

        gid = await client.game_client.player_gid()
        print(f"\nYour GID: {gid}  Role: {role.name}")
        print("Teleported onto the magic grid; beacon yaw set. Scanning for peers...\n")
        print("  1      - List confirmed peers")
        if role is Role.MASTER:
            print("  2      - Offer a bot index to all confirmed peers")
        print("  Ctrl+C - Exit\n")

        while True:
            choice = await loop.run_in_executor(None, lambda: input("> ").strip())
            if choice == "1":
                peers = protocol.confirmed_peers()
                if not peers:
                    print("  No confirmed peers yet.")
                for peer in peers:
                    role_name = peer.role.name if peer.role else "?"
                    bound = "bound" if peer.bound else "unbound"
                    print(f"  GID {peer.gid}: {role_name} ({bound}) cell=({peer.qx}, {peer.qy})")
            elif choice == "2" and role is Role.MASTER:
                idx_str = await loop.run_in_executor(None, lambda: input("  Bot index: ").strip())
                try:
                    bot_index = int(idx_str)
                except ValueError:
                    print("  Invalid index")
                    continue
                sent = await protocol.offer_bot(bot_index)
                print(f"  Offered bot #{bot_index} to {len(sent)} peer(s): {sent}")
            else:
                print("  Unknown option.")

    except KeyboardInterrupt:
        print("\nCtrl+C received")
    finally:
        print("Stopping protocol...")
        if protocol is not None:
            try:
                await protocol.stop()
            except Exception:
                pass
        try:
            await client.hook_handler.deactivate_chat_hook()
        except Exception:
            pass
        try:
            await client.hook_handler.deactivate_chat_send_hook()
        except Exception:
            pass
        await handler.close()
        print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
