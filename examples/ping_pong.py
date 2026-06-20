"""HiveMind PING/PONG test.

Run on 2 game clients. Each bot starts the protocol, then
use option 2 to send a PING to the other bot's GID. The
receiving bot auto-replies with PONG.

Controls:
  1      - Get your GID
  2      - Send PING to a GID
  Ctrl+C - Stop and unhook
"""

import asyncio

from wizwalker import ClientHandler
from hivemind import HiveMindProtocol, MessageType


async def main():
    handler = ClientHandler()
    clients = handler.get_new_clients()
    if not clients:
        print("No game clients found.")
        return

    client = clients[0]
    print(f"Attached to client (PID: {client._pymem.process_id})")

    try:
        print("Activating hooks...")
        await client.activate_hooks()
        await client.hook_handler.activate_chat_send_hook()
        await client.hook_handler.activate_chat_hook(wait_for_ready=False)

        print("Starting HiveMind protocol...")
        protocol = HiveMindProtocol(client)
        await protocol.start()

        gid = await client.game_client.player_gid()
        print(f"\nYour GID: {gid}")

        print("\n=== HiveMind PING/PONG ===")
        print("  1      - Get your GID")
        print("  2      - Send PING to a GID")
        print("  Ctrl+C - Exit\n")

        while True:
            choice = await asyncio.get_event_loop().run_in_executor(
                None, lambda: input("> ").strip()
            )

            if choice == "1":
                gid = await client.game_client.player_gid()
                print(f"  Your GID: {gid}")

            elif choice == "2":
                target_str = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: input("  Target GID: ").strip()
                )
                try:
                    target_gid = int(target_str)
                except ValueError:
                    print("  Invalid GID")
                    continue

                print(f"  Sending PING to {target_gid}...")
                try:
                    await protocol.send(MessageType.PING, target_gid)
                    print("  PING sent!")
                except Exception as e:
                    print(f"  Failed: {e}")
            else:
                print("  Unknown option. Use 1, 2, or Ctrl+C.")

    except KeyboardInterrupt:
        print("\nCtrl+C received")
    finally:
        print("Stopping protocol...")
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
