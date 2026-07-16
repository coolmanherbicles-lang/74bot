"""
main.py — Axiom Bot runtime
Auto-reconnects on disconnect, exponential backoff on repeated failures,
clean SIGTERM/SIGINT shutdown.
"""

import discord
from discord.ext import commands
import asyncio
import os
import signal
import sys
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("axiom")

TOKEN    = os.environ["DISCORD_BOT_TOKEN"]
OWNER_ID = int(os.environ.get("BOT_OWNER_ID", "0"))

_shutdown = asyncio.Event()

def _handle_signal(sig, frame):
    log.info(f"Signal {sig} — shutting down.")
    _shutdown.set()

signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT,  _handle_signal)


def make_bot() -> commands.Bot:
    intents = discord.Intents.default()
    intents.message_content = True
    bot = commands.Bot(command_prefix="!", intents=intents)

    @bot.event
    async def on_ready():
        try:
            synced = await bot.tree.sync()
            log.info(f"Logged in as {bot.user}  |  Synced {len(synced)} slash commands")
        except Exception as ex:
            log.error(f"Sync failed: {ex}")

    @bot.event
    async def on_disconnect():
        log.warning("Disconnected — will reconnect.")

    @bot.event
    async def on_resumed():
        log.info("Session resumed.")

    @bot.event
    async def on_error(event, *args, **kwargs):
        log.exception(f"Unhandled error in {event}")

    return bot


async def run():
    attempt, base_backoff, max_backoff = 0, 5, 120

    while not _shutdown.is_set():
        bot = make_bot()
        start = time.monotonic()
        try:
            await bot.load_extension("osint_cog")
            await bot.load_extension("whitelist_cog")
            log.info(f"Starting bot (attempt {attempt + 1})")
            await bot.start(TOKEN)
        except discord.LoginFailure:
            log.critical("Invalid token — check DISCORD_BOT_TOKEN. Exiting.")
            sys.exit(1)
        except discord.PrivilegedIntentsRequired:
            log.critical("Privileged intents not enabled in Dev Portal. Exiting.")
            sys.exit(1)
        except (discord.HTTPException, discord.GatewayNotFound, OSError) as ex:
            log.error(f"Connection error: {ex}")
        except Exception as ex:
            log.exception(f"Unexpected error: {ex}")
        finally:
            if not bot.is_closed():
                await bot.close()

        if _shutdown.is_set():
            break

        if time.monotonic() - start > 300:
            attempt = 0

        wait = min(base_backoff * (2 ** attempt), max_backoff)
        attempt += 1
        log.info(f"Reconnecting in {wait:.0f}s (attempt {attempt})…")
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=wait)
        except asyncio.TimeoutError:
            pass

    log.info("Axiom shut down cleanly.")


if __name__ == "__main__":
    asyncio.run(run())
