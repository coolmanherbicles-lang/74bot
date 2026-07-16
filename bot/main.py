"""
main.py — Axiom Bot runtime
Auto-reconnects on disconnect, exponential backoff on repeated failures,
clean SIGTERM/SIGINT shutdown. Runs like a partial VM — stays alive.
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

TOKEN = os.environ["DISCORD_BOT_TOKEN"]

# ─── SHUTDOWN SIGNAL ──────────────────────────────────────────────────────────
_shutdown = asyncio.Event()

def _handle_signal(sig, frame):
    log.info(f"Signal {sig} received — shutting down cleanly.")
    _shutdown.set()

signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT,  _handle_signal)

# ─── BOT FACTORY ──────────────────────────────────────────────────────────────

def make_bot() -> commands.Bot:
    intents = discord.Intents.default()
    intents.message_content = True
    bot = commands.Bot(command_prefix="!", intents=intents)

    @bot.event
    async def on_ready():
        try:
            synced = await bot.tree.sync()
            log.info(f"Logged in as {bot.user}  |  Synced {len(synced)} slash commands")
        except Exception as e:
            log.error(f"Command sync failed: {e}")

    @bot.event
    async def on_disconnect():
        log.warning("Bot disconnected from Discord — runtime will reconnect.")

    @bot.event
    async def on_resumed():
        log.info("Session resumed.")

    @bot.event
    async def on_error(event, *args, **kwargs):
        log.exception(f"Unhandled error in event {event}")

    return bot

# ─── MAIN LOOP WITH BACKOFF ────────────────────────────────────────────────────

async def run():
    attempt       = 0
    max_backoff   = 120   # seconds
    base_backoff  = 5

    while not _shutdown.is_set():
        bot = make_bot()
        try:
            await bot.load_extension("osint_cog")
            log.info(f"Starting bot (attempt {attempt + 1})")
            start = time.monotonic()
            await bot.start(TOKEN)
            # If start() returns cleanly, Discord closed the connection
        except discord.LoginFailure:
            log.critical("Invalid bot token — check DISCORD_BOT_TOKEN secret. Exiting.")
            sys.exit(1)
        except discord.PrivilegedIntentsRequired:
            log.critical("Privileged intents not enabled in Discord Developer Portal. Exiting.")
            sys.exit(1)
        except (discord.HTTPException, discord.GatewayNotFound, OSError) as e:
            log.error(f"Connection error: {e}")
        except Exception as e:
            log.exception(f"Unexpected error: {e}")
        finally:
            if not bot.is_closed():
                await bot.close()

        if _shutdown.is_set():
            break

        uptime = time.monotonic() - start
        if uptime > 300:
            # Was up for >5 min — reset backoff
            attempt = 0

        wait = min(base_backoff * (2 ** attempt), max_backoff)
        attempt += 1
        log.info(f"Reconnecting in {wait:.0f}s (attempt {attempt})...")
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=wait)
        except asyncio.TimeoutError:
            pass   # timeout expired — loop and reconnect

    log.info("Axiom bot shut down cleanly.")

if __name__ == "__main__":
    asyncio.run(run())
