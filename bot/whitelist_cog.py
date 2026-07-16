"""
whitelist_cog.py — owner-only whitelist management commands.
Only the user whose ID matches BOT_OWNER_ID can run these.
"""

import discord
from discord.ext import commands
from discord import app_commands
import os
import whitelist as wl
from datetime import datetime, timezone

OWNER_ID = int(os.environ.get("BOT_OWNER_ID", "0"))


def owner_only():
    """App command check — hard-fails for anyone who isn't the bot owner."""
    async def predicate(interaction: discord.Interaction) -> bool:
        if interaction.user.id != OWNER_ID:
            await interaction.response.send_message(
                "❌ This command is restricted to the bot owner.", ephemeral=True
            )
            return False
        return True
    return app_commands.check(predicate)


class WhitelistCog(commands.Cog, name="Whitelist"):

    def __init__(self, bot: commands.Bot):
        self.bot = bot

    wl_group = app_commands.Group(
        name="whitelist",
        description="Manage who can use Axiom OSINT commands (owner only)",
        allowed_installs=app_commands.AppInstallationType(guild=True, user=True),
        allowed_contexts=app_commands.AppCommandContext(guild=True, dm_channel=True, private_channel=True),
    )

    @wl_group.command(name="add", description="Whitelist a user by their Discord ID")
    @app_commands.describe(user_id="The Discord user ID to whitelist")
    @owner_only()
    async def wl_add(self, interaction: discord.Interaction, user_id: str):
        await interaction.response.defer(ephemeral=True)
        try:
            uid = int(user_id)
        except ValueError:
            await interaction.followup.send("❌ That's not a valid user ID.", ephemeral=True)
            return

        added = await wl.add_user(uid)

        # Try to fetch the username for a nice confirmation
        username = f"`{uid}`"
        try:
            user = await self.bot.fetch_user(uid)
            username = f"`{user}` (`{uid}`)"
        except Exception:
            pass

        if added:
            e = discord.Embed(
                title="✅ User Whitelisted",
                description=f"{username} can now use Axiom OSINT commands.",
                color=discord.Color.green(),
                timestamp=datetime.now(timezone.utc),
            )
        else:
            e = discord.Embed(
                title="⚠️ Already Whitelisted",
                description=f"{username} was already on the list.",
                color=discord.Color.orange(),
                timestamp=datetime.now(timezone.utc),
            )
        await interaction.followup.send(embed=e, ephemeral=True)

    @wl_group.command(name="remove", description="Remove a user from the whitelist")
    @app_commands.describe(user_id="The Discord user ID to remove")
    @owner_only()
    async def wl_remove(self, interaction: discord.Interaction, user_id: str):
        await interaction.response.defer(ephemeral=True)
        try:
            uid = int(user_id)
        except ValueError:
            await interaction.followup.send("❌ That's not a valid user ID.", ephemeral=True)
            return

        removed = await wl.remove_user(uid)

        username = f"`{uid}`"
        try:
            user = await self.bot.fetch_user(uid)
            username = f"`{user}` (`{uid}`)"
        except Exception:
            pass

        if removed:
            e = discord.Embed(
                title="🗑️ User Removed",
                description=f"{username} has been removed from the whitelist.",
                color=discord.Color.red(),
                timestamp=datetime.now(timezone.utc),
            )
        else:
            e = discord.Embed(
                title="⚠️ Not Found",
                description=f"{username} wasn't on the whitelist.",
                color=discord.Color.orange(),
                timestamp=datetime.now(timezone.utc),
            )
        await interaction.followup.send(embed=e, ephemeral=True)

    @wl_group.command(name="list", description="Show all whitelisted users")
    @owner_only()
    async def wl_list(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        users = await wl.list_users()

        e = discord.Embed(
            title="📋 Whitelisted Users",
            color=discord.Color.blurple(),
            timestamp=datetime.now(timezone.utc),
        )
        e.set_footer(text=f"Axiom Whitelist • {len(users)} user(s)")

        if not users:
            e.description = "No users whitelisted yet."
        else:
            lines = []
            for uid in users:
                try:
                    user = await self.bot.fetch_user(uid)
                    lines.append(f"• `{user}` — `{uid}`")
                except Exception:
                    lines.append(f"• `{uid}` (unresolvable)")
            e.description = "\n".join(lines)

        await interaction.followup.send(embed=e, ephemeral=True)

    @wl_group.command(name="check", description="Check if a user ID is whitelisted")
    @app_commands.describe(user_id="The Discord user ID to check")
    @owner_only()
    async def wl_check(self, interaction: discord.Interaction, user_id: str):
        await interaction.response.defer(ephemeral=True)
        try:
            uid = int(user_id)
        except ValueError:
            await interaction.followup.send("❌ Invalid user ID.", ephemeral=True)
            return

        whitelist_set = wl.load_whitelist()
        is_owner      = uid == OWNER_ID
        on_list       = uid in whitelist_set

        username = f"`{uid}`"
        try:
            user = await self.bot.fetch_user(uid)
            username = f"`{user}` (`{uid}`)"
        except Exception:
            pass

        status = "✅ Owner (always allowed)" if is_owner else ("✅ Whitelisted" if on_list else "❌ Not whitelisted")
        e = discord.Embed(
            title="🔍 Whitelist Check",
            description=f"{username}\nStatus: **{status}**",
            color=discord.Color.green() if (is_owner or on_list) else discord.Color.red(),
            timestamp=datetime.now(timezone.utc),
        )
        await interaction.followup.send(embed=e, ephemeral=True)


async def setup(bot: commands.Bot):
    await bot.add_cog(WhitelistCog(bot))
