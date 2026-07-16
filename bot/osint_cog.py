"""
osint_cog.py — Axiom OSINT Suite v2
User-installable: works in guilds, DMs, and private channels.
All commands gated behind the owner whitelist.
"""

import discord
from discord.ext import commands
from discord import app_commands
import aiohttp
import asyncio
import hashlib
import re
import base64
import socket
import urllib.parse
import os
from datetime import datetime, timezone
from typing import Optional

import whitelist as wl

# ─── KEYS ─────────────────────────────────────────────────────────────────────
HIBP_API_KEY      = os.getenv("HIBP_API_KEY", "")
SHODAN_API_KEY    = os.getenv("SHODAN_API_KEY", "")
WIGLE_API_NAME    = os.getenv("WIGLE_API_NAME", "")
WIGLE_API_TOKEN   = os.getenv("WIGLE_API_TOKEN", "")
NUMVERIFY_KEY     = os.getenv("NUMVERIFY_KEY", "")
IPINFO_TOKEN      = os.getenv("IPINFO_TOKEN", "")
ABUSEIPDB_KEY     = os.getenv("ABUSEIPDB_KEY", "")
VIRUSTOTAL_KEY    = os.getenv("VIRUSTOTAL_KEY", "")
ABSTRACTAPI_PHONE = os.getenv("ABSTRACTAPI_PHONE", "")
OWNER_ID          = int(os.environ.get("BOT_OWNER_ID", "0"))

# ─── PLATFORM LIST (70+) ──────────────────────────────────────────────────────
USERNAME_PLATFORMS: dict[str, str] = {
    "GitHub":          "https://github.com/{}",
    "GitLab":          "https://gitlab.com/{}",
    "Bitbucket":       "https://bitbucket.org/{}",
    "Replit":          "https://replit.com/@{}",
    "Codepen":         "https://codepen.io/{}",
    "Hackerrank":      "https://www.hackerrank.com/{}",
    "LeetCode":        "https://leetcode.com/{}",
    "Codeforces":      "https://codeforces.com/profile/{}",
    "HackerNews":      "https://news.ycombinator.com/user?id={}",
    "Keybase":         "https://keybase.io/{}",
    "npm":             "https://www.npmjs.com/~{}",
    "PyPI":            "https://pypi.org/user/{}/",
    "Twitter/X":       "https://twitter.com/{}",
    "Instagram":       "https://www.instagram.com/{}/",
    "TikTok":          "https://www.tiktok.com/@{}",
    "Reddit":          "https://www.reddit.com/user/{}",
    "Pinterest":       "https://www.pinterest.com/{}/",
    "Snapchat":        "https://www.snapchat.com/add/{}",
    "Tumblr":          "https://{}.tumblr.com",
    "VK":              "https://vk.com/{}",
    "Telegram":        "https://t.me/{}",
    "LinkedIn":        "https://www.linkedin.com/in/{}",
    "Facebook":        "https://www.facebook.com/{}",
    "Mastodon":        "https://mastodon.social/@{}",
    "Bluesky":         "https://bsky.app/profile/{}",
    "Threads":         "https://www.threads.net/@{}",
    "YouTube":         "https://www.youtube.com/@{}",
    "Twitch":          "https://www.twitch.tv/{}",
    "Kick":            "https://kick.com/{}",
    "Medium":          "https://medium.com/@{}",
    "Substack":        "https://substack.com/@{}",
    "DeviantArt":      "https://www.deviantart.com/{}",
    "Flickr":          "https://www.flickr.com/people/{}",
    "500px":           "https://500px.com/p/{}",
    "Dribbble":        "https://dribbble.com/{}",
    "Behance":         "https://www.behance.net/{}",
    "ArtStation":      "https://www.artstation.com/{}",
    "Wattpad":         "https://www.wattpad.com/user/{}",
    "SoundCloud":      "https://soundcloud.com/{}",
    "Spotify":         "https://open.spotify.com/user/{}",
    "Last.fm":         "https://www.last.fm/user/{}",
    "Bandcamp":        "https://bandcamp.com/{}",
    "Letterboxd":      "https://letterboxd.com/{}",
    "Goodreads":       "https://www.goodreads.com/{}",
    "ProductHunt":     "https://www.producthunt.com/@{}",
    "Steam":           "https://steamcommunity.com/id/{}",
    "Roblox":          "https://www.roblox.com/user.aspx?username={}",
    "Chess.com":       "https://www.chess.com/member/{}",
    "Lichess":         "https://lichess.org/@/{}",
    "Duolingo":        "https://www.duolingo.com/profile/{}",
    "Kongregate":      "https://www.kongregate.com/accounts/{}",
    "Newgrounds":      "https://{}.newgrounds.com",
    "itch.io":         "https://{}.itch.io",
    "Fiverr":          "https://www.fiverr.com/{}",
    "Upwork":          "https://www.upwork.com/freelancers/~{}",
    "Freelancer":      "https://www.freelancer.com/u/{}",
    "Pastebin":        "https://pastebin.com/u/{}",
    "Imgur":           "https://imgur.com/user/{}",
    "Gravatar":        "https://en.gravatar.com/{}",
    "About.me":        "https://about.me/{}",
    "Linktree":        "https://linktr.ee/{}",
    "Ko-fi":           "https://ko-fi.com/{}",
    "Buy Me a Coffee": "https://buymeacoffee.com/{}",
    "Patreon":         "https://www.patreon.com/{}",
    "Cash App":        "https://cash.app/${}",
    "Venmo":           "https://venmo.com/{}",
}

# ─── WHITELIST CHECK ──────────────────────────────────────────────────────────

def whitelist_check():
    """
    App command check: passes for the bot owner or any whitelisted user.
    Sends an ephemeral denial to everyone else.
    """
    async def predicate(interaction: discord.Interaction) -> bool:
        uid = interaction.user.id
        if uid == OWNER_ID:
            return True
        if uid in wl.load_whitelist():
            return True
        await interaction.response.send_message(
            "🔒 You're not whitelisted to use Axiom commands. "
            "Contact the bot owner to get access.",
            ephemeral=True,
        )
        return False
    return app_commands.check(predicate)


# ─── SHORTHAND DECORATORS ─────────────────────────────────────────────────────
# Applied to every command so the bot works as a user install everywhere.

_installs = app_commands.allowed_installs(guilds=True, users=True)
_contexts  = app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def build_embed(title: str, color: discord.Color = discord.Color.from_rgb(20, 20, 30)) -> discord.Embed:
    e = discord.Embed(title=f"🔍 {title}", color=color,
                      timestamp=datetime.now(timezone.utc))
    e.set_footer(text="Axiom OSINT v2")
    return e


def chunk_field(items: list[str], sep: str = "\n", limit: int = 1024) -> list[str]:
    chunks, current = [], ""
    for item in items:
        if len(current) + len(item) + len(sep) > limit:
            chunks.append(current)
            current = item
        else:
            current = (current + sep + item) if current else item
    if current:
        chunks.append(current)
    return chunks or ["none"]


async def safe_get(
    session: aiohttp.ClientSession,
    url: str,
    *,
    headers: dict | None = None,
    params: dict | None = None,
    timeout: int = 10,
) -> dict | list | str | None:
    try:
        async with session.get(
            url, headers=headers or {}, params=params,
            timeout=aiohttp.ClientTimeout(total=timeout), ssl=False,
        ) as r:
            if r.status in (200, 201):
                ct = r.headers.get("Content-Type", "")
                return await r.json(content_type=None) if "json" in ct else await r.text()
            return None
    except Exception:
        return None


async def probe_platform(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    platform: str,
    url: str,
) -> tuple[str, bool, str]:
    async with sem:
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=7),
                allow_redirects=True, ssl=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            ) as r:
                return platform, r.status == 200, url
        except Exception:
            return platform, False, url


# ─── COG ──────────────────────────────────────────────────────────────────────

class OSINTCog(commands.Cog, name="OSINT"):

    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self._session: aiohttp.ClientSession | None = None

    async def cog_load(self):
        connector = aiohttp.TCPConnector(limit=100, ssl=False)
        self._session = aiohttp.ClientSession(connector=connector)

    async def cog_unload(self):
        if self._session:
            await self._session.close()

    # ── /email ────────────────────────────────────────────────────────────────
    @app_commands.command(name="email", description="Deep OSINT on an email — breaches, rep, DNS, Gravatar")
    @app_commands.describe(address="Target email address")
    @_installs
    @_contexts
    @whitelist_check()
    async def email_lookup(self, interaction: discord.Interaction, address: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"Email — {address}")
        address_clean = address.strip().lower()
        domain     = address_clean.split("@")[-1] if "@" in address_clean else ""
        email_hash = hashlib.md5(address_clean.encode()).hexdigest()
        hibp_hd    = {"hibp-api-key": HIBP_API_KEY, "User-Agent": "AxiomOSINT/2.0"}

        (breach_data, paste_data, emailrep_data, gravatar_data,
         disposable_data, mx_data, spf_data, dmarc_data) = await asyncio.gather(
            safe_get(self._session,
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(address_clean)}?truncateResponse=false",
                headers=hibp_hd),
            safe_get(self._session,
                f"https://haveibeenpwned.com/api/v3/pasteaccount/{urllib.parse.quote(address_clean)}",
                headers=hibp_hd),
            safe_get(self._session,
                f"https://emailrep.io/{urllib.parse.quote(address_clean)}",
                headers={"User-Agent": "AxiomOSINT/2.0"}),
            safe_get(self._session, f"https://www.gravatar.com/{email_hash}.json"),
            safe_get(self._session, f"https://open.kickbox.com/v1/disposable/{urllib.parse.quote(domain)}"),
            safe_get(self._session, f"https://dns.google/resolve?name={domain}&type=MX"),
            safe_get(self._session, f"https://dns.google/resolve?name={domain}&type=TXT"),
            safe_get(self._session, f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT"),
        )

        # HIBP breaches
        if isinstance(breach_data, list) and breach_data:
            names   = [b.get("Name", "?") for b in breach_data]
            dates   = [b.get("BreachDate", "?") for b in breach_data]
            classes = sorted({c for b in breach_data for c in b.get("DataClasses", [])})
            lines   = [f"`{n}` — {d}" for n, d in zip(names, dates)]
            for i, chunk in enumerate(chunk_field(lines)):
                e.add_field(name=f"💀 Breached ({len(names)})" if i == 0 else "↳", value=chunk, inline=False)
            e.add_field(name="📦 Exposed Data", value=", ".join(classes[:35]) or "unknown", inline=False)
            e.color = discord.Color.red()
        else:
            e.add_field(name="✅ HIBP", value="No known breaches", inline=True)
            e.color = discord.Color.green()

        # HIBP pastes
        if isinstance(paste_data, list) and paste_data:
            lines = [f"`{p.get('Source','?')}` — {str(p.get('Date','?'))[:10]}" for p in paste_data[:15]]
            e.add_field(name=f"📋 Pastes ({len(paste_data)})", value="\n".join(lines), inline=False)

        # Emailrep
        if isinstance(emailrep_data, dict):
            details  = emailrep_data.get("details", {})
            profiles = details.get("profiles", [])
            e.add_field(name="🧠 Reputation",   value=f"`{emailrep_data.get('reputation','?')}` {'⚠️' if emailrep_data.get('suspicious') else ''}", inline=True)
            e.add_field(name="📊 References",   value=f"`{emailrep_data.get('references', 0)}`", inline=True)
            e.add_field(name="🔒 Deliverable",  value=f"`{details.get('deliverable','?')}`",    inline=True)
            e.add_field(name="🏢 Free Provider",value=f"`{details.get('free_provider','?')}`",  inline=True)
            e.add_field(name="🤖 Spam",         value=f"`{details.get('spam','?')}`",           inline=True)
            e.add_field(name="🔐 Breach",       value=f"`{details.get('data_breach','?')}`",    inline=True)
            if profiles:
                e.add_field(name="🌐 Linked Profiles", value=", ".join(f"`{p}`" for p in profiles), inline=False)

        # Gravatar
        if isinstance(gravatar_data, dict) and gravatar_data.get("entry"):
            entry     = gravatar_data["entry"][0]
            avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?s=200"
            e.add_field(name="🖼️ Gravatar", value=f"`{entry.get('displayName','found')}`  [Avatar]({avatar_url})", inline=False)
            e.set_thumbnail(url=avatar_url)

        # Disposable
        if isinstance(disposable_data, dict):
            e.add_field(name="🗑️ Disposable Domain", value=f"`{'YES ⚠️' if disposable_data.get('disposable') else 'No'}`", inline=True)

        # DNS
        if isinstance(mx_data, dict) and mx_data.get("Answer"):
            mxs = [a.get("data","") for a in mx_data["Answer"][:4]]
            e.add_field(name="📧 MX Records", value="\n".join(f"`{m}`" for m in mxs), inline=False)
        if isinstance(spf_data, dict) and spf_data.get("Answer"):
            spf = [a.get("data","") for a in spf_data["Answer"] if "spf" in a.get("data","").lower()]
            if spf:
                e.add_field(name="🛡️ SPF", value=f"`{spf[0][:200]}`", inline=False)
        if isinstance(dmarc_data, dict) and dmarc_data.get("Answer"):
            e.add_field(name="🛡️ DMARC", value=f"`{dmarc_data['Answer'][0].get('data','')[:200]}`", inline=False)

        await interaction.followup.send(embed=e)

    # ── /breach ───────────────────────────────────────────────────────────────
    @app_commands.command(name="breach", description="Full breach intelligence — email or domain pivot")
    @app_commands.describe(query="Email address or bare domain")
    @_installs
    @_contexts
    @whitelist_check()
    async def breach_lookup(self, interaction: discord.Interaction, query: str):
        await interaction.response.defer(thinking=True)
        e  = build_embed(f"Breach Intelligence — {query}")
        hd = {"hibp-api-key": HIBP_API_KEY, "User-Agent": "AxiomOSINT/2.0"}

        if "@" in query:
            breach_data, paste_data = await asyncio.gather(
                safe_get(self._session,
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(query)}?truncateResponse=false",
                    headers=hd),
                safe_get(self._session,
                    f"https://haveibeenpwned.com/api/v3/pasteaccount/{urllib.parse.quote(query)}",
                    headers=hd),
            )
            if isinstance(breach_data, list) and breach_data:
                e.color = discord.Color.red()
                sorted_b       = sorted(breach_data, key=lambda x: x.get("BreachDate",""), reverse=True)
                total_accounts = sum(b.get("PwnCount", 0) for b in sorted_b)
                all_classes    = sorted({c for b in sorted_b for c in b.get("DataClasses", [])})
                e.add_field(name="📊 Summary",
                    value=f"Breaches: **{len(sorted_b)}** | Pwned records: **{total_accounts:,}**", inline=False)
                e.add_field(name="📦 All Exposed Data",
                    value=", ".join(all_classes[:40]) or "unknown", inline=False)
                for b in sorted_b[:20]:
                    e.add_field(
                        name=f"🔴 {b.get('Name','?')}",
                        value=(f"Date: `{b.get('BreachDate','?')}`\n"
                               f"Accounts: `{b.get('PwnCount',0):,}`\n"
                               f"Data: {', '.join(b.get('DataClasses',[])[:6])}"),
                        inline=True)
            else:
                e.add_field(name="✅ Status", value="No breaches found in HIBP", inline=False)
                e.color = discord.Color.green()
            if isinstance(paste_data, list) and paste_data:
                lines = [f"`{p.get('Source','?')}` — {str(p.get('Date','?'))[:10]}" for p in paste_data[:12]]
                e.add_field(name=f"📋 Pastes ({len(paste_data)})", value="\n".join(lines), inline=False)
        else:
            all_breaches = await safe_get(self._session, "https://haveibeenpwned.com/api/v3/breaches", headers=hd)
            if isinstance(all_breaches, list):
                domain_hits = [b for b in all_breaches if b.get("Domain","").lower() == query.lower()]
                e.add_field(name="📊 HIBP Global",
                    value=f"Total breaches: **{len(all_breaches):,}** | "
                          f"Total accounts: **{sum(b.get('PwnCount',0) for b in all_breaches):,}**",
                    inline=False)
                if domain_hits:
                    e.color = discord.Color.orange()
                    for b in domain_hits:
                        e.add_field(
                            name=f"🔴 {b.get('Name','?')}",
                            value=(f"Date: `{b.get('BreachDate','?')}`\n"
                                   f"Accounts: `{b.get('PwnCount',0):,}`\n"
                                   f"Data: {', '.join(b.get('DataClasses',[])[:6])}\n"
                                   f"Verified: `{b.get('IsVerified','?')}`"),
                            inline=True)
                else:
                    e.add_field(name="✅ Domain", value="No breaches tied to this domain", inline=False)
                    e.color = discord.Color.green()

        await interaction.followup.send(embed=e)

    # ── /username ─────────────────────────────────────────────────────────────
    @app_commands.command(name="username", description="Hunt a username across 70+ platforms concurrently")
    @app_commands.describe(username="Username to hunt")
    @_installs
    @_contexts
    @whitelist_check()
    async def username_lookup(self, interaction: discord.Interaction, username: str):
        await interaction.response.defer(thinking=True)
        sem     = asyncio.Semaphore(30)
        tasks   = [probe_platform(self._session, sem, p, u.format(username))
                   for p, u in USERNAME_PLATFORMS.items()]
        results = await asyncio.gather(*tasks)
        found   = [(p, u) for p, f, u in results if f]
        not_fnd = [p for p, f, u in results if not f]

        e = build_embed(f"Username Hunt — {username}")
        e.add_field(name="📊 Coverage", value=f"Probed: **{len(results)}** platforms", inline=False)
        for i, chunk in enumerate(chunk_field([f"[{p}]({u})" for p, u in found])):
            e.add_field(name=f"✅ Found ({len(found)})" if i == 0 else "↳", value=chunk, inline=False)
        for i, chunk in enumerate(chunk_field([f"`{p}`" for p in not_fnd], sep=", ")[:2]):
            e.add_field(name=f"❌ Not Found ({len(not_fnd)})" if i == 0 else "↳", value=chunk, inline=False)
        e.color = discord.Color.blurple() if found else discord.Color.dark_grey()
        await interaction.followup.send(embed=e)

    # ── /discordid ────────────────────────────────────────────────────────────
    @app_commands.command(name="discordid", description="Full snowflake decode + Discord user lookup")
    @app_commands.describe(user_id="Discord snowflake ID")
    @_installs
    @_contexts
    @whitelist_check()
    async def discordid_lookup(self, interaction: discord.Interaction, user_id: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"Discord Snowflake — {user_id}")
        try:
            sf         = int(user_id)
            ts_ms      = (sf >> 22) + 1420070400000
            created_at = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
            age_days   = (datetime.now(timezone.utc) - created_at).days
            worker_id  = (sf & 0x3E0000) >> 17
            process_id = (sf & 0x1F000)  >> 12
            increment  = sf & 0xFFF
            binary     = format(sf, "064b")

            e.add_field(name="🕐 Created",      value=f"`{created_at.strftime('%Y-%m-%d %H:%M:%S')} UTC`\n`{age_days:,}` days ago", inline=True)
            e.add_field(name="⚙️ Internal",     value=f"Worker `{worker_id}` | Process `{process_id}` | Inc `{increment}`", inline=True)
            e.add_field(name="📅 Unix MS",       value=f"`{ts_ms}`", inline=True)
            e.add_field(name="🔢 Binary",        value=f"```{binary[:32]}\n{binary[32:]}```", inline=False)
            try:
                user = await interaction.client.fetch_user(sf)
                e.add_field(name="👤 Tag",       value=f"`{user}`",                                inline=True)
                e.add_field(name="🤖 Bot",       value=f"`{user.bot}`",                            inline=True)
                e.add_field(name="🖼️ Avatar",    value=f"[Open]({user.display_avatar.url})",       inline=True)
                e.add_field(name="💎 Hash",      value=f"`{user.avatar.key if user.avatar else 'default'}`", inline=True)
                if user.banner:
                    e.add_field(name="🎨 Banner", value=f"[Open]({user.banner.url})", inline=True)
                e.set_thumbnail(url=user.display_avatar.url)
                e.color = discord.Color.blurple()
            except discord.NotFound:
                e.add_field(name="👤 Fetch", value="Account not found or deleted", inline=False)
            except discord.Forbidden:
                e.add_field(name="👤 Fetch", value="Forbidden — missing access", inline=False)
        except ValueError:
            e.description = "❌ Not a valid snowflake integer"
            e.color = discord.Color.red()
        await interaction.followup.send(embed=e)

    # ── /phone ────────────────────────────────────────────────────────────────
    @app_commands.command(name="phone", description="Phone OSINT — carrier, region, validation, AbstractAPI")
    @app_commands.describe(number="International format: +12025551234")
    @_installs
    @_contexts
    @whitelist_check()
    async def phone_lookup(self, interaction: discord.Interaction, number: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"Phone — {number}")
        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier, timezone as ptz

            parsed   = phonenumbers.parse(number, None)
            valid    = phonenumbers.is_valid_number(parsed)
            ntype    = phonenumbers.number_type(parsed)
            e164_fmt = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)

            e.add_field(name="✅ Valid",          value=f"`{valid}`",  inline=True)
            e.add_field(name="📲 Type",           value=f"`{ntype.name}`", inline=True)
            e.add_field(name="🌍 Region",         value=f"`{geocoder.description_for_number(parsed,'en') or 'unknown'}`", inline=True)
            e.add_field(name="📡 Carrier",        value=f"`{carrier.name_for_number(parsed,'en') or 'unknown'}`", inline=True)
            e.add_field(name="🕐 Timezones",      value="`" + ", ".join(ptz.time_zones_for_number(parsed)) + "`", inline=False)
            e.add_field(name="📞 International",  value=f"`{phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}`", inline=True)
            e.add_field(name="🔢 National",       value=f"`{phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)}`", inline=True)
            e.add_field(name="🔤 E.164",          value=f"`{e164_fmt}`", inline=True)
            e.add_field(name="🌐 Country Code",   value=f"`+{parsed.country_code}`", inline=True)

            nv_task = safe_get(self._session,
                f"http://apilayer.net/api/validate?access_key={NUMVERIFY_KEY}&number={urllib.parse.quote(number)}&format=1"
            ) if NUMVERIFY_KEY else asyncio.sleep(0)
            ab_task = safe_get(self._session,
                f"https://phonevalidation.abstractapi.com/v1/?api_key={ABSTRACTAPI_PHONE}&phone={urllib.parse.quote(e164_fmt)}"
            ) if ABSTRACTAPI_PHONE else asyncio.sleep(0)
            nv_data, ab_data = await asyncio.gather(nv_task, ab_task)

            if isinstance(nv_data, dict) and nv_data.get("valid"):
                e.add_field(name="📍 Numverify Line",    value=f"`{nv_data.get('line_type','?')}`", inline=True)
                e.add_field(name="🏢 Numverify Carrier", value=f"`{nv_data.get('carrier','?')}`",   inline=True)
                e.add_field(name="🌐 Numverify Loc",     value=f"`{nv_data.get('location','?')}`",  inline=True)
            if isinstance(ab_data, dict) and ab_data.get("valid"):
                e.add_field(name="🔬 AbstractAPI Type",    value=f"`{ab_data.get('type','?')}`", inline=True)
                e.add_field(name="🔬 AbstractAPI Country", value=f"`{ab_data.get('country',{}).get('name','?')}`", inline=True)
        except Exception as ex:
            e.description = f"❌ Error: {ex}"
            e.color = discord.Color.red()
        await interaction.followup.send(embed=e)

    # ── /ip ───────────────────────────────────────────────────────────────────
    @app_commands.command(name="ip", description="Full IP intel — geo, ASN, Shodan, AbuseIPDB, VirusTotal, Tor, VPN")
    @app_commands.describe(address="IPv4 or IPv6 address")
    @_installs
    @_contexts
    @whitelist_check()
    async def ip_lookup(self, interaction: discord.Interaction, address: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"IP Intelligence — {address}")

        (ipinfo, ipapi, abuse_raw, vt_raw, shodan_raw,
         tor_raw, proxy_raw, bgp_raw) = await asyncio.gather(
            safe_get(self._session, f"https://ipinfo.io/{address}/json?token={IPINFO_TOKEN}"),
            safe_get(self._session, f"http://ip-api.com/json/{address}?fields=66846719"),
            safe_get(self._session,
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={address}&maxAgeInDays=90&verbose",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"}) if ABUSEIPDB_KEY else asyncio.sleep(0),
            safe_get(self._session,
                f"https://www.virustotal.com/api/v3/ip_addresses/{address}",
                headers={"x-apikey": VIRUSTOTAL_KEY}) if VIRUSTOTAL_KEY else asyncio.sleep(0),
            safe_get(self._session,
                f"https://api.shodan.io/shodan/host/{address}?key={SHODAN_API_KEY}") if SHODAN_API_KEY else asyncio.sleep(0),
            safe_get(self._session, "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"),
            safe_get(self._session, f"http://proxycheck.io/v2/{address}?vpn=1&asn=1"),
            safe_get(self._session, f"https://api.bgpview.io/ip/{address}"),
        )

        # ipinfo
        if isinstance(ipinfo, dict):
            for label, key in [("🌍 Country","country"),("🏙️ City","city"),("🗺️ Region","region"),
                                ("🏢 Org","org"),("📮 Postal","postal"),("⏰ TZ","timezone"),("📍 Coords","loc")]:
                if v := ipinfo.get(key):
                    e.add_field(name=label, value=f"`{v}`", inline=True)

        # ip-api
        if isinstance(ipapi, dict) and ipapi.get("status") == "success":
            e.add_field(name="🔌 ISP",      value=f"`{ipapi.get('isp','?')}`",     inline=True)
            e.add_field(name="📡 AS",       value=f"`{ipapi.get('as','?')}`",       inline=True)
            e.add_field(name="📶 Mobile",   value=f"`{ipapi.get('mobile','?')}`",   inline=True)
            e.add_field(name="🔒 Proxy",    value=f"`{ipapi.get('proxy','?')}`",    inline=True)
            e.add_field(name="🏠 Hosting",  value=f"`{ipapi.get('hosting','?')}`",  inline=True)

        # RDAP/WHOIS
        try:
            from ipwhois import IPWhois
            res = IPWhois(address).lookup_rdap(depth=1)
            e.add_field(name="🔒 ASN",      value=f"`{res.get('asn','?')}`",                    inline=True)
            e.add_field(name="📝 ASN Desc", value=f"`{res.get('asn_description','?')}`",        inline=True)
            e.add_field(name="🌐 CIDR",     value=f"`{res.get('network',{}).get('cidr','?')}`", inline=True)
        except Exception:
            pass

        # AbuseIPDB
        if isinstance(abuse_raw, dict):
            d     = abuse_raw.get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            flag  = "🔴" if score > 50 else ("🟡" if score > 10 else "🟢")
            e.add_field(name=f"{flag} Abuse Score", value=f"`{score}/100`",                           inline=True)
            e.add_field(name="📋 Reports",           value=f"`{d.get('totalReports',0)}`",             inline=True)
            e.add_field(name="📅 Last Report",       value=f"`{str(d.get('lastReportedAt','?'))[:10]}`", inline=True)
            e.add_field(name="🔒 Usage Type",        value=f"`{d.get('usageType','?')}`",               inline=True)

        # VirusTotal
        if isinstance(vt_raw, dict):
            stats = vt_raw.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            e.add_field(name="🛡️ VirusTotal",
                value=f"Malicious: `{stats.get('malicious',0)}` | Suspicious: `{stats.get('suspicious',0)}` | Clean: `{stats.get('harmless',0)}`",
                inline=False)

        # Shodan
        if isinstance(shodan_raw, dict):
            ports = shodan_raw.get("ports", [])
            vulns = list(shodan_raw.get("vulns", {}).keys())
            e.add_field(name="🔓 Open Ports", value=f"`{', '.join(str(p) for p in ports[:25]) or 'none'}`", inline=False)
            if vulns:
                e.add_field(name=f"⚠️ CVEs ({len(vulns)})", value="`" + "`, `".join(vulns[:10]) + "`", inline=False)
            e.add_field(name="💻 OS",          value=f"`{shodan_raw.get('os') or 'unknown'}`",              inline=True)

        # Tor
        e.add_field(name="🧅 Tor Exit",
            value="`YES ⚠️`" if (isinstance(tor_raw, str) and address in tor_raw) else "`No`",
            inline=True)

        # Proxycheck
        if isinstance(proxy_raw, dict):
            pd = proxy_raw.get(address, {})
            e.add_field(name="🕵️ VPN/Proxy", value=f"`{pd.get('proxy','no')}`", inline=True)
            e.add_field(name="🔒 Type",       value=f"`{pd.get('type','unknown')}`", inline=True)

        # BGP
        if isinstance(bgp_raw, dict):
            pfxs = bgp_raw.get("data",{}).get("prefixes",[])
            if pfxs:
                p = pfxs[0]
                e.add_field(name="📡 BGP Prefix",  value=f"`{p.get('prefix','?')}`",       inline=True)
                e.add_field(name="🌍 BGP Country", value=f"`{p.get('country_code','?')}`",  inline=True)

        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(address)[0]
            e.add_field(name="🔄 Reverse DNS", value=f"`{hostname}`", inline=False)
        except Exception:
            pass

        await interaction.followup.send(embed=e)

    # ── /wifi ─────────────────────────────────────────────────────────────────
    @app_commands.command(name="wifi", description="WiFi OSINT — Wigle SSID/BSSID + MAC vendor lookup")
    @app_commands.describe(query="SSID name or BSSID (MAC address)")
    @_installs
    @_contexts
    @whitelist_check()
    async def wifi_lookup(self, interaction: discord.Interaction, query: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"WiFi — {query}")

        is_bssid = bool(re.match(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$", query))
        params   = {"netid": query} if is_bssid else {"ssid": query, "resultsPerPage": 25}
        auth_str = base64.b64encode(f"{WIGLE_API_NAME}:{WIGLE_API_TOKEN}".encode()).decode()
        oui      = query.replace("-",":").upper()[:8]

        wigle_data, vendor_data = await asyncio.gather(
            safe_get(self._session,
                "https://api.wigle.net/api/v2/network/search?" + urllib.parse.urlencode(params),
                headers={"Authorization": f"Basic {auth_str}"}),
            safe_get(self._session,
                f"https://api.macvendors.com/{urllib.parse.quote(oui)}") if is_bssid else asyncio.sleep(0),
        )

        if isinstance(wigle_data, dict) and wigle_data.get("success"):
            results = wigle_data.get("results", [])
            e.add_field(name="📊 Wigle Total", value=f"`{wigle_data.get('totalResults',0):,}`", inline=False)
            if is_bssid and isinstance(vendor_data, str) and vendor_data.strip():
                e.add_field(name="🏭 MAC Vendor", value=f"`{vendor_data.strip()}`", inline=False)

            enc_counts: dict[str, int] = {}
            for net in results:
                k = net.get("encryption","?")
                enc_counts[k] = enc_counts.get(k, 0) + 1
            if enc_counts:
                e.add_field(name="🔒 Encryption", value="\n".join(f"`{k}`: {v}" for k,v in sorted(enc_counts.items(),key=lambda x:-x[1])), inline=True)

            for net in results[:8]:
                lat, lon = net.get("trilat","?"), net.get("trilong","?")
                e.add_field(
                    name=f"`{net.get('netid','?')}` — **{net.get('ssid','?') or '(hidden)'}**",
                    value=(f"📍 [{lat}, {lon}](https://www.google.com/maps?q={lat},{lon})\n"
                           f"🔒 `{net.get('encryption','?')}` | 📡 Ch`{net.get('channel','?')}`\n"
                           f"📅 `{str(net.get('lasttime','?'))[:10]}`\n"
                           f"🏙️ `{net.get('city','?')}, {net.get('region','?')}, {net.get('country','?')}`"),
                    inline=False)
        else:
            e.description = "❌ No results — check WIGLE_API_NAME / WIGLE_API_TOKEN secrets"
            e.color = discord.Color.red()
        await interaction.followup.send(embed=e)


async def setup(bot: commands.Bot):
    await bot.add_cog(OSINTCog(bot))
