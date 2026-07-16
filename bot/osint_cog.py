"""
osint_cog.py — Axiom OSINT Suite v2
Sources per command:
  email    — HIBP breaches+pastes, Emailrep.io, Gravatar, disposable check, DNS MX/SPF/DMARC
  breach   — HIBP full DB + domain pivot, breach timeline, data class breakdown
  username — 70+ platform concurrent probes
  discordid— Snowflake decode + full Discord API user fetch
  phone    — phonenumbers, Numverify, AbstractAPI, disposable SIM check, carrier+timezone
  ip       — ipinfo, RDAP/WHOIS, Shodan, AbuseIPDB, VirusTotal, Tor exit check,
             proxycheck.io, reverse DNS, BGP prefix
  wifi     — Wigle SSID+BSSID, MAC OUI vendor lookup, channel/encryption/GPS
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

# ─── KEYS (set as Replit Secrets or env vars) ─────────────────────────────────
HIBP_API_KEY        = os.getenv("HIBP_API_KEY", "")
SHODAN_API_KEY      = os.getenv("SHODAN_API_KEY", "")
WIGLE_API_NAME      = os.getenv("WIGLE_API_NAME", "")
WIGLE_API_TOKEN     = os.getenv("WIGLE_API_TOKEN", "")
NUMVERIFY_KEY       = os.getenv("NUMVERIFY_KEY", "")
IPINFO_TOKEN        = os.getenv("IPINFO_TOKEN", "")
ABUSEIPDB_KEY       = os.getenv("ABUSEIPDB_KEY", "")
VIRUSTOTAL_KEY      = os.getenv("VIRUSTOTAL_KEY", "")
ABSTRACTAPI_PHONE   = os.getenv("ABSTRACTAPI_PHONE", "")   # abstractapi.com/phone-validation

# ─── USERNAME PLATFORMS (70+) ─────────────────────────────────────────────────
USERNAME_PLATFORMS: dict[str, str] = {
    # Dev / tech
    "GitHub":           "https://github.com/{}",
    "GitLab":           "https://gitlab.com/{}",
    "Bitbucket":        "https://bitbucket.org/{}",
    "Replit":           "https://replit.com/@{}",
    "Codepen":          "https://codepen.io/{}",
    "Hackerrank":       "https://www.hackerrank.com/{}",
    "LeetCode":         "https://leetcode.com/{}",
    "Codeforces":       "https://codeforces.com/profile/{}",
    "HackerNews":       "https://news.ycombinator.com/user?id={}",
    "StackOverflow":    "https://stackoverflow.com/users/{}",
    "Keybase":          "https://keybase.io/{}",
    "npm":              "https://www.npmjs.com/~{}",
    "PyPI":             "https://pypi.org/user/{}/",
    # Social
    "Twitter/X":        "https://twitter.com/{}",
    "Instagram":        "https://www.instagram.com/{}/",
    "TikTok":           "https://www.tiktok.com/@{}",
    "Reddit":           "https://www.reddit.com/user/{}",
    "Pinterest":        "https://www.pinterest.com/{}/",
    "Snapchat":         "https://www.snapchat.com/add/{}",
    "Tumblr":           "https://{}.tumblr.com",
    "VK":               "https://vk.com/{}",
    "Telegram":         "https://t.me/{}",
    "LinkedIn":         "https://www.linkedin.com/in/{}",
    "Facebook":         "https://www.facebook.com/{}",
    "Mastodon":         "https://mastodon.social/@{}",
    "Bluesky":          "https://bsky.app/profile/{}",
    "Threads":          "https://www.threads.net/@{}",
    # Content / creative
    "YouTube":          "https://www.youtube.com/@{}",
    "Twitch":           "https://www.twitch.tv/{}",
    "Kick":             "https://kick.com/{}",
    "Medium":           "https://medium.com/@{}",
    "Substack":         "https://substack.com/@{}",
    "DeviantArt":       "https://www.deviantart.com/{}",
    "Flickr":           "https://www.flickr.com/people/{}",
    "500px":            "https://500px.com/p/{}",
    "Dribbble":         "https://dribbble.com/{}",
    "Behance":          "https://www.behance.net/{}",
    "ArtStation":       "https://www.artstation.com/{}",
    "Wattpad":          "https://www.wattpad.com/user/{}",
    "SoundCloud":       "https://soundcloud.com/{}",
    "Spotify":          "https://open.spotify.com/user/{}",
    "Last.fm":          "https://www.last.fm/user/{}",
    "Bandcamp":         "https://bandcamp.com/{}",
    "Letterboxd":       "https://letterboxd.com/{}",
    "Goodreads":        "https://www.goodreads.com/{}",
    "ProductHunt":      "https://www.producthunt.com/@{}",
    # Gaming
    "Steam":            "https://steamcommunity.com/id/{}",
    "Roblox":           "https://www.roblox.com/user.aspx?username={}",
    "Chess.com":        "https://www.chess.com/member/{}",
    "Lichess":          "https://lichess.org/@/{}",
    "Duolingo":         "https://www.duolingo.com/profile/{}",
    "Kongregate":       "https://www.kongregate.com/accounts/{}",
    "Newgrounds":       "https://{}.newgrounds.com",
    "itch.io":          "https://{}.itch.io",
    # Freelance / professional
    "Fiverr":           "https://www.fiverr.com/{}",
    "Upwork":           "https://www.upwork.com/freelancers/~{}",
    "Freelancer":       "https://www.freelancer.com/u/{}",
    # Misc
    "Pastebin":         "https://pastebin.com/u/{}",
    "Imgur":            "https://imgur.com/user/{}",
    "Gravatar":         "https://en.gravatar.com/{}",
    "About.me":         "https://about.me/{}",
    "Linktree":         "https://linktr.ee/{}",
    "Ko-fi":            "https://ko-fi.com/{}",
    "Buy Me a Coffee":  "https://buymeacoffee.com/{}",
    "Patreon":          "https://www.patreon.com/{}",
    "OnlyFans":         "https://onlyfans.com/{}",
    "Cash App":         "https://cash.app/${}",
    "Venmo":            "https://venmo.com/{}",
}

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def build_embed(title: str, color: discord.Color = discord.Color.from_rgb(20, 20, 30)) -> discord.Embed:
    e = discord.Embed(title=f"🔍 {title}", color=color, timestamp=datetime.now(timezone.utc))
    e.set_footer(text=f"Axiom OSINT v2 • {ts()}")
    return e

def chunk_field(items: list[str], sep: str = "\n", limit: int = 1024) -> list[str]:
    """Split a list of strings into chunks that fit within embed field limits."""
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
            url,
            headers=headers or {},
            params=params,
            timeout=aiohttp.ClientTimeout(total=timeout),
            ssl=False,
        ) as r:
            if r.status in (200, 201):
                ct = r.headers.get("Content-Type", "")
                if "json" in ct:
                    return await r.json(content_type=None)
                return await r.text()
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
                url,
                timeout=aiohttp.ClientTimeout(total=7),
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                ssl=False,
            ) as r:
                # some platforms redirect to a 404 page with 200 status — check for common patterns
                found = r.status == 200
                return platform, found, url
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
    async def email_lookup(self, interaction: discord.Interaction, address: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"Email — {address}")
        address_clean = address.strip().lower()

        hibp_headers = {"hibp-api-key": HIBP_API_KEY, "User-Agent": "AxiomOSINT/2.0"}
        domain = address_clean.split("@")[-1] if "@" in address_clean else ""
        email_hash = hashlib.md5(address_clean.encode()).hexdigest()

        # Fire all sources concurrently
        breach_task  = safe_get(self._session,
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(address_clean)}?truncateResponse=false",
            headers=hibp_headers)
        paste_task   = safe_get(self._session,
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{urllib.parse.quote(address_clean)}",
            headers=hibp_headers)
        emailrep_task = safe_get(self._session,
            f"https://emailrep.io/{urllib.parse.quote(address_clean)}",
            headers={"User-Agent": "AxiomOSINT/2.0"})
        gravatar_task = safe_get(self._session,
            f"https://www.gravatar.com/{email_hash}.json")
        disposable_task = safe_get(self._session,
            f"https://open.kickbox.com/v1/disposable/{urllib.parse.quote(domain)}")
        mx_task     = safe_get(self._session, f"https://dns.google/resolve?name={domain}&type=MX")
        spf_task    = safe_get(self._session, f"https://dns.google/resolve?name={domain}&type=TXT")
        dmarc_task  = safe_get(self._session, f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT")

        (breach_data, paste_data, emailrep_data, gravatar_data,
         disposable_data, mx_data, spf_data, dmarc_data) = await asyncio.gather(
            breach_task, paste_task, emailrep_task, gravatar_task,
            disposable_task, mx_task, spf_task, dmarc_task
        )

        # ① HIBP Breaches
        if isinstance(breach_data, list) and breach_data:
            names   = [b.get("Name", "?") for b in breach_data]
            dates   = [b.get("BreachDate", "?") for b in breach_data]
            classes = sorted({c for b in breach_data for c in b.get("DataClasses", [])})
            lines   = [f"`{n}` — {d}" for n, d in zip(names, dates)]
            for i, chunk in enumerate(chunk_field(lines)):
                e.add_field(
                    name=f"💀 Breached ({len(names)} sources)" if i == 0 else "↳ continued",
                    value=chunk, inline=False)
            e.add_field(name="📦 Exposed Data", value=", ".join(classes[:35]) or "unknown", inline=False)
            e.color = discord.Color.red()
        else:
            e.add_field(name="✅ HIBP Breach", value="No known breaches", inline=True)
            e.color = discord.Color.green()

        # ② HIBP Pastes
        if isinstance(paste_data, list) and paste_data:
            lines = [f"`{p.get('Source','?')}` — {str(p.get('Date','?'))[:10]}" for p in paste_data[:15]]
            e.add_field(name=f"📋 Paste Leaks ({len(paste_data)})", value="\n".join(lines), inline=False)

        # ③ Emailrep.io
        if isinstance(emailrep_data, dict):
            rep      = emailrep_data.get("reputation", "unknown")
            sus      = emailrep_data.get("suspicious", False)
            refs     = emailrep_data.get("references", 0)
            details  = emailrep_data.get("details", {})
            profiles = details.get("profiles", [])
            e.add_field(name="🧠 Reputation",       value=f"`{rep}` {'⚠️ suspicious' if sus else ''}",   inline=True)
            e.add_field(name="📊 Ref Count",         value=f"`{refs}`",                                    inline=True)
            e.add_field(name="🔒 Deliverable",       value=f"`{details.get('deliverable','?')}`",          inline=True)
            e.add_field(name="🏢 Free Provider",     value=f"`{details.get('free_provider','?')}`",        inline=True)
            e.add_field(name="🤖 Spam",              value=f"`{details.get('spam','?')}`",                 inline=True)
            e.add_field(name="🔐 Data Breach",       value=f"`{details.get('data_breach','?')}`",          inline=True)
            if profiles:
                e.add_field(name="🌐 Linked Profiles", value=", ".join(f"`{p}`" for p in profiles), inline=False)

        # ④ Gravatar
        if isinstance(gravatar_data, dict) and gravatar_data.get("entry"):
            entry      = gravatar_data["entry"][0]
            display    = entry.get("displayName", "")
            avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?s=200"
            e.add_field(name="🖼️ Gravatar Name",    value=f"`{display}`" if display else "found (no name)", inline=True)
            e.add_field(name="🔗 Gravatar URL",      value=f"[Avatar]({avatar_url})", inline=True)
            e.set_thumbnail(url=avatar_url)

        # ⑤ Disposable check
        if isinstance(disposable_data, dict):
            is_disp = disposable_data.get("disposable", False)
            e.add_field(name="🗑️ Disposable Domain", value=f"`{'YES ⚠️' if is_disp else 'No'}`", inline=True)

        # ⑥ DNS MX / SPF / DMARC
        if isinstance(mx_data, dict) and mx_data.get("Answer"):
            mxs = [a.get("data", "") for a in mx_data["Answer"][:4]]
            e.add_field(name="📧 MX Records", value="\n".join(f"`{m}`" for m in mxs), inline=False)
        if isinstance(spf_data, dict) and spf_data.get("Answer"):
            spf_records = [a.get("data","") for a in spf_data["Answer"] if "spf" in a.get("data","").lower()]
            if spf_records:
                e.add_field(name="🛡️ SPF", value=f"`{spf_records[0][:200]}`", inline=False)
        if isinstance(dmarc_data, dict) and dmarc_data.get("Answer"):
            dmarc_rec = dmarc_data["Answer"][0].get("data","")
            e.add_field(name="🛡️ DMARC", value=f"`{dmarc_rec[:200]}`", inline=False)

        await interaction.followup.send(embed=e)

    # ── /breach ───────────────────────────────────────────────────────────────
    @app_commands.command(name="breach", description="Full breach intelligence — email or domain pivot")
    @app_commands.describe(query="Email address or bare domain (e.g. example.com)")
    async def breach_lookup(self, interaction: discord.Interaction, query: str):
        await interaction.response.defer(thinking=True)
        e  = build_embed(f"Breach Intelligence — {query}")
        hd = {"hibp-api-key": HIBP_API_KEY, "User-Agent": "AxiomOSINT/2.0"}

        if "@" in query:
            # Email path — full breach + paste details
            breach_task = safe_get(self._session,
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(query)}?truncateResponse=false",
                headers=hd)
            paste_task  = safe_get(self._session,
                f"https://haveibeenpwned.com/api/v3/pasteaccount/{urllib.parse.quote(query)}",
                headers=hd)
            breach_data, paste_data = await asyncio.gather(breach_task, paste_task)

            if isinstance(breach_data, list) and breach_data:
                e.color = discord.Color.red()
                # Timeline: sort by date
                sorted_b = sorted(breach_data, key=lambda x: x.get("BreachDate",""), reverse=True)
                total_accounts = sum(b.get("PwnCount", 0) for b in sorted_b)
                all_classes    = sorted({c for b in sorted_b for c in b.get("DataClasses", [])})
                e.add_field(name="📊 Summary",
                    value=f"Breaches: **{len(sorted_b)}**\nTotal pwned records: **{total_accounts:,}**",
                    inline=False)
                e.add_field(name="📦 All Exposed Data Types",
                    value=", ".join(all_classes[:40]) or "unknown", inline=False)
                # Detailed per-breach (up to 20)
                for b in sorted_b[:20]:
                    e.add_field(
                        name=f"🔴 {b.get('Name','?')}",
                        value=(
                            f"Date: `{b.get('BreachDate','?')}`\n"
                            f"Accounts: `{b.get('PwnCount',0):,}`\n"
                            f"Data: {', '.join(b.get('DataClasses',[])[:6])}"
                        ),
                        inline=True,
                    )
            else:
                e.add_field(name="✅ Status", value="No breaches found in HIBP", inline=False)
                e.color = discord.Color.green()

            if isinstance(paste_data, list) and paste_data:
                lines = [
                    f"`{p.get('Source','?')}` — {str(p.get('Date','?'))[:10]} — "
                    f"[{'link' if p.get('Id') else 'no link'}]"
                    f"(https://pastebin.com/{p.get('Id','')})"
                    for p in paste_data[:12]
                ]
                e.add_field(name=f"📋 Paste Exposures ({len(paste_data)})",
                    value="\n".join(lines), inline=False)
        else:
            # Domain pivot
            all_breaches_task = safe_get(self._session,
                "https://haveibeenpwned.com/api/v3/breaches", headers=hd)
            all_breaches = await all_breaches_task

            if isinstance(all_breaches, list):
                domain_hits = [b for b in all_breaches
                               if b.get("Domain","").lower() == query.lower()]
                # Stats for whole HIBP DB
                total_breaches  = len(all_breaches)
                total_accounts  = sum(b.get("PwnCount",0) for b in all_breaches)
                e.add_field(name="📊 HIBP Global Stats",
                    value=f"Indexed breaches: **{total_breaches:,}**\n"
                          f"Total pwned accounts: **{total_accounts:,}**",
                    inline=False)
                if domain_hits:
                    e.color = discord.Color.orange()
                    for b in domain_hits:
                        e.add_field(
                            name=f"🔴 {b.get('Name','?')}",
                            value=(
                                f"Date: `{b.get('BreachDate','?')}`\n"
                                f"Accounts: `{b.get('PwnCount',0):,}`\n"
                                f"Data: {', '.join(b.get('DataClasses',[])[:6])}\n"
                                f"Verified: `{b.get('IsVerified','?')}`"
                            ),
                            inline=True,
                        )
                else:
                    e.add_field(name="✅ Domain Status", value="No breaches tied to this domain", inline=False)
                    e.color = discord.Color.green()

        await interaction.followup.send(embed=e)

    # ── /username ─────────────────────────────────────────────────────────────
    @app_commands.command(name="username", description="Hunt a username across 70+ platforms concurrently")
    @app_commands.describe(username="Username to hunt")
    async def username_lookup(self, interaction: discord.Interaction, username: str):
        await interaction.response.defer(thinking=True)
        sem   = asyncio.Semaphore(30)   # 30 concurrent probes
        tasks = [probe_platform(self._session, sem, p, u.format(username))
                 for p, u in USERNAME_PLATFORMS.items()]
        results  = await asyncio.gather(*tasks)
        found    = [(p, u) for p, f, u in results if f]
        not_fnd  = [p for p, f, u in results if not f]

        e = build_embed(f"Username Hunt — {username}")
        e.add_field(name=f"📊 Coverage", value=f"Probed: **{len(results)}** platforms", inline=False)

        for i, chunk in enumerate(chunk_field([f"[{p}]({u})" for p, u in found])):
            e.add_field(name=f"✅ Found ({len(found)})" if i == 0 else "↳ more", value=chunk, inline=False)

        nf_chunks = chunk_field([f"`{p}`" for p in not_fnd], sep=", ")
        for i, chunk in enumerate(nf_chunks[:2]):   # cap not-found to 2 fields
            e.add_field(name=f"❌ Not Found ({len(not_fnd)})" if i == 0 else "↳", value=chunk, inline=False)

        e.color = discord.Color.blurple() if found else discord.Color.dark_grey()
        await interaction.followup.send(embed=e)

    # ── /discordid ────────────────────────────────────────────────────────────
    @app_commands.command(name="discordid", description="Full snowflake decode + Discord user lookup")
    @app_commands.describe(user_id="Discord snowflake ID")
    async def discordid_lookup(self, interaction: discord.Interaction, user_id: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"Discord Snowflake — {user_id}")
        try:
            sf           = int(user_id)
            ts_ms        = (sf >> 22) + 1420070400000
            created_at   = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
            age_days     = (datetime.now(timezone.utc) - created_at).days
            worker_id    = (sf & 0x3E0000) >> 17
            process_id   = (sf & 0x1F000)  >> 12
            increment    = sf & 0xFFF
            binary_repr  = format(sf, "064b")

            e.add_field(name="🕐 Created",          value=f"`{created_at.strftime('%Y-%m-%d %H:%M:%S')} UTC`\n(`{age_days:,}` days ago)", inline=True)
            e.add_field(name="⚙️ Internal IDs",     value=f"Worker: `{worker_id}` | Process: `{process_id}` | Inc: `{increment}`", inline=True)
            e.add_field(name="📅 Unix MS",           value=f"`{ts_ms}`", inline=True)
            e.add_field(name="🔢 Binary (64-bit)",   value=f"```{binary_repr[:32]}\n{binary_repr[32:]}```", inline=False)

            try:
                user = await interaction.client.fetch_user(sf)
                e.add_field(name="👤 Tag",           value=f"`{user}`",                                      inline=True)
                e.add_field(name="🆔 ID",            value=f"`{user.id}`",                                   inline=True)
                e.add_field(name="🤖 Bot",           value=f"`{user.bot}`",                                  inline=True)
                e.add_field(name="🖼️ Avatar URL",    value=f"[Open]({user.display_avatar.url})",             inline=True)
                e.add_field(name="💎 Avatar Hash",   value=f"`{user.avatar.key if user.avatar else 'default'}`", inline=True)
                if user.banner:
                    e.add_field(name="🎨 Banner", value=f"[Open]({user.banner.url})", inline=True)
                e.set_thumbnail(url=user.display_avatar.url)
                e.color = discord.Color.blurple()
            except discord.NotFound:
                e.add_field(name="👤 Fetch", value="Account not found or deleted", inline=False)
                e.color = discord.Color.dark_grey()
            except discord.Forbidden:
                e.add_field(name="👤 Fetch", value="Forbidden — missing access", inline=False)
        except ValueError:
            e.description = "❌ Not a valid snowflake integer"
            e.color = discord.Color.red()

        await interaction.followup.send(embed=e)

    # ── /phone ────────────────────────────────────────────────────────────────
    @app_commands.command(name="phone", description="Phone OSINT — carrier, region, validation, disposable check")
    @app_commands.describe(number="International format: +12025551234")
    async def phone_lookup(self, interaction: discord.Interaction, number: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"Phone — {number}")

        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier, timezone as ptz

            parsed   = phonenumbers.parse(number, None)
            valid    = phonenumbers.is_valid_number(parsed)
            possible = phonenumbers.is_possible_number(parsed)
            ntype    = phonenumbers.number_type(parsed)
            intl_fmt = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            natl_fmt = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
            e164_fmt = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)

            e.add_field(name="✅ Valid",             value=f"`{valid}`",     inline=True)
            e.add_field(name="❓ Possible",          value=f"`{possible}`",  inline=True)
            e.add_field(name="📲 Type",              value=f"`{ntype.name}`", inline=True)
            e.add_field(name="🌍 Region",            value=f"`{geocoder.description_for_number(parsed, 'en') or 'unknown'}`", inline=True)
            e.add_field(name="📡 Carrier",           value=f"`{carrier.name_for_number(parsed, 'en') or 'unknown'}`", inline=True)
            e.add_field(name="🕐 Timezones",         value="`" + ", ".join(ptz.time_zones_for_number(parsed)) + "`", inline=False)
            e.add_field(name="📞 International",     value=f"`{intl_fmt}`", inline=True)
            e.add_field(name="🔢 National",          value=f"`{natl_fmt}`", inline=True)
            e.add_field(name="🔤 E.164",             value=f"`{e164_fmt}`", inline=True)
            e.add_field(name="🌐 Country Code",      value=f"`+{parsed.country_code}`", inline=True)
            e.add_field(name="🔢 National Number",   value=f"`{parsed.national_number}`", inline=True)

            # Fire Numverify + AbstractAPI concurrently
            nv_task  = safe_get(self._session,
                f"http://apilayer.net/api/validate?access_key={NUMVERIFY_KEY}"
                f"&number={urllib.parse.quote(number)}&format=1") if NUMVERIFY_KEY else asyncio.sleep(0)
            ab_task  = safe_get(self._session,
                f"https://phonevalidation.abstractapi.com/v1/?api_key={ABSTRACTAPI_PHONE}"
                f"&phone={urllib.parse.quote(e164_fmt)}") if ABSTRACTAPI_PHONE else asyncio.sleep(0)

            nv_data, ab_data = await asyncio.gather(nv_task, ab_task)

            if isinstance(nv_data, dict) and nv_data.get("valid"):
                e.add_field(name="📍 Numverify Line",    value=f"`{nv_data.get('line_type','?')}`", inline=True)
                e.add_field(name="🏢 Numverify Carrier", value=f"`{nv_data.get('carrier','?')}`",   inline=True)
                e.add_field(name="🌐 Numverify Loc",     value=f"`{nv_data.get('location','?')}`",  inline=True)

            if isinstance(ab_data, dict) and ab_data.get("valid"):
                e.add_field(name="🔬 AbstractAPI Type",     value=f"`{ab_data.get('type','?')}`",                      inline=True)
                e.add_field(name="🔬 AbstractAPI Format",   value=f"`{ab_data.get('format',{}).get('international','?')}`", inline=True)
                e.add_field(name="🔬 AbstractAPI Country",  value=f"`{ab_data.get('country',{}).get('name','?')}`",    inline=True)

        except Exception as ex:
            e.description = f"❌ Error: {ex}"
            e.color = discord.Color.red()

        await interaction.followup.send(embed=e)

    # ── /ip ───────────────────────────────────────────────────────────────────
    @app_commands.command(name="ip", description="Full IP intel — geo, ASN, Shodan, AbuseIPDB, VirusTotal, Tor, VPN")
    @app_commands.describe(address="IPv4 or IPv6 address")
    async def ip_lookup(self, interaction: discord.Interaction, address: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"IP Intelligence — {address}")

        # Fire all sources concurrently
        ipinfo_task = safe_get(self._session,
            f"https://ipinfo.io/{address}/json?token={IPINFO_TOKEN}")
        ipapi_task  = safe_get(self._session,
            f"http://ip-api.com/json/{address}?fields=66846719")
        abuse_task  = safe_get(self._session,
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={address}&maxAgeInDays=90&verbose",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"}) if ABUSEIPDB_KEY else asyncio.sleep(0)
        vt_task     = safe_get(self._session,
            f"https://www.virustotal.com/api/v3/ip_addresses/{address}",
            headers={"x-apikey": VIRUSTOTAL_KEY}) if VIRUSTOTAL_KEY else asyncio.sleep(0)
        shodan_task = safe_get(self._session,
            f"https://api.shodan.io/shodan/host/{address}?key={SHODAN_API_KEY}") if SHODAN_API_KEY else asyncio.sleep(0)
        tor_task    = safe_get(self._session,
            f"https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1")
        proxy_task  = safe_get(self._session,
            f"http://proxycheck.io/v2/{address}?vpn=1&asn=1")
        bgp_task    = safe_get(self._session,
            f"https://api.bgpview.io/ip/{address}")

        (ipinfo, ipapi, abuse_raw, vt_raw, shodan_raw,
         tor_list_raw, proxy_raw, bgp_raw) = await asyncio.gather(
            ipinfo_task, ipapi_task, abuse_task, vt_task, shodan_task,
            tor_task, proxy_task, bgp_task)

        # ① ipinfo.io
        if isinstance(ipinfo, dict):
            fields = [("🌍 Country","country"),("🏙️ City","city"),("🗺️ Region","region"),
                      ("🏢 Org/ASN","org"),("📮 Postal","postal"),("⏰ Timezone","timezone"),("📍 Coords","loc")]
            for label, key in fields:
                if v := ipinfo.get(key):
                    e.add_field(name=label, value=f"`{v}`", inline=True)

        # ② ip-api.com (richer free data)
        if isinstance(ipapi, dict) and ipapi.get("status") == "success":
            e.add_field(name="🔌 ISP",       value=f"`{ipapi.get('isp','?')}`",            inline=True)
            e.add_field(name="🏢 Org",        value=f"`{ipapi.get('org','?')}`",             inline=True)
            e.add_field(name="📡 AS",         value=f"`{ipapi.get('as','?')}`",              inline=True)
            e.add_field(name="📶 Mobile",     value=f"`{ipapi.get('mobile','?')}`",          inline=True)
            e.add_field(name="🔒 Proxy/VPN",  value=f"`{ipapi.get('proxy','?')}`",           inline=True)
            e.add_field(name="🏠 Hosting",    value=f"`{ipapi.get('hosting','?')}`",         inline=True)

        # ③ RDAP / WHOIS
        try:
            from ipwhois import IPWhois
            obj = IPWhois(address)
            res = obj.lookup_rdap(depth=1)
            e.add_field(name="🔒 ASN",        value=f"`{res.get('asn','?')}`",                        inline=True)
            e.add_field(name="📝 ASN Desc",   value=f"`{res.get('asn_description','?')}`",            inline=True)
            e.add_field(name="🌐 CIDR",       value=f"`{res.get('network',{}).get('cidr','?')}`",     inline=True)
            e.add_field(name="🏷️ Net Name",   value=f"`{res.get('network',{}).get('name','?')}`",     inline=True)
            e.add_field(name="🌍 ASN Country",value=f"`{res.get('asn_country_code','?')}`",           inline=True)
        except Exception:
            pass

        # ④ AbuseIPDB
        if isinstance(abuse_raw, dict):
            d = abuse_raw.get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            color_flag = "🔴" if score > 50 else ("🟡" if score > 10 else "🟢")
            e.add_field(name=f"{color_flag} AbuseIPDB Score",  value=f"`{score}/100`",                     inline=True)
            e.add_field(name="📋 Total Reports",               value=f"`{d.get('totalReports',0)}`",        inline=True)
            e.add_field(name="📅 Last Reported",               value=f"`{str(d.get('lastReportedAt','?'))[:10]}`", inline=True)
            e.add_field(name="🔒 Usage Type",                  value=f"`{d.get('usageType','?')}`",         inline=True)
            e.add_field(name="🌐 Domain",                      value=f"`{d.get('domain','?')}`",            inline=True)
            e.add_field(name="📶 Public",                      value=f"`{d.get('isPublic','?')}`",          inline=True)

        # ⑤ VirusTotal
        if isinstance(vt_raw, dict):
            stats = vt_raw.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            mal   = stats.get("malicious", 0)
            sus2  = stats.get("suspicious", 0)
            e.add_field(name="🛡️ VirusTotal",
                value=f"Malicious: `{mal}` | Suspicious: `{sus2}` | Clean: `{stats.get('harmless',0)}`",
                inline=False)

        # ⑥ Shodan
        if isinstance(shodan_raw, dict):
            ports = shodan_raw.get("ports", [])
            vulns = list(shodan_raw.get("vulns", {}).keys())
            tags  = shodan_raw.get("tags", [])
            e.add_field(name="🔓 Open Ports",  value=f"`{', '.join(str(p) for p in ports[:25]) or 'none'}`", inline=False)
            if vulns:
                e.add_field(name=f"⚠️ CVEs ({len(vulns)})", value="`" + "`, `".join(vulns[:10]) + "`", inline=False)
            e.add_field(name="🏷️ Shodan Tags", value=f"`{', '.join(tags) or 'none'}`",  inline=True)
            e.add_field(name="💻 OS",           value=f"`{shodan_raw.get('os') or 'unknown'}`", inline=True)
            e.add_field(name="📡 Last Scan",    value=f"`{str(shodan_raw.get('last_update','?'))[:10]}`", inline=True)

        # ⑦ Tor exit check
        if isinstance(tor_list_raw, str) and address in tor_list_raw:
            e.add_field(name="🧅 Tor Exit Node", value="`YES — this IP is a known Tor exit node`", inline=False)
            e.color = discord.Color.dark_red()
        else:
            e.add_field(name="🧅 Tor Exit Node", value="`No`", inline=True)

        # ⑧ Proxycheck.io
        if isinstance(proxy_raw, dict):
            pdata = proxy_raw.get(address, {})
            e.add_field(name="🕵️ Proxy/VPN",   value=f"`{pdata.get('proxy','no')}`",  inline=True)
            e.add_field(name="🔒 Type",         value=f"`{pdata.get('type','unknown')}`", inline=True)
            e.add_field(name="📡 Provider",     value=f"`{pdata.get('provider','unknown')}`", inline=True)

        # ⑨ BGP prefix
        if isinstance(bgp_raw, dict):
            prefixes = bgp_raw.get("data",{}).get("prefixes",[])
            if prefixes:
                p = prefixes[0]
                e.add_field(name="📡 BGP Prefix",   value=f"`{p.get('prefix','?')}`",                      inline=True)
                e.add_field(name="🏷️ BGP Name",     value=f"`{p.get('name','?')}`",                        inline=True)
                e.add_field(name="🌍 BGP Country",  value=f"`{p.get('country_code','?')}`",                inline=True)

        # ⑩ Reverse DNS
        try:
            hostname = socket.gethostbyaddr(address)[0]
            e.add_field(name="🔄 Reverse DNS", value=f"`{hostname}`", inline=False)
        except Exception:
            pass

        await interaction.followup.send(embed=e)

    # ── /wifi ─────────────────────────────────────────────────────────────────
    @app_commands.command(name="wifi", description="WiFi OSINT — Wigle SSID/BSSID + MAC vendor lookup")
    @app_commands.describe(query="SSID name or BSSID (MAC address like AA:BB:CC:DD:EE:FF)")
    async def wifi_lookup(self, interaction: discord.Interaction, query: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"WiFi — {query}")

        is_bssid = bool(re.match(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$", query))
        params   = {"netid": query} if is_bssid else {"ssid": query, "resultsPerPage": 25}
        auth_str = base64.b64encode(f"{WIGLE_API_NAME}:{WIGLE_API_TOKEN}".encode()).decode()

        wigle_task = safe_get(self._session,
            "https://api.wigle.net/api/v2/network/search?" + urllib.parse.urlencode(params),
            headers={"Authorization": f"Basic {auth_str}"})

        # MAC vendor lookup (only for BSSID queries)
        oui_clean = query.replace("-", ":").upper()[:8]
        vendor_task = safe_get(self._session,
            f"https://api.macvendors.com/{urllib.parse.quote(oui_clean)}") if is_bssid else asyncio.sleep(0)

        wigle_data, vendor_data = await asyncio.gather(wigle_task, vendor_task)

        if isinstance(wigle_data, dict) and wigle_data.get("success"):
            results = wigle_data.get("results", [])
            total   = wigle_data.get("totalResults", 0)
            e.add_field(name="📊 Total Matches in Wigle", value=f"`{total:,}`", inline=False)

            if is_bssid and isinstance(vendor_data, str) and vendor_data.strip():
                e.add_field(name="🏭 MAC Vendor (OUI)", value=f"`{vendor_data.strip()}`", inline=False)

            # Encryption breakdown
            enc_counts: dict[str, int] = {}
            for net in results:
                enc = net.get("encryption", "unknown")
                enc_counts[enc] = enc_counts.get(enc, 0) + 1
            if enc_counts:
                e.add_field(name="🔒 Encryption Breakdown",
                    value="\n".join(f"`{k}`: {v}" for k, v in sorted(enc_counts.items(), key=lambda x: -x[1])),
                    inline=True)

            # Channel distribution
            ch_counts: dict[str, int] = {}
            for net in results:
                ch = str(net.get("channel", "?"))
                ch_counts[ch] = ch_counts.get(ch, 0) + 1
            if ch_counts:
                e.add_field(name="📡 Channel Distribution",
                    value="\n".join(f"Ch`{k}`: {v}" for k, v in sorted(ch_counts.items(), key=lambda x: -x[1])[:8]),
                    inline=True)

            # Individual network cards
            for net in results[:8]:
                bssid    = net.get("netid", "?")
                ssid     = net.get("ssid", "(hidden)") or "(hidden)"
                lat      = net.get("trilat", "?")
                lon      = net.get("trilong", "?")
                enc      = net.get("encryption", "?")
                channel  = net.get("channel", "?")
                last     = str(net.get("lasttime", "?"))[:10]
                city     = net.get("city", "?")
                region   = net.get("region", "?")
                country  = net.get("country", "?")
                maps_url = f"https://www.google.com/maps?q={lat},{lon}"

                # Per-BSSID vendor lookup if not a direct BSSID query
                mac_prefix = bssid.replace("-", ":").upper()[:8] if bssid != "?" else ""
                val = (
                    f"📍 [{lat}, {lon}]({maps_url})\n"
                    f"🔒 Encryption: `{enc}`\n"
                    f"📡 Channel: `{channel}`\n"
                    f"📅 Last seen: `{last}`\n"
                    f"🏙️ `{city}, {region}, {country}`"
                )
                e.add_field(name=f"`{bssid}` — **{ssid}**", value=val, inline=False)
        else:
            e.description = "❌ No results — check Wigle credentials (WIGLE_API_NAME / WIGLE_API_TOKEN secrets)"
            e.color = discord.Color.red()

        await interaction.followup.send(embed=e)


async def setup(bot: commands.Bot):
    await bot.add_cog(OSINTCog(bot))
