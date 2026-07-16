# osint_cog.py — drop this into your bot's cogs folder
# Requirements: pip install discord.py aiohttp phonenumbers ipwhois

import discord
from discord.ext import commands
from discord import app_commands
import aiohttp
import asyncio
import json
import re
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from ipwhois import IPWhois
import socket
import base64
import urllib.parse
from datetime import datetime
from typing import Optional

# ─── CONFIG ───────────────────────────────────────────────────────────────────
import os

HIBP_API_KEY     = os.getenv("HIBP_API_KEY", "")
SHODAN_API_KEY   = os.getenv("SHODAN_API_KEY", "")
WIGLE_API_NAME   = os.getenv("WIGLE_API_NAME", "")
WIGLE_API_TOKEN  = os.getenv("WIGLE_API_TOKEN", "")
NUMVERIFY_KEY    = os.getenv("NUMVERIFY_KEY", "")
IPINFO_TOKEN     = os.getenv("IPINFO_TOKEN", "")

USERNAME_PLATFORMS = {
    "GitHub":       "https://github.com/{}",
    "Twitter/X":    "https://twitter.com/{}",
    "Instagram":    "https://www.instagram.com/{}/",
    "TikTok":       "https://www.tiktok.com/@{}",
    "Reddit":       "https://www.reddit.com/user/{}",
    "Pinterest":    "https://www.pinterest.com/{}/",
    "Twitch":       "https://www.twitch.tv/{}",
    "YouTube":      "https://www.youtube.com/@{}",
    "Steam":        "https://steamcommunity.com/id/{}",
    "Roblox":       "https://www.roblox.com/user.aspx?username={}",
    "Snapchat":     "https://www.snapchat.com/add/{}",
    "Pastebin":     "https://pastebin.com/u/{}",
    "DeviantArt":   "https://www.deviantart.com/{}",
    "Flickr":       "https://www.flickr.com/people/{}",
    "Tumblr":       "https://{}.tumblr.com",
    "Medium":       "https://medium.com/@{}",
    "Spotify":      "https://open.spotify.com/user/{}",
    "SoundCloud":   "https://soundcloud.com/{}",
    "Replit":       "https://replit.com/@{}",
    "Keybase":      "https://keybase.io/{}",
    "GitLab":       "https://gitlab.com/{}",
    "Bitbucket":    "https://bitbucket.org/{}",
    "HackerNews":   "https://news.ycombinator.com/user?id={}",
    "ProductHunt":  "https://www.producthunt.com/@{}",
    "Dribbble":     "https://dribbble.com/{}",
    "Behance":      "https://www.behance.net/{}",
    "Fiverr":       "https://www.fiverr.com/{}",
    "VK":           "https://vk.com/{}",
    "Telegram":     "https://t.me/{}",
    "Chess.com":    "https://www.chess.com/member/{}",
    "Duolingo":     "https://www.duolingo.com/profile/{}",
    "Letterboxd":   "https://letterboxd.com/{}",
    "Goodreads":    "https://www.goodreads.com/{}",
    "Last.fm":      "https://www.last.fm/user/{}",
    "Lichess":      "https://lichess.org/@/{}",
    "Codepen":      "https://codepen.io/{}",
    "Hackerrank":   "https://www.hackerrank.com/{}",
    "LeetCode":     "https://leetcode.com/{}",
    "Codeforces":   "https://codeforces.com/profile/{}",
}

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def build_embed(title: str, color: discord.Color = discord.Color.dark_red()) -> discord.Embed:
    e = discord.Embed(title=f"🔍 {title}", color=color, timestamp=datetime.utcnow())
    e.set_footer(text="OSINT • Axiom Suite")
    return e


async def safe_get(session: aiohttp.ClientSession, url: str, **kwargs) -> Optional[dict | str | list]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), **kwargs) as r:
            if r.status == 200:
                ct = r.headers.get("Content-Type", "")
                return await r.json() if "json" in ct else await r.text()
            return None
    except Exception:
        return None


async def check_username_platform(session: aiohttp.ClientSession, platform: str, url: str) -> tuple[str, bool, str]:
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=6),
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        ) as r:
            return platform, r.status == 200, url
    except Exception:
        return platform, False, url


# ─── COG ──────────────────────────────────────────────────────────────────────

class OSINTCog(commands.Cog, name="OSINT"):
    """Advanced OSINT suite — Axiom-built."""

    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self._session: Optional[aiohttp.ClientSession] = None

    async def cog_load(self):
        self._session = aiohttp.ClientSession()

    async def cog_unload(self):
        if self._session:
            await self._session.close()

    # ── /email ────────────────────────────────────────────────────────────────
    @app_commands.command(name="email", description="OSINT lookup on an email address")
    @app_commands.describe(address="Email address to investigate")
    async def email_lookup(self, interaction: discord.Interaction, address: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"Email — {address}")

        breach_data = await safe_get(
            self._session,
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(address)}?truncateResponse=false",
            headers={"hibp-api-key": HIBP_API_KEY, "User-Agent": "AxiomOSINT/1.0"},
        )

        if isinstance(breach_data, list) and breach_data:
            names  = [b.get("Name", "?") for b in breach_data]
            dates  = [b.get("BreachDate", "?") for b in breach_data]
            classes = list({c for b in breach_data for c in b.get("DataClasses", [])})
            e.add_field(
                name=f"💀 Breached ({len(names)} sources)",
                value="\n".join(f"`{n}` — {d}" for n, d in zip(names[:20], dates[:20])) +
                      (f"\n…+{len(names)-20} more" if len(names) > 20 else ""),
                inline=False,
            )
            e.add_field(name="📦 Exposed Data Types", value=", ".join(classes[:30]) or "unknown", inline=False)
            e.color = discord.Color.red()
        else:
            e.add_field(name="✅ Breach Status", value="No known breaches found", inline=False)
            e.color = discord.Color.green()

        paste_data = await safe_get(
            self._session,
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{urllib.parse.quote(address)}",
            headers={"hibp-api-key": HIBP_API_KEY, "User-Agent": "AxiomOSINT/1.0"},
        )
        if isinstance(paste_data, list):
            e.add_field(
                name=f"📋 Paste Exposures ({len(paste_data)})",
                value="\n".join(
                    f"`{p.get('Source','?')}` — {p.get('Date','?')[:10] if p.get('Date') else '?'}"
                    for p in paste_data[:10]
                ) or "none",
                inline=False,
            )

        domain = address.split("@")[-1] if "@" in address else None
        if domain:
            mx = await safe_get(self._session, f"https://dns.google/resolve?name={domain}&type=MX")
            if isinstance(mx, dict) and mx.get("Answer"):
                mx_records = [a.get("data", "") for a in mx["Answer"][:3]]
                e.add_field(name="📧 MX Records", value="\n".join(f"`{m}`" for m in mx_records), inline=False)

        await interaction.followup.send(embed=e)

    # ── /breach ───────────────────────────────────────────────────────────────
    @app_commands.command(name="breach", description="Bulk breach search across HIBP database")
    @app_commands.describe(query="Email or domain to search breaches for")
    async def breach_lookup(self, interaction: discord.Interaction, query: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"Breach Scan — {query}")
        headers = {"hibp-api-key": HIBP_API_KEY, "User-Agent": "AxiomOSINT/1.0"}

        if "@" not in query:
            all_breaches = await safe_get(self._session, "https://haveibeenpwned.com/api/v3/breaches", headers=headers)
            if isinstance(all_breaches, list):
                domain_hits = [b for b in all_breaches if b.get("Domain", "").lower() == query.lower()]
                if domain_hits:
                    lines = [
                        f"**{b['Name']}** — {b.get('BreachDate','?')} — {b.get('PwnCount',0):,} accounts"
                        for b in domain_hits
                    ]
                    e.add_field(name=f"🌐 Domain Breaches ({len(domain_hits)})", value="\n".join(lines), inline=False)
                    e.color = discord.Color.orange()
                else:
                    e.add_field(name="✅ Domain Breach Status", value="No breaches tied to this domain", inline=False)
                    e.color = discord.Color.green()

                e.add_field(
                    name="📊 HIBP Database Stats",
                    value=f"Total breaches indexed: **{len(all_breaches):,}**\n"
                          f"Total pwned accounts: **{sum(b.get('PwnCount',0) for b in all_breaches):,}**",
                    inline=False,
                )
        else:
            data = await safe_get(
                self._session,
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(query)}?truncateResponse=false",
                headers=headers,
            )
            if isinstance(data, list):
                for b in data[:25]:
                    e.add_field(
                        name=b.get("Name", "?"),
                        value=f"Date: {b.get('BreachDate','?')}\n"
                              f"Accounts: {b.get('PwnCount',0):,}\n"
                              f"Data: {', '.join(b.get('DataClasses',[])[:5])}",
                        inline=True,
                    )
                e.color = discord.Color.red()
            else:
                e.add_field(name="✅ Clean", value="No breaches found", inline=False)
                e.color = discord.Color.green()

        await interaction.followup.send(embed=e)

    # ── /username ─────────────────────────────────────────────────────────────
    @app_commands.command(name="username", description="Hunt a username across 40+ platforms")
    @app_commands.describe(username="Username to search")
    async def username_lookup(self, interaction: discord.Interaction, username: str):
        await interaction.response.defer(thinking=True)

        tasks = [
            check_username_platform(self._session, platform, url.format(username))
            for platform, url in USERNAME_PLATFORMS.items()
        ]
        results = await asyncio.gather(*tasks)

        found     = [(p, u) for p, f, u in results if f]
        not_found = [p for p, f, u in results if not f]

        e = build_embed(f"Username Hunt — {username}")
        e.add_field(
            name=f"✅ Found ({len(found)})",
            value="\n".join(f"[{p}]({u})" for p, u in found[:20]) or "none",
            inline=False,
        )
        if len(found) > 20:
            e.add_field(name="…more", value="\n".join(f"[{p}]({u})" for p, u in found[20:]), inline=False)
        e.add_field(
            name=f"❌ Not Found ({len(not_found)})",
            value=", ".join(not_found[:40]) or "none",
            inline=False,
        )
        e.color = discord.Color.blurple()
        await interaction.followup.send(embed=e)

    # ── /discordid ────────────────────────────────────────────────────────────
    @app_commands.command(name="discordid", description="Decode and lookup a Discord user ID")
    @app_commands.describe(user_id="Discord snowflake ID")
    async def discordid_lookup(self, interaction: discord.Interaction, user_id: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"Discord ID — {user_id}")

        try:
            snowflake    = int(user_id)
            timestamp_ms = (snowflake >> 22) + 1420070400000
            created_at   = datetime.utcfromtimestamp(timestamp_ms / 1000)
            worker_id    = (snowflake & 0x3E0000) >> 17
            process_id   = (snowflake & 0x1F000) >> 12
            increment    = snowflake & 0xFFF

            e.add_field(name="🕐 Account Created", value=f"`{created_at.strftime('%Y-%m-%d %H:%M:%S')} UTC`", inline=True)
            e.add_field(name="⚙️ Worker ID",        value=f"`{worker_id}`",  inline=True)
            e.add_field(name="⚙️ Process ID",       value=f"`{process_id}`", inline=True)
            e.add_field(name="🔢 Increment",        value=f"`{increment}`",  inline=True)
            e.add_field(name="📅 Unix Timestamp",   value=f"`{timestamp_ms // 1000}`", inline=True)

            try:
                user = await interaction.client.fetch_user(snowflake)
                e.add_field(name="👤 Username", value=f"`{user}`",     inline=True)
                e.add_field(name="🤖 Bot",      value=f"`{user.bot}`", inline=True)
                e.add_field(name="🖼️ Avatar",   value=f"[Link]({user.display_avatar.url})", inline=True)
                if user.banner:
                    e.add_field(name="🎨 Banner", value=f"[Link]({user.banner.url})", inline=True)
                e.set_thumbnail(url=user.display_avatar.url)
            except discord.NotFound:
                e.add_field(name="👤 User Fetch", value="Account not found / deleted", inline=False)
            except discord.Forbidden:
                e.add_field(name="👤 User Fetch", value="Forbidden — bot lacks access", inline=False)
        except ValueError:
            e.description = "❌ Invalid snowflake ID"
            e.color = discord.Color.red()

        await interaction.followup.send(embed=e)

    # ── /phone ────────────────────────────────────────────────────────────────
    @app_commands.command(name="phone", description="OSINT lookup on a phone number")
    @app_commands.describe(number="Phone number in international format e.g. +12025551234")
    async def phone_lookup(self, interaction: discord.Interaction, number: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"Phone — {number}")

        try:
            parsed   = phonenumbers.parse(number, None)
            valid    = phonenumbers.is_valid_number(parsed)
            possible = phonenumbers.is_possible_number(parsed)

            e.add_field(name="✅ Valid",       value=f"`{valid}`",    inline=True)
            e.add_field(name="❓ Possible",    value=f"`{possible}`", inline=True)
            e.add_field(name="🌍 Region",      value=f"`{geocoder.description_for_number(parsed, 'en')}`", inline=True)
            e.add_field(name="📡 Carrier",     value=f"`{carrier.name_for_number(parsed, 'en') or 'unknown'}`", inline=True)
            e.add_field(name="🕐 Timezones",   value="`" + ", ".join(timezone.time_zones_for_number(parsed)) + "`", inline=False)
            e.add_field(name="📞 International", value=f"`{phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}`", inline=True)
            e.add_field(name="🔢 National",    value=f"`{phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)}`", inline=True)
            e.add_field(name="🔤 E164",        value=f"`{phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)}`", inline=True)
            e.add_field(name="📲 Number Type", value=f"`{phonenumbers.number_type(parsed).name}`", inline=True)

            if NUMVERIFY_KEY:
                nv = await safe_get(
                    self._session,
                    f"http://apilayer.net/api/validate?access_key={NUMVERIFY_KEY}"
                    f"&number={urllib.parse.quote(number)}&country_code=&format=1",
                )
                if isinstance(nv, dict) and nv.get("valid"):
                    e.add_field(name="📍 Line Type",    value=f"`{nv.get('line_type','?')}`", inline=True)
                    e.add_field(name="🏢 Carrier (NV)", value=f"`{nv.get('carrier','?')}`",  inline=True)
                    e.add_field(name="🌐 Location",     value=f"`{nv.get('location','?')}`", inline=True)

        except phonenumbers.NumberParseException as ex:
            e.description = f"❌ Parse error: {ex}"
            e.color = discord.Color.red()

        await interaction.followup.send(embed=e)

    # ── /ip ───────────────────────────────────────────────────────────────────
    @app_commands.command(name="ip", description="Deep IP address intelligence")
    @app_commands.describe(address="IPv4 or IPv6 address")
    async def ip_lookup(self, interaction: discord.Interaction, address: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"IP — {address}")

        info = await safe_get(self._session, f"https://ipinfo.io/{address}/json?token={IPINFO_TOKEN}")
        if isinstance(info, dict):
            for label, key in [
                ("🌍 Country", "country"), ("🏙️ City", "city"), ("🗺️ Region", "region"),
                ("🏢 Org / ASN", "org"),   ("📮 Postal", "postal"), ("⏰ Timezone", "timezone"),
                ("📍 Coordinates", "loc"),
            ]:
                if val := info.get(key):
                    e.add_field(name=label, value=f"`{val}`", inline=True)

        try:
            obj = IPWhois(address)
            res = obj.lookup_rdap(depth=1)
            e.add_field(name="🔒 ASN",         value=f"`{res.get('asn','?')}`",                      inline=True)
            e.add_field(name="🏷️ ASN Desc",    value=f"`{res.get('asn_description','?')}`",          inline=True)
            e.add_field(name="🌐 Network CIDR", value=f"`{res.get('network',{}).get('cidr','?')}`",  inline=True)
            e.add_field(name="🏢 Net Name",     value=f"`{res.get('network',{}).get('name','?')}`",  inline=True)
        except Exception:
            e.add_field(name="WHOIS", value="Could not resolve", inline=False)

        if SHODAN_API_KEY:
            shodan_data = await safe_get(
                self._session,
                f"https://api.shodan.io/shodan/host/{address}?key={SHODAN_API_KEY}",
            )
            if isinstance(shodan_data, dict):
                ports = shodan_data.get("ports", [])
                vulns = list(shodan_data.get("vulns", {}).keys())
                tags  = shodan_data.get("tags", [])
                e.add_field(name="🔓 Open Ports", value=f"`{', '.join(str(p) for p in ports[:20]) or 'none'}`", inline=False)
                e.add_field(name="⚠️ CVEs",        value=f"`{', '.join(vulns[:10]) or 'none'}`",                 inline=False)
                e.add_field(name="🏷️ Tags",        value=f"`{', '.join(tags) or 'none'}`",                       inline=True)
                e.add_field(name="💻 OS",           value=f"`{shodan_data.get('os') or 'unknown'}`",              inline=True)
                e.add_field(name="📡 Last Seen",    value=f"`{shodan_data.get('last_update','?')}`",              inline=True)

        try:
            hostname = socket.gethostbyaddr(address)[0]
            e.add_field(name="🔄 Reverse DNS", value=f"`{hostname}`", inline=False)
        except Exception:
            pass

        await interaction.followup.send(embed=e)

    # ── /wifi ─────────────────────────────────────────────────────────────────
    @app_commands.command(name="wifi", description="Search Wigle for WiFi networks by SSID or BSSID")
    @app_commands.describe(query="SSID name or BSSID (MAC address)")
    async def wifi_lookup(self, interaction: discord.Interaction, query: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"WiFi — {query}")

        is_bssid = bool(re.match(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$", query))
        params   = {"netid": query} if is_bssid else {"ssid": query, "resultsPerPage": 25}
        auth_str = base64.b64encode(f"{WIGLE_API_NAME}:{WIGLE_API_TOKEN}".encode()).decode()

        data = await safe_get(
            self._session,
            "https://api.wigle.net/api/v2/network/search?" + urllib.parse.urlencode(params),
            headers={"Authorization": f"Basic {auth_str}"},
        )

        if isinstance(data, dict) and data.get("success"):
            results = data.get("results", [])
            e.add_field(name="📊 Total Matches", value=f"`{data.get('totalResults', 0):,}`", inline=False)
            for net in results[:10]:
                e.add_field(
                    name=f"`{net.get('netid','?')}` — {net.get('ssid','?') or '(hidden)'}",
                    value=(
                        f"📍 `{net.get('trilat','?')}, {net.get('trilong','?')}`\n"
                        f"🔒 Encryption: `{net.get('encryption','?')}`\n"
                        f"📶 Last seen: `{str(net.get('lasttime','?'))[:10]}`\n"
                        f"🏙️ Location: `{net.get('city','?')}, {net.get('region','?')}, {net.get('country','?')}`\n"
                        f"📡 Channel: `{net.get('channel','?')}`"
                    ),
                    inline=False,
                )
        else:
            e.description = "❌ No results or Wigle credentials missing"
            e.color = discord.Color.red()

        await interaction.followup.send(embed=e)


# ─── SETUP ────────────────────────────────────────────────────────────────────

async def setup(bot: commands.Bot):
    await bot.add_cog(OSINTCog(bot))
