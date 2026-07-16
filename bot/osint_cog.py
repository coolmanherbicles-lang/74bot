"""
osint_cog.py — Axiom OSINT Suite v3
Every command now runs a breach sweep in parallel with its primary lookup.
User-installable (guilds, DMs, private channels). Whitelist gated.
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

HIBP_HEADERS = lambda: {"hibp-api-key": HIBP_API_KEY, "User-Agent": "AxiomOSINT/3.0"}

# Common domains used to spray username -> email combos against HIBP
BREACH_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "icloud.com", "aol.com", "live.com",
    "me.com", "msn.com",
]

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
    async def predicate(interaction: discord.Interaction) -> bool:
        uid = interaction.user.id
        if uid == OWNER_ID or uid in wl.load_whitelist():
            return True
        await interaction.response.send_message(
            "🔒 You're not whitelisted. Contact the bot owner to get access.",
            ephemeral=True)
        return False
    return app_commands.check(predicate)

_installs = app_commands.allowed_installs(guilds=True, users=True)
_contexts  = app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def build_embed(title: str, color: discord.Color = discord.Color.from_rgb(20, 20, 30)) -> discord.Embed:
    e = discord.Embed(title=f"🔍 {title}", color=color, timestamp=datetime.now(timezone.utc))
    e.set_footer(text="Axiom OSINT v3")
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
    timeout: int = 10,
) -> dict | list | str | None:
    try:
        async with session.get(
            url, headers=headers or {},
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

# ─── SHARED BREACH ENGINE ─────────────────────────────────────────────────────

def _mask_password(pw: str) -> str:
    """Show first 2 chars then asterisks — enough to confirm a leak without exposing it."""
    if not pw:
        return "***"
    visible = min(2, len(pw))
    return pw[:visible] + "*" * max(3, len(pw) - visible)


async def comb_search(
    session: aiohttp.ClientSession,
    query: str,
) -> list[dict]:
    """
    ProxyNova COMB search — queries the Collection Of Many Breaches dataset.
    Returns parsed records: {line, email, password_masked, source_hint}
    Free, no key required. Returns up to 100 lines.
    """
    try:
        async with session.get(
            f"https://api.proxynova.com/comb?query={urllib.parse.quote(query)}",
            headers={"User-Agent": "AxiomOSINT/3.0"},
            timeout=aiohttp.ClientTimeout(total=12),
            ssl=False,
        ) as r:
            if r.status != 200:
                return []
            data = await r.json(content_type=None)
    except Exception:
        return []

    records = []
    for line in data.get("lines", [])[:100]:
        if ":" not in line:
            continue
        parts    = line.split(":", 1)
        email    = parts[0].strip()
        password = parts[1].strip() if len(parts) > 1 else ""
        records.append({
            "raw_line":        line,
            "email":           email,
            "password_masked": _mask_password(password),
            "count":           data.get("count", 0),
        })
    return records


async def breachdirectory_search(
    session: aiohttp.ClientSession,
    query: str,
) -> list[dict]:
    """
    BreachDirectory free API — searches by username or email.
    Returns list of {email, password, sources, hash_type}.
    No key needed for basic queries.
    """
    try:
        async with session.get(
            f"https://breachdirectory.p.rapidapi.com/?func=auto&term={urllib.parse.quote(query)}",
            headers={
                "User-Agent":          "AxiomOSINT/3.0",
                "X-RapidAPI-Host":     "breachdirectory.p.rapidapi.com",
                "X-RapidAPI-Key":      os.getenv("RAPIDAPI_KEY", ""),
            },
            timeout=aiohttp.ClientTimeout(total=10),
            ssl=False,
        ) as r:
            if r.status != 200:
                return []
            return (await r.json(content_type=None)).get("result", [])
    except Exception:
        return []


async def hibp_email_breach(
    session: aiohttp.ClientSession,
    email: str,
) -> tuple[list[dict], list[dict]]:
    """Returns (breaches, pastes) for a single email via HIBP."""
    if not HIBP_API_KEY:
        return [], []
    hd = HIBP_HEADERS()
    breaches, pastes = await asyncio.gather(
        safe_get(session,
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false",
            headers=hd),
        safe_get(session,
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{urllib.parse.quote(email)}",
            headers=hd),
    )
    return (breaches if isinstance(breaches, list) else [],
            pastes   if isinstance(pastes,   list) else [])


async def username_breach_sweep(
    session: aiohttp.ClientSession,
    username: str,
) -> dict[str, dict]:
    """HIBP email spray: username@common_domains. Returns deduped breach dict."""
    if not HIBP_API_KEY:
        return {}
    emails  = [f"{username}@{d}" for d in BREACH_EMAIL_DOMAINS]
    results = await asyncio.gather(*[hibp_email_breach(session, em) for em in emails])
    merged: dict[str, dict] = {}
    for email, (breaches, pastes) in zip(emails, results):
        for b in breaches:
            name = b.get("Name", "?")
            if name not in merged:
                b["_matched_email"] = email
                merged[name] = b
        for p in pastes:
            key = f"PASTE:{p.get('Source','?')}:{p.get('Id','')}"
            if key not in merged:
                p["_matched_email"] = email
                p["_is_paste"]      = True
                merged[key]         = p
    return merged


async def full_username_breach_intel(
    session: aiohttp.ClientSession,
    username: str,
) -> tuple[list[dict], list[dict], dict[str, dict]]:
    """
    Runs all three breach sources concurrently for a username:
      - ProxyNova COMB (real leaked lines)
      - BreachDirectory (structured records)
      - HIBP email spray (named breach sources)
    Returns (comb_records, bd_records, hibp_merged)
    """
    comb, bd, hibp = await asyncio.gather(
        comb_search(session, username),
        breachdirectory_search(session, username),
        username_breach_sweep(session, username),
    )
    return comb, bd, hibp


def render_breach_fields(e: discord.Embed, merged: dict[str, dict], label_prefix: str = "") -> None:
    """Attach HIBP breach + paste fields to an embed."""
    breaches = {k: v for k, v in merged.items() if not v.get("_is_paste")}
    pastes   = {k: v for k, v in merged.items() if v.get("_is_paste")}

    if breaches:
        lines = []
        for b in sorted(breaches.values(), key=lambda x: x.get("BreachDate",""), reverse=True):
            em  = b.get("_matched_email", "")
            dc  = ", ".join(b.get("DataClasses", [])[:5])
            lines.append(f"`{b.get('Name','?')}` ({b.get('BreachDate','?')}) via `{em}` — {dc}")
        for i, chunk in enumerate(chunk_field(lines)):
            e.add_field(
                name=f"{'💀 ' + label_prefix + ' ' if label_prefix else '💀 '}Breaches ({len(breaches)})" if i == 0 else "↳",
                value=chunk, inline=False)
        all_classes = sorted({c for b in breaches.values() for c in b.get("DataClasses", [])})
        if all_classes:
            e.add_field(name="📦 All Exposed Data", value=", ".join(all_classes[:40]), inline=False)
        e.color = discord.Color.red()

    if pastes:
        lines = [
            f"`{p.get('Source','?')}` — {str(p.get('Date','?'))[:10]} via `{p.get('_matched_email','')}`"
            for p in pastes.values()
        ]
        e.add_field(name=f"📋 Paste Leaks ({len(pastes)})", value="\n".join(lines[:15]), inline=False)


# ─── COG ──────────────────────────────────────────────────────────────────────

class OSINTCog(commands.Cog, name="OSINT"):

    def __init__(self, bot: commands.Bot):
        self.bot    = bot
        self._session: aiohttp.ClientSession | None = None

    async def cog_load(self):
        self._session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=120, ssl=False))

    async def cog_unload(self):
        if self._session:
            await self._session.close()

    # ── /email ────────────────────────────────────────────────────────────────
    @app_commands.command(name="email", description="Deep email OSINT — breaches, rep, DNS, Gravatar")
    @app_commands.describe(address="Target email address")
    @_installs
    @_contexts
    @whitelist_check()
    async def email_lookup(self, interaction: discord.Interaction, address: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"Email — {address}")
        addr  = address.strip().lower()
        dom   = addr.split("@")[-1] if "@" in addr else ""
        ehash = hashlib.md5(addr.encode()).hexdigest()
        hd    = HIBP_HEADERS()

        # Fire everything concurrently
        (breach_data, paste_data, emailrep, gravatar,
         disposable, mx_data, spf_data, dmarc_data) = await asyncio.gather(
            safe_get(self._session,
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(addr)}?truncateResponse=false",
                headers=hd),
            safe_get(self._session,
                f"https://haveibeenpwned.com/api/v3/pasteaccount/{urllib.parse.quote(addr)}",
                headers=hd),
            safe_get(self._session,
                f"https://emailrep.io/{urllib.parse.quote(addr)}",
                headers={"User-Agent": "AxiomOSINT/3.0"}),
            safe_get(self._session, f"https://www.gravatar.com/{ehash}.json"),
            safe_get(self._session, f"https://open.kickbox.com/v1/disposable/{urllib.parse.quote(dom)}"),
            safe_get(self._session, f"https://dns.google/resolve?name={dom}&type=MX"),
            safe_get(self._session, f"https://dns.google/resolve?name={dom}&type=TXT"),
            safe_get(self._session, f"https://dns.google/resolve?name=_dmarc.{dom}&type=TXT"),
        )

        # HIBP breaches (direct email hit)
        if isinstance(breach_data, list) and breach_data:
            sorted_b = sorted(breach_data, key=lambda x: x.get("BreachDate",""), reverse=True)
            classes  = sorted({c for b in sorted_b for c in b.get("DataClasses",[])})
            lines    = [f"`{b.get('Name','?')}` — {b.get('BreachDate','?')} — {b.get('PwnCount',0):,} accts"
                        for b in sorted_b]
            for i, chunk in enumerate(chunk_field(lines)):
                e.add_field(name=f"💀 HIBP Breaches ({len(sorted_b)})" if i==0 else "↳",
                            value=chunk, inline=False)
            e.add_field(name="📦 Exposed Data", value=", ".join(classes[:40]) or "unknown", inline=False)
            e.color = discord.Color.red()
        else:
            e.add_field(name="✅ HIBP Direct", value="No breaches on this exact address", inline=True)
            e.color = discord.Color.green()

        # Pastes
        if isinstance(paste_data, list) and paste_data:
            lines = [f"`{p.get('Source','?')}` — {str(p.get('Date','?'))[:10]}" for p in paste_data[:15]]
            e.add_field(name=f"📋 Paste Leaks ({len(paste_data)})", value="\n".join(lines), inline=False)

        # Emailrep.io
        if isinstance(emailrep, dict):
            det = emailrep.get("details", {})
            e.add_field(name="🧠 Reputation",    value=f"`{emailrep.get('reputation','?')}` {'⚠️' if emailrep.get('suspicious') else ''}", inline=True)
            e.add_field(name="📊 References",    value=f"`{emailrep.get('references',0)}`",      inline=True)
            e.add_field(name="🔒 Deliverable",   value=f"`{det.get('deliverable','?')}`",         inline=True)
            e.add_field(name="🏢 Free Provider", value=f"`{det.get('free_provider','?')}`",       inline=True)
            e.add_field(name="🤖 Spam",          value=f"`{det.get('spam','?')}`",                inline=True)
            if det.get("profiles"):
                e.add_field(name="🌐 Linked Profiles",
                    value=", ".join(f"`{p}`" for p in det["profiles"]), inline=False)

        # Gravatar
        if isinstance(gravatar, dict) and gravatar.get("entry"):
            av = f"https://www.gravatar.com/avatar/{ehash}?s=200"
            e.add_field(name="🖼️ Gravatar",
                value=f"`{gravatar['entry'][0].get('displayName','found')}` — [Avatar]({av})", inline=False)
            e.set_thumbnail(url=av)

        # Disposable
        if isinstance(disposable, dict):
            e.add_field(name="🗑️ Disposable", value=f"`{'YES ⚠️' if disposable.get('disposable') else 'No'}`", inline=True)

        # DNS
        if isinstance(mx_data, dict) and mx_data.get("Answer"):
            e.add_field(name="📧 MX",
                value="\n".join(f"`{a.get('data','')}`" for a in mx_data["Answer"][:4]), inline=False)
        if isinstance(spf_data, dict) and spf_data.get("Answer"):
            spf = [a.get("data","") for a in spf_data["Answer"] if "spf" in a.get("data","").lower()]
            if spf:
                e.add_field(name="🛡️ SPF", value=f"`{spf[0][:200]}`", inline=False)
        if isinstance(dmarc_data, dict) and dmarc_data.get("Answer"):
            e.add_field(name="🛡️ DMARC",
                value=f"`{dmarc_data['Answer'][0].get('data','')[:200]}`", inline=False)

        # Username-sweep breach (strip domain, treat local part as username)
        local = addr.split("@")[0] if "@" in addr else addr
        sweep = await username_breach_sweep(self._session, local)
        # Remove exact matches already shown above
        exact = {b.get("Name","?") for b in (breach_data or [])}
        sweep = {k: v for k, v in sweep.items() if k not in exact}
        if sweep:
            e.add_field(name="\u200b", value="**── Username Combo Breach Sweep ──**", inline=False)
            render_breach_fields(e, sweep, label_prefix="Combo")

        await interaction.followup.send(embed=e)

    # ── /breach ───────────────────────────────────────────────────────────────
    @app_commands.command(name="breach", description="Full breach intel — email or domain pivot")
    @app_commands.describe(query="Email address or bare domain")
    @_installs
    @_contexts
    @whitelist_check()
    async def breach_lookup(self, interaction: discord.Interaction, query: str):
        await interaction.response.defer(thinking=True)
        e  = build_embed(f"Breach Intelligence — {query}")
        hd = HIBP_HEADERS()

        if "@" in query:
            (breach_data, paste_data) = await asyncio.gather(
                safe_get(self._session,
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(query)}?truncateResponse=false",
                    headers=hd),
                safe_get(self._session,
                    f"https://haveibeenpwned.com/api/v3/pasteaccount/{urllib.parse.quote(query)}",
                    headers=hd),
            )
            if isinstance(breach_data, list) and breach_data:
                e.color = discord.Color.red()
                sb  = sorted(breach_data, key=lambda x: x.get("BreachDate",""), reverse=True)
                tot = sum(b.get("PwnCount",0) for b in sb)
                all_cls = sorted({c for b in sb for c in b.get("DataClasses",[])})
                e.add_field(name="📊 Summary",
                    value=f"Breaches: **{len(sb)}** | Pwned records: **{tot:,}**", inline=False)
                e.add_field(name="📦 All Exposed Data", value=", ".join(all_cls[:40]) or "unknown", inline=False)
                for b in sb[:20]:
                    e.add_field(
                        name=f"🔴 {b.get('Name','?')}",
                        value=(f"Date: `{b.get('BreachDate','?')}`\n"
                               f"Accounts: `{b.get('PwnCount',0):,}`\n"
                               f"Data: {', '.join(b.get('DataClasses',[])[:6])}"),
                        inline=True)
            else:
                e.add_field(name="✅ Direct Hit", value="No breaches on this exact email", inline=False)
                e.color = discord.Color.green()

            if isinstance(paste_data, list) and paste_data:
                lines = [f"`{p.get('Source','?')}` — {str(p.get('Date','?'))[:10]}" for p in paste_data[:12]]
                e.add_field(name=f"📋 Pastes ({len(paste_data)})", value="\n".join(lines), inline=False)

            # Username sweep on local part
            local = query.split("@")[0]
            sweep = await username_breach_sweep(self._session, local)
            exact = {b.get("Name","?") for b in (breach_data if isinstance(breach_data, list) else [])}
            sweep = {k: v for k, v in sweep.items() if k not in exact}
            if sweep:
                e.add_field(name="\u200b", value="**── Username Combo Sweep ──**", inline=False)
                render_breach_fields(e, sweep, label_prefix="Combo")
        else:
            all_breaches = await safe_get(self._session,
                "https://haveibeenpwned.com/api/v3/breaches", headers=hd)
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
                                   f"Data: {', '.join(b.get('DataClasses',[])[:6])}"),
                            inline=True)
                else:
                    e.add_field(name="✅ Domain", value="No breaches tied to this domain", inline=False)
                    e.color = discord.Color.green()

        await interaction.followup.send(embed=e)

    # ── /username ─────────────────────────────────────────────────────────────
    @app_commands.command(name="username", description="Hunt a username across 70+ platforms + breach sweep")
    @app_commands.describe(username="Username to hunt")
    @_installs
    @_contexts
    @whitelist_check()
    async def username_lookup(self, interaction: discord.Interaction, username: str):
        await interaction.response.defer(thinking=True)

        sem = asyncio.Semaphore(30)
        platform_tasks = [probe_platform(self._session, sem, p, u.format(username))
                          for p, u in USERNAME_PLATFORMS.items()]

        # Run platform hunt and breach sweep concurrently
        platform_results, breach_merged = await asyncio.gather(
            asyncio.gather(*platform_tasks),
            username_breach_sweep(self._session, username),
        )

        found   = [(p, u) for p, f, u in platform_results if f]
        not_fnd = [p for p, f, u in platform_results if not f]

        e = build_embed(f"Username Hunt — {username}")
        e.add_field(name="📊 Coverage",
            value=f"Probed: **{len(platform_results)}** platforms | Found: **{len(found)}**",
            inline=False)
        for i, chunk in enumerate(chunk_field([f"[{p}]({u})" for p, u in found])):
            e.add_field(name=f"✅ Found ({len(found)})" if i==0 else "↳", value=chunk, inline=False)
        for i, chunk in enumerate(chunk_field([f"`{p}`" for p in not_fnd], sep=", ")[:2]):
            e.add_field(name=f"❌ Not Found ({len(not_fnd)})" if i==0 else "↳", value=chunk, inline=False)

        # Breach sweep results
        if breach_merged:
            e.add_field(name="\u200b", value="**── Breach Sweep (username@common_domains) ──**", inline=False)
            render_breach_fields(e, breach_merged)
        else:
            e.add_field(name="✅ Breach Sweep", value="No breaches found across common email combos", inline=True)
            if not found:
                e.color = discord.Color.dark_grey()

        await interaction.followup.send(embed=e)

    # ── /discordid ────────────────────────────────────────────────────────────
    @app_commands.command(name="discordid", description="Snowflake decode + full breach intel — COMB, BreachDirectory, HIBP")
    @app_commands.describe(user_id="Discord snowflake ID")
    @_installs
    @_contexts
    @whitelist_check()
    async def discordid_lookup(self, interaction: discord.Interaction, user_id: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"Discord ID — {user_id}")

        try:
            sf         = int(user_id)
            ts_ms      = (sf >> 22) + 1420070400000
            created_at = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
            age_days   = (datetime.now(timezone.utc) - created_at).days
            worker_id  = (sf & 0x3E0000) >> 17
            process_id = (sf & 0x1F000)  >> 12
            increment  = sf & 0xFFF
            binary     = format(sf, "064b")

            e.add_field(name="🕐 Created",   value=f"`{created_at.strftime('%Y-%m-%d %H:%M:%S')} UTC`\n`{age_days:,}` days ago", inline=True)
            e.add_field(name="⚙️ Internal", value=f"Worker `{worker_id}` | Process `{process_id}` | Inc `{increment}`", inline=True)
            e.add_field(name="📅 Unix MS",   value=f"`{ts_ms}`", inline=True)
            e.add_field(name="🔢 Binary",    value=f"```{binary[:32]}\n{binary[32:]}```", inline=False)

            # ── Fetch Discord user ────────────────────────────────────────────
            discord_username = None
            display_name     = None
            user             = None
            try:
                user             = await interaction.client.fetch_user(sf)
                discord_username = user.name
                display_name     = user.global_name or user.name
                e.add_field(name="👤 Username",     value=f"`{user}`",                          inline=True)
                e.add_field(name="📛 Display Name", value=f"`{display_name}`",                  inline=True)
                e.add_field(name="🤖 Bot",          value=f"`{user.bot}`",                      inline=True)
                e.add_field(name="🖼️ Avatar",       value=f"[Open]({user.display_avatar.url})", inline=True)
                e.add_field(name="💎 Avatar Hash",  value=f"`{user.avatar.key if user.avatar else 'default'}`", inline=True)
                if user.banner:
                    e.add_field(name="🎨 Banner", value=f"[Open]({user.banner.url})", inline=True)
                e.set_thumbnail(url=user.display_avatar.url)
                e.color = discord.Color.blurple()
            except discord.NotFound:
                e.add_field(name="👤 Fetch", value="Account not found or deleted", inline=False)
            except discord.Forbidden:
                e.add_field(name="👤 Fetch", value="Forbidden — missing access", inline=False)

            # ── Breach Intel (all sources, parallel) ─────────────────────────
            if discord_username:
                # Collect usernames to search — both handle and display name
                targets = list({discord_username.lower(), (display_name or "").lower()} - {""})

                # Fire COMB, BreachDirectory, and HIBP for every target name at once
                all_tasks = []
                for t in targets:
                    all_tasks.append(comb_search(self._session, t))
                    all_tasks.append(breachdirectory_search(self._session, t))
                    all_tasks.append(username_breach_sweep(self._session, t))

                results = await asyncio.gather(*all_tasks)

                # Reshape into per-target buckets
                per_target: list[tuple[str, list, list, dict]] = []
                for i, t in enumerate(targets):
                    base          = i * 3
                    comb_recs     = results[base]
                    bd_recs       = results[base + 1]
                    hibp_merged   = results[base + 2]
                    per_target.append((t, comb_recs, bd_recs, hibp_merged))

                total_hits = sum(
                    len(c) + len(b) + len(h)
                    for _, c, b, h in per_target
                )

                e.add_field(
                    name="\u200b",
                    value=f"**── 🔥 Breach Intelligence ──**\nSources: COMB · BreachDirectory · HIBP\n"
                          f"Targets searched: `{'`, `'.join(targets)}`",
                    inline=False,
                )

                # ── Collect all real emails found in COMB + BreachDirectory ──────
                # email -> {password_masked, hash_type, sources}
                leaked_email_map: dict[str, dict] = {}
                for (target, comb_recs, bd_recs, _) in per_target:
                    for rec in comb_recs:
                        em = rec.get("email", "").strip().lower()
                        if em and "@" in em and em not in leaked_email_map:
                            leaked_email_map[em] = {
                                "password_masked": rec.get("password_masked", "***"),
                                "source":          "COMB",
                                "hash_type":       "",
                            }
                    for rec in bd_recs:
                        em = rec.get("email", rec.get("username", "")).strip().lower()
                        if em and "@" in em and em not in leaked_email_map:
                            leaked_email_map[em] = {
                                "password_masked": _mask_password(rec.get("password", rec.get("hash", ""))),
                                "source":          "BreachDirectory",
                                "hash_type":       rec.get("hash_type", ""),
                            }

                # ── HIBP breach each leaked email concurrently ────────────────
                unique_emails = list(leaked_email_map.keys())[:20]   # cap at 20 to stay within embed limits
                if unique_emails:
                    hibp_per_email = await asyncio.gather(
                        *[hibp_email_breach(self._session, em) for em in unique_emails]
                    )
                else:
                    hibp_per_email = []

                # Merge email-level results with HIBP findings
                # Structure: {email: {meta, breaches: [...], pastes: [...]}}
                email_intel: list[dict] = []
                for em, (hibp_breaches, hibp_pastes) in zip(unique_emails, hibp_per_email):
                    meta = leaked_email_map[em]
                    email_intel.append({
                        "email":    em,
                        "meta":     meta,
                        "breaches": hibp_breaches,
                        "pastes":   hibp_pastes,
                    })

                # Also pull any HIBP spray hits for emails not in the real-leak set
                all_hibp_merged: dict[str, dict] = {}
                for (_, __, ___, hibp_merged) in per_target:
                    for k, v in hibp_merged.items():
                        if k not in all_hibp_merged:
                            # Only include if the matched email isn't already in our real set
                            matched = v.get("_matched_email", "")
                            if matched.lower() not in leaked_email_map:
                                all_hibp_merged[k] = v

                total_hits = len(leaked_email_map) + sum(len(x["breaches"]) for x in email_intel) + len(all_hibp_merged)

                e.add_field(
                    name="\u200b",
                    value=f"**── 🔥 Breach Intelligence ──**\nSources: COMB · BreachDirectory · HIBP\n"
                          f"Targets searched: `{'`, `'.join(targets)}`\n"
                          f"Real emails found in leaks: `{len(unique_emails)}`",
                    inline=False,
                )

                if total_hits == 0 and not leaked_email_map:
                    e.add_field(
                        name="✅ All Clear",
                        value="No records found across COMB, BreachDirectory, or HIBP for any username variant.",
                        inline=False,
                    )
                else:
                    # ── Display each leaked email + its HIBP breach chain ──────
                    if email_intel:
                        e.color = discord.Color.red()
                        for ei in email_intel:
                            em       = ei["email"]
                            meta     = ei["meta"]
                            breaches = ei["breaches"]
                            pastes   = ei["pastes"]

                            # Build the per-email field value
                            pw_line  = f"🔑 Leaked pw: `{meta['password_masked']}`"
                            if meta.get("hash_type"):
                                pw_line += f" `[{meta['hash_type']}]`"
                            pw_line += f" via `{meta['source']}`"

                            if breaches:
                                breach_names = ", ".join(
                                    f"`{b.get('Name','?')}`" for b in
                                    sorted(breaches, key=lambda x: x.get("BreachDate",""), reverse=True)[:8]
                                )
                                data_classes = sorted({c for b in breaches for c in b.get("DataClasses",[])})
                                breach_line  = f"💀 In **{len(breaches)}** breach(es): {breach_names}"
                                if data_classes:
                                    breach_line += f"\n📦 Data exposed: {', '.join(data_classes[:12])}"
                            else:
                                breach_line = "✅ Not in HIBP breach database"

                            paste_line = f"📋 In **{len(pastes)}** paste(s)" if pastes else ""

                            value = pw_line + "\n" + breach_line
                            if paste_line:
                                value += "\n" + paste_line

                            e.add_field(
                                name=f"📧 {em}",
                                value=value[:1024],
                                inline=False,
                            )

                    elif leaked_email_map and not HIBP_API_KEY:
                        # We found emails but can't HIBP check — show them raw
                        lines = []
                        for em, meta in leaked_email_map.items():
                            lines.append(f"`{em}` — pw: `{meta['password_masked']}` via `{meta['source']}`")
                        for i2, chunk in enumerate(chunk_field(lines)):
                            e.add_field(
                                name=f"💀 Leaked Emails ({len(leaked_email_map)}) — add HIBP_API_KEY for breach chain" if i2 == 0 else "↳",
                                value=chunk, inline=False,
                            )
                        e.color = discord.Color.orange()

                    # ── HIBP spray results for emails not in real-leak set ─────
                    if all_hibp_merged:
                        e.add_field(name="\u200b", value="**── HIBP Email Spray (combo hits) ──**", inline=False)
                        render_breach_fields(e, all_hibp_merged)

        except ValueError:
            e.description = "❌ Not a valid snowflake integer"
            e.color = discord.Color.red()

        await interaction.followup.send(embed=e)

    # ── /phone ────────────────────────────────────────────────────────────────
    @app_commands.command(name="phone", description="Phone OSINT — carrier, region, validation + breach sweep")
    @app_commands.describe(number="International format: +12025551234")
    @_installs
    @_contexts
    @whitelist_check()
    async def phone_lookup(self, interaction: discord.Interaction, number: str):
        await interaction.response.defer(thinking=True)
        e = build_embed(f"Phone — {number}")

        # Strip everything except digits for sweep identifiers
        digits_only = re.sub(r"\D", "", number)

        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier, timezone as ptz

            parsed   = phonenumbers.parse(number, None)
            valid    = phonenumbers.is_valid_number(parsed)
            ntype    = phonenumbers.number_type(parsed)
            e164_fmt = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            intl_fmt = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            natl_fmt = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

            e.add_field(name="✅ Valid",         value=f"`{valid}`",   inline=True)
            e.add_field(name="📲 Type",          value=f"`{ntype.name}`", inline=True)
            e.add_field(name="🌍 Region",        value=f"`{geocoder.description_for_number(parsed,'en') or 'unknown'}`", inline=True)
            e.add_field(name="📡 Carrier",       value=f"`{carrier.name_for_number(parsed,'en') or 'unknown'}`", inline=True)
            e.add_field(name="🕐 Timezones",     value="`" + ", ".join(ptz.time_zones_for_number(parsed)) + "`", inline=False)
            e.add_field(name="📞 International", value=f"`{intl_fmt}`", inline=True)
            e.add_field(name="🔢 National",      value=f"`{natl_fmt}`", inline=True)
            e.add_field(name="🔤 E.164",         value=f"`{e164_fmt}`", inline=True)
            e.add_field(name="🌐 Country Code",  value=f"`+{parsed.country_code}`", inline=True)

            nv_task = safe_get(self._session,
                f"http://apilayer.net/api/validate?access_key={NUMVERIFY_KEY}&number={urllib.parse.quote(number)}&format=1"
            ) if NUMVERIFY_KEY else asyncio.sleep(0)
            ab_task = safe_get(self._session,
                f"https://phonevalidation.abstractapi.com/v1/?api_key={ABSTRACTAPI_PHONE}&phone={urllib.parse.quote(e164_fmt)}"
            ) if ABSTRACTAPI_PHONE else asyncio.sleep(0)

            # Breach sweep: try number string variants as "username" combos
            # (some breaches expose phone numbers stored as usernames)
            sweep_task = username_breach_sweep(self._session, digits_only)

            nv_data, ab_data, sweep = await asyncio.gather(nv_task, ab_task, sweep_task)

            if isinstance(nv_data, dict) and nv_data.get("valid"):
                e.add_field(name="📍 Numverify Line",    value=f"`{nv_data.get('line_type','?')}`", inline=True)
                e.add_field(name="🏢 Numverify Carrier", value=f"`{nv_data.get('carrier','?')}`",   inline=True)
                e.add_field(name="🌐 Numverify Loc",     value=f"`{nv_data.get('location','?')}`",  inline=True)

            if isinstance(ab_data, dict) and ab_data.get("valid"):
                e.add_field(name="🔬 AbstractAPI Type",    value=f"`{ab_data.get('type','?')}`", inline=True)
                e.add_field(name="🔬 AbstractAPI Country", value=f"`{ab_data.get('country',{}).get('name','?')}`", inline=True)

            # Breach sweep results
            e.add_field(name="\u200b", value=f"**── Breach Sweep on `{digits_only}` ──**", inline=False)
            if sweep:
                render_breach_fields(e, sweep)
            else:
                e.add_field(name="✅ Breach Sweep", value="No breach hits for this number pattern", inline=True)

        except Exception as ex:
            e.description = f"❌ Error: {ex}"
            e.color = discord.Color.red()

        await interaction.followup.send(embed=e)

    # ── /ip ───────────────────────────────────────────────────────────────────
    @app_commands.command(name="ip", description="Full IP intel — geo, ASN, Shodan, AbuseIPDB, VT, Tor, VPN + breach")
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
            e.add_field(name="🔌 ISP",     value=f"`{ipapi.get('isp','?')}`",    inline=True)
            e.add_field(name="📡 AS",      value=f"`{ipapi.get('as','?')}`",      inline=True)
            e.add_field(name="📶 Mobile",  value=f"`{ipapi.get('mobile','?')}`",  inline=True)
            e.add_field(name="🔒 Proxy",   value=f"`{ipapi.get('proxy','?')}`",   inline=True)
            e.add_field(name="🏠 Hosting", value=f"`{ipapi.get('hosting','?')}`", inline=True)

        # RDAP
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
            e.add_field(name=f"{flag} Abuse Score", value=f"`{score}/100`",                            inline=True)
            e.add_field(name="📋 Reports",           value=f"`{d.get('totalReports',0)}`",              inline=True)
            e.add_field(name="📅 Last Report",       value=f"`{str(d.get('lastReportedAt','?'))[:10]}`", inline=True)
            e.add_field(name="🔒 Usage Type",        value=f"`{d.get('usageType','?')}`",               inline=True)

        # VirusTotal
        if isinstance(vt_raw, dict):
            s = vt_raw.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            e.add_field(name="🛡️ VirusTotal",
                value=f"Malicious: `{s.get('malicious',0)}` | Suspicious: `{s.get('suspicious',0)}` | Clean: `{s.get('harmless',0)}`",
                inline=False)

        # Shodan
        if isinstance(shodan_raw, dict):
            ports = shodan_raw.get("ports", [])
            vulns = list(shodan_raw.get("vulns", {}).keys())
            e.add_field(name="🔓 Open Ports",
                value=f"`{', '.join(str(p) for p in ports[:25]) or 'none'}`", inline=False)
            if vulns:
                e.add_field(name=f"⚠️ CVEs ({len(vulns)})",
                    value="`" + "`, `".join(vulns[:10]) + "`", inline=False)
            e.add_field(name="💻 OS", value=f"`{shodan_raw.get('os') or 'unknown'}`", inline=True)

        # Tor + Proxy
        e.add_field(name="🧅 Tor Exit",
            value="`YES ⚠️`" if (isinstance(tor_raw, str) and address in tor_raw) else "`No`",
            inline=True)
        if isinstance(proxy_raw, dict):
            pd = proxy_raw.get(address, {})
            e.add_field(name="🕵️ VPN/Proxy", value=f"`{pd.get('proxy','no')}`",   inline=True)
            e.add_field(name="🔒 Type",       value=f"`{pd.get('type','unknown')}`", inline=True)

        # BGP
        if isinstance(bgp_raw, dict):
            pfxs = bgp_raw.get("data",{}).get("prefixes",[])
            if pfxs:
                p = pfxs[0]
                e.add_field(name="📡 BGP Prefix",  value=f"`{p.get('prefix','?')}`",      inline=True)
                e.add_field(name="🌍 BGP Country", value=f"`{p.get('country_code','?')}`", inline=True)

        # Reverse DNS
        hostname = None
        try:
            hostname = socket.gethostbyaddr(address)[0]
            e.add_field(name="🔄 Reverse DNS", value=f"`{hostname}`", inline=False)
        except Exception:
            pass

        # Breach sweep — use hostname domain if resolved, else try IP owner org keyword
        sweep_target = None
        if hostname:
            # strip to root domain for breach sweep
            parts = hostname.rstrip(".").split(".")
            sweep_target = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        elif isinstance(ipinfo, dict) and ipinfo.get("org"):
            # e.g. "AS12345 Cloudflare" -> "Cloudflare"
            org_parts = ipinfo["org"].split(" ", 1)
            sweep_target = org_parts[1] if len(org_parts) > 1 else None

        e.add_field(name="\u200b",
            value=f"**── Breach Sweep{' on `' + sweep_target + '`' if sweep_target else ''} ──**",
            inline=False)

        if sweep_target:
            # Check HIBP for domain breaches
            hd = HIBP_HEADERS()
            all_breaches = await safe_get(self._session,
                "https://haveibeenpwned.com/api/v3/breaches", headers=hd)
            if isinstance(all_breaches, list):
                domain_hits = [b for b in all_breaches
                               if sweep_target.lower() in b.get("Domain","").lower()
                               or sweep_target.lower() in b.get("Name","").lower()]
                if domain_hits:
                    lines = [f"🔴 `{b.get('Name','?')}` — {b.get('BreachDate','?')} — {b.get('PwnCount',0):,} accts"
                             for b in domain_hits[:10]]
                    e.add_field(name=f"💀 Related Breaches ({len(domain_hits)})",
                        value="\n".join(lines), inline=False)
                    e.color = discord.Color.red()
                else:
                    e.add_field(name="✅ Breach Sweep", value=f"No HIBP breaches tied to `{sweep_target}`", inline=True)
        else:
            e.add_field(name="⚠️ Breach Sweep", value="Could not resolve hostname for breach pivot", inline=True)

        await interaction.followup.send(embed=e)

    # ── /wifi ─────────────────────────────────────────────────────────────────
    @app_commands.command(name="wifi", description="WiFi OSINT — Wigle SSID/BSSID + MAC vendor + breach sweep")
    @app_commands.describe(query="SSID name or BSSID (AA:BB:CC:DD:EE:FF)")
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

        # Run Wigle, MAC vendor, and breach sweep concurrently
        # Breach sweep: SSID as a "username" — some breaches expose network names
        wigle_data, vendor_data, sweep = await asyncio.gather(
            safe_get(self._session,
                "https://api.wigle.net/api/v2/network/search?" + urllib.parse.urlencode(params),
                headers={"Authorization": f"Basic {auth_str}"}),
            safe_get(self._session,
                f"https://api.macvendors.com/{urllib.parse.quote(oui)}") if is_bssid else asyncio.sleep(0),
            username_breach_sweep(self._session, query.replace(":", "").replace("-", "")),
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
                e.add_field(name="🔒 Encryption Breakdown",
                    value="\n".join(f"`{k}`: {v}" for k,v in sorted(enc_counts.items(),key=lambda x:-x[1])),
                    inline=True)

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
            e.description = "❌ No Wigle results — check WIGLE_API_NAME / WIGLE_API_TOKEN secrets"
            e.color = discord.Color.red()

        # Breach sweep on SSID/BSSID identifier
        e.add_field(name="\u200b", value=f"**── Breach Sweep on `{query}` ──**", inline=False)
        if sweep:
            render_breach_fields(e, sweep)
        else:
            e.add_field(name="✅ Breach Sweep", value="No breach hits for this identifier", inline=True)

        await interaction.followup.send(embed=e)


async def setup(bot: commands.Bot):
    await bot.add_cog(OSINTCog(bot))
