#!/usr/bin/env python3
"""
Suno Song & Media Downloader
Supports:
  - Song URLs (https://suno.com/song/<uuid>)
  - Share shortlinks (https://suno.com/s/<shortcode>)
  - Playlists (https://suno.com/playlist/<uuid>)
  - Raw UUIDs

Features:
  - Full Suno "Mango" DRM decryption (AES-GCM + AES-CTR)
  - Lossless audio download (.m4a)
  - Optional auto-conversion to 320kbps MP3 (--mp3) via ffmpeg
  - Unicode path safety (Khmer, Japanese, Chinese, etc.)
  - High-res cover art download (--cover)
  - Lyrics & metadata saving (--lyrics)
  - Interactive mode if run without arguments
  - Auto Telegram bot notification when a download finishes (--tg-token / --tg-chat)

Usage:
  python suno_downloader.py https://suno.com/s/b0pn5r9CKE6ygUJ9
  python suno_downloader.py --all https://suno.com/song/<id>
  python suno_downloader.py -f links.txt -o my_songs --mp3 --cover --lyrics

Telegram auto-notify (set once, then it sends automatically after every download):
  1) Create a bot with @BotFather -> copy the token
  2) Send any message to your bot (or add it to a group/channel), get your chat id
  3) Provide credentials in ONE of these ways (priority top -> bottom):
       - CLI:  --tg-token 123:ABC --tg-chat 123456789
       - Env:  SUNO_TG_TOKEN / SUNO_TG_CHAT_ID
       - File: telegram_config.json next to this script
               {"token": "123:ABC", "chat_id": "123456789"}
  Extra: music file is uploaded to Telegram automatically (max 50 MB)
         --tg-no-file  send text notification only, no file upload
         --tg-test   send a test message and exit
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

# Make console output safe for Khmer / emoji on Windows (cp1252 etc.)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Referer": "https://suno.com/",
    "Origin": "https://suno.com",
}


# --------------------------------------------------------------------------- #
# Telegram notifier
# --------------------------------------------------------------------------- #
TG_CONFIG_FILE = Path(__file__).resolve().parent / "telegram_config.json"
TG_MAX_UPLOAD = 50 * 1024 * 1024  # Bot API upload limit (50 MB)


def load_telegram_config(cli_token: str | None = None, cli_chat: str | None = None) -> tuple[str, str]:
    """Resolve Telegram credentials: CLI > environment > telegram_config.json."""
    token = (cli_token or os.environ.get("SUNO_TG_TOKEN") or "").strip()
    chat_id = (cli_chat or os.environ.get("SUNO_TG_CHAT_ID") or "").strip()

    if (not token or not chat_id) and TG_CONFIG_FILE.exists():
        try:
            cfg = json.loads(TG_CONFIG_FILE.read_text(encoding="utf-8"))
            token = token or str(cfg.get("token", "")).strip()
            chat_id = chat_id or str(cfg.get("chat_id", "")).strip()
        except (OSError, ValueError) as e:
            print(f"[!] Could not read {TG_CONFIG_FILE.name}: {e}")

    # Token known but chat id missing -> try to detect it from the bot's latest message
    if token and not chat_id:
        chat_id = detect_chat_id(token)
        if chat_id:
            try:
                TG_CONFIG_FILE.write_text(
                    json.dumps({"token": token, "chat_id": chat_id}, indent=2),
                    encoding="utf-8",
                )
                print(f"[*] Telegram chat id detected ({chat_id}) and saved to {TG_CONFIG_FILE.name}")
            except OSError:
                pass
        else:
            print("[!] Telegram chat id not set. Open your bot in Telegram, press Start / send any "
                  "message, then run again (the chat id is detected automatically).")
    return token, chat_id


def detect_chat_id(token: str) -> str:
    """Find the chat id of whoever last messaged the bot (getUpdates)."""
    try:
        r = requests.get(f"https://api.telegram.org/bot{token}/getUpdates", timeout=15)
        if r.status_code != 200:
            return ""
        for upd in reversed(r.json().get("result", [])):
            msg = upd.get("message") or upd.get("channel_post") or upd.get("edited_message") or {}
            chat = msg.get("chat") or {}
            if chat.get("id") is not None:
                return str(chat["id"])
    except (requests.RequestException, ValueError):
        pass
    return ""


class TelegramNotifier:
    """Sends status messages / files to a Telegram bot chat. Never raises."""

    def __init__(self, token: str = "", chat_id: str = "", send_files: bool = True):
        self.token = token
        self.chat_id = chat_id
        self.send_files = send_files

    @property
    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    def _call(self, method: str, data: dict, files: dict | None = None, timeout: int = 60) -> bool:
        url = f"https://api.telegram.org/bot{self.token}/{method}"
        for attempt in range(2):
            try:
                if files:
                    # rewind file handles so a retry re-sends the whole file
                    for _name, fh in files.values():
                        fh.seek(0)
                r = requests.post(url, data=data, files=files, timeout=timeout)
                if r.status_code == 200:
                    return True
                if r.status_code == 429 and attempt == 0:  # rate limited -> wait & retry
                    try:
                        wait = int(r.json().get("parameters", {}).get("retry_after", 3))
                    except Exception:
                        wait = 3
                    time.sleep(min(wait, 30))
                    continue
                try:
                    desc = r.json().get("description", r.text[:120])
                except Exception:
                    desc = r.text[:120]
                print(f" [!] Telegram error ({r.status_code}): {desc}")
                return False
            except requests.RequestException as e:
                print(f" [!] Telegram request failed: {e}")
                return False
        return False

    def send_message(self, text: str) -> bool:
        if not self.enabled:
            return False
        return self._call(
            "sendMessage",
            {
                "chat_id": self.chat_id,
                "text": text[:4000],
                "parse_mode": "HTML",
                "disable_web_page_preview": "true",
            },
            timeout=20,
        )

    def send_audio(self, path: Path, title: str, caption: str = "") -> bool:
        if not self.enabled:
            return False
        if path.stat().st_size > TG_MAX_UPLOAD:
            print(f" [!] Telegram: {path.name} is larger than 50 MB, skipping upload.")
            return False
        is_audio = path.suffix.lower() in (".mp3", ".m4a")
        method, field = ("sendAudio", "audio") if is_audio else ("sendDocument", "document")
        data = {"chat_id": self.chat_id, "caption": caption[:1000], "parse_mode": "HTML"}
        if is_audio:
            data["title"] = title[:64]
        # ASCII-safe upload name (Khmer/Unicode names can break multipart headers);
        # Telegram displays `title` for audio anyway.
        upload_name = re.sub(r"[^A-Za-z0-9._-]+", "_", path.stem)[:40].strip("_") or "song"
        with open(path, "rb") as fh:
            return self._call(method, data, files={field: (upload_name + path.suffix, fh)}, timeout=300)

    # ---- high level helpers ------------------------------------------------ #
    def send_photo(self, path: Path, caption: str = "") -> bool:
        if not self.enabled or not path.exists() or path.stat().st_size > 10 * 1024 * 1024:
            return False
        with open(path, "rb") as fh:
            return self._call(
                "sendPhoto",
                {"chat_id": self.chat_id, "caption": caption[:1000], "parse_mode": "HTML"},
                files={"photo": ("cover" + (path.suffix or ".jpeg"), fh)},
                timeout=120,
            )

    @staticmethod
    def _split_text(text: str, limit: int = 3500) -> list[str]:
        """Split long text on line boundaries; `limit` is measured AFTER HTML escaping."""
        esc = lambda x: len(html.escape(x))  # noqa: E731
        parts, cur = [], ""
        for line in text.splitlines():
            while esc(line) > limit:  # a single huge line
                cut = max(1, limit // 6)
                while esc(line[: cut * 2]) <= limit and cut * 2 < len(line):
                    cut *= 2
                if cur:
                    parts.append(cur)
                    cur = ""
                parts.append(line[:cut])
                line = line[cut:]
            if esc(cur) + esc(line) + 1 > limit and cur:
                parts.append(cur)
                cur = ""
            cur += line + "\n"
        if cur.strip():
            parts.append(cur)
        return [x.rstrip("\n") for x in parts]

    def notify_song_done(
        self,
        song_id: str,
        title: str,
        audio_path: Path | None,
        extras: list[str],
        description: str = "",
        cover_path: Path | None = None,
    ) -> None:
        """Send: [Img + Title(copy)] -> [Title(copy) + Description(copy)] -> [music file]."""
        if not self.enabled:
            return
        t = html.escape(title)

        # 1) Image (cover) with the title - tap the code block to copy
        head = f"✅ <b>Download finished</b>\n<b>Title:</b> <code>{t}</code>"
        if cover_path and cover_path.exists() and self.send_photo(cover_path, head):
            print(" [ok] Telegram: image sent")
        elif self.send_message(head):
            print(" [ok] Telegram: notification sent")

        # 2) Title + Description as tap-to-copy blocks (long text is split in parts)
        blocks = [f"<b>Title:</b>\n<code>{t}</code>"]
        if description.strip():
            chunks = self._split_text(description)
            for i, chunk in enumerate(chunks, 1):
                label = "Description" if len(chunks) == 1 else f"Description ({i}/{len(chunks)})"
                blocks.append(f"<b>{label}:</b>\n<code>{html.escape(chunk)}</code>")
        # first message carries the title + first description part, rest follow separately
        if len(blocks) >= 2:
            msgs = ["\n\n".join(blocks[:2])] + blocks[2:]
        else:
            msgs = blocks
        for m in msgs:
            self.send_message(m)

        # 3) Music file
        info = []
        if audio_path and audio_path.exists():
            info.append(f"📁 {html.escape(audio_path.name)} ({audio_path.stat().st_size / (1024 * 1024):.2f} MB)")
        if extras:
            info.append("➕ " + ", ".join(extras))
        info.append(f"🔗 https://suno.com/song/{song_id}")
        caption = f"🎵 <b>{t}</b>\n" + "\n".join(info)
        if self.send_files and audio_path and audio_path.exists():
            if self.send_audio(audio_path, title, caption=caption):
                print(" [ok] Telegram: music file sent")
                return
        self.send_message(caption)

    def notify_song_failed(self, song_id: str, title: str) -> None:
        if not self.enabled:
            return
        self.send_message(
            "❌ <b>Download failed</b>\n"
            f"🎵 {html.escape(title)}\n"
            f"🔗 https://suno.com/song/{song_id}"
        )

    def notify_batch_done(self, ok: int, total: int, out_dir: Path) -> None:
        if not self.enabled:
            return
        icon = "🎉" if ok == total else "⚠️"
        if self.send_message(
            f"{icon} <b>All downloads finished</b>\n"
            f"✔ Success: {ok}/{total}\n"
            f"📂 {html.escape(str(out_dir.resolve()))}"
        ):
            print(" [ok] Telegram: summary sent")


def build_description(info: dict) -> str:
    """Description text for copy/paste: style tags + lyrics (prompt)."""
    parts = []
    if info.get("tags"):
        parts.append(f"Style: {info['tags']}")
    if info.get("prompt"):
        parts.append(info["prompt"].strip())
    return "\n\n".join(parts)


def has_ffmpeg() -> bool:
    """Check if ffmpeg executable is available in PATH."""
    return shutil.which("ffmpeg") is not None


def safe_name(name: str) -> str:
    """Sanitize string for Windows and Unix file paths."""
    cleaned = re.sub(r'[\\/:*?"<>|]+', "_", name).strip()
    return cleaned[:120] or "song"


def get_unique_path(base_path: Path) -> Path:
    """Ensure base_path doesn't overwrite an existing file."""
    if not base_path.exists():
        return base_path
    stem = base_path.stem
    suffix = base_path.suffix
    counter = 1
    while True:
        candidate = base_path.parent / f"{stem} ({counter}){suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def resolve_playlist(playlist_id: str) -> list[str]:
    """Fetch all clip IDs belonging to a public playlist."""
    print(f"[*] Fetching playlist: {playlist_id}...")
    for api_host in ["studio-api.prod.suno.com", "studio-api.suno.ai"]:
        ids: list[str] = []
        try:
            for page in range(1, 51):  # up to 50 pages
                url = f"https://{api_host}/api/playlist/{playlist_id}/?page={page}"
                r = requests.get(url, headers=HEADERS, timeout=15)
                if r.status_code != 200:
                    break
                clips = r.json().get("playlist_clips", [])
                page_ids = [
                    item["clip"]["id"]
                    for item in clips
                    if item.get("clip") and "id" in item["clip"]
                ]
                new_ids = [i for i in page_ids if i not in ids]
                if not new_ids:
                    break
                ids.extend(new_ids)
        except (requests.RequestException, ValueError):
            pass
        if ids:
            print(f"[*] Found {len(ids)} track(s) in playlist.")
            return ids

    # Fallback to HTML scrape
    try:
        r = requests.get(f"https://suno.com/playlist/{playlist_id}", headers=HEADERS, timeout=15)
        if r.status_code == 200:
            found = UUID_RE.findall(r.text)
            unique = [
                uid.lower() for uid in dict.fromkeys(found) if uid.lower() != playlist_id.lower()
            ]
            if unique:
                print(f"[*] Found {len(unique)} track(s) on playlist page.")
                return unique
    except requests.RequestException:
        pass

    return []


def resolve_item_to_ids(item: str) -> list[str]:
    """Extract Suno clip UUIDs from URL, shortlink, playlist, or raw ID."""
    item = item.strip()
    if not item:
        return []

    # Direct playlist link with UUID
    if "playlist" in item:
        m = UUID_RE.search(item)
        if m:
            return resolve_playlist(m.group(0).lower())

    # Direct UUID in text
    m = UUID_RE.search(item)
    if m:
        return [m.group(0).lower()]

    # URL or shortlink (e.g. https://suno.com/s/xxxx)
    if item.startswith("http://") or item.startswith("https://") or "suno.com" in item:
        url = item if item.startswith("http") else f"https://{item}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=15, allow_redirects=True)
            if "playlist" in r.url:
                pm = UUID_RE.search(r.url)
                if pm:
                    return resolve_playlist(pm.group(0).lower())

            found = UUID_RE.findall(r.url) + UUID_RE.findall(r.text)
            if found:
                return [found[0].lower()]
        except requests.RequestException as e:
            print(f"[!] Failed to resolve URL '{item}': {e}")

    return []


def fetch_clip_details(song_id: str) -> dict:
    """Fetch complete metadata and media URLs from Suno's studio API."""
    metadata = {
        "id": song_id,
        "title": song_id,
        "audio_sources": [],
        "image_url": None,
        "video_url": None,
        "prompt": "",
        "tags": "",
        "created_at": "",
    }

    try:
        r = requests.get(
            f"https://studio-api.prod.suno.com/api/clip/{song_id}",
            headers=HEADERS,
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("title"):
                metadata["title"] = data["title"].strip()

            meta = data.get("metadata", {})
            metadata["prompt"] = meta.get("prompt", "")
            metadata["tags"] = meta.get("tags", "") or data.get("display_tags", "")
            metadata["created_at"] = data.get("created_at", "")

            # Cover artwork
            metadata["image_url"] = (
                data.get("image_large_url")
                or data.get("image_url")
                or f"https://cdn2.suno.ai/image_{song_id}.jpeg"
            )

            # Video clip
            if data.get("video_url"):
                metadata["video_url"] = data["video_url"]

            # Progressive audio streams (media_urls)
            for m in data.get("media_urls", []):
                if m.get("url"):
                    metadata["audio_sources"].append({
                        "url": m["url"],
                        "encrypted": bool(m.get("encoding")),
                    })

            # Legacy audio_url if accessible
            if data.get("audio_url") and "forbidden" not in data["audio_url"]:
                metadata["audio_sources"].append({
                    "url": data["audio_url"],
                    "encrypted": False,
                })
    except requests.RequestException:
        pass

    # Fallback CDN endpoints
    metadata["audio_sources"].extend([
        {"url": f"https://cdn1.suno.ai/{song_id}.mp3", "encrypted": False},
        {"url": f"https://audiopipe.suno.ai/?item_id={song_id}", "encrypted": False},
    ])

    return metadata


def decrypt_mango_audio(song_id: str, encrypted_bytes: bytes) -> bytes | None:
    """Decrypt Suno Mango DRM encrypted audio using AES-GCM + AES-CTR."""
    if not HAS_CRYPTO:
        print(" [!] cryptography package required for DRM decryption. (pip install cryptography)")
        return None

    try:
        # 1. Fetch license from Mango rights server
        rights_url = "https://studio-api.prod.suno.com/api/mango/rights"
        resp = requests.post(
            rights_url,
            json={"content_params": {"content_id": song_id, "content_type": "clip"}},
            headers={**HEADERS, "Content-Type": "application/json"},
            timeout=15,
        )
        if resp.status_code != 200:
            print(f" [!] Mango license error (HTTP {resp.status_code})")
            return None

        rights_data = resp.json()
        glt = rights_data["glt"]
        key_b64 = rights_data["key"]
        iv_b64 = rights_data["iv"]

        # 2. Derive master key = SHA-256(glt)
        master_key = hashlib.sha256(glt.encode("utf-8")).digest()
        aes_gcm = AESGCM(master_key)
        aad = song_id.encode("utf-8")

        # 3. Decrypt file key
        raw_key = base64.b64decode(key_b64)
        file_key = aes_gcm.decrypt(raw_key[:12], raw_key[12:], aad)

        # 4. Decrypt file IV
        raw_iv = base64.b64decode(iv_b64)
        file_iv = aes_gcm.decrypt(raw_iv[:12], raw_iv[12:], aad)

        # 5. Decrypt full payload via AES-CTR
        cipher = Cipher(algorithms.AES(file_key), modes.CTR(file_iv))
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_bytes) + decryptor.finalize()
    except Exception as e:
        print(f" [!] DRM decryption error: {e}")
        return None


def convert_to_mp3_safely(source_file: Path, delete_source: bool = False) -> Path:
    """Convert audio file to 320k MP3 using ffmpeg with Unicode path safety."""
    mp3_file = get_unique_path(source_file.with_suffix(".mp3"))
    
    # Use temporary ASCII paths to prevent Windows console encoding issues with Unicode filenames in ffmpeg
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_in = Path(tmp_dir) / f"input{source_file.suffix}"
        tmp_out = Path(tmp_dir) / "output.mp3"
        shutil.copy(source_file, tmp_in)

        cmd = [
            "ffmpeg",
            "-y",
            "-i",
            str(tmp_in),
            "-vn",
            "-c:a",
            "libmp3lame",
            "-b:a",
            "320k",
            str(tmp_out),
        ]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0 and tmp_out.exists():
            shutil.move(tmp_out, mp3_file)
            print(f" [ok] Converted to MP3 (320k): {mp3_file.name}")
            if delete_source:
                source_file.unlink(missing_ok=True)
            return mp3_file

    print(" [!] ffmpeg conversion failed; keeping original file.")
    return source_file


def download_song(
    song_id: str,
    out_dir: Path,
    convert_mp3: bool = False,
    save_cover: bool = False,
    save_lyrics: bool = False,
    save_video: bool = False,
    notifier: "TelegramNotifier | None" = None,
    on_result=None,
) -> bool:
    """Download audio, cover, lyrics, and video for a single Suno track."""
    info = fetch_clip_details(song_id)
    title = safe_name(info["title"])
    print(f"\n▶ [{title}] ({song_id})")

    audio_saved = False
    saved_audio_path = None
    extras: list[str] = []
    cover_path: Path | None = None
    # the cover is also needed for the Telegram image / GUI preview
    want_cover = save_cover or bool(notifier and notifier.enabled) or on_result is not None

    # 1. Download Audio
    for src in info["audio_sources"]:
        url = src["url"]
        is_encrypted = src["encrypted"]

        try:
            with requests.get(url, headers=HEADERS, stream=True, timeout=30) as r:
                if r.status_code == 200:
                    raw_content = r.content
                    if is_encrypted:
                        print(" [*] Decrypting audio stream (Mango DRM)...")
                        decrypted = decrypt_mango_audio(song_id, raw_content)
                        if not decrypted:
                            continue
                        raw_content = decrypted

                    ext = ".m4a" if (b"ftyp" in raw_content[:32] or ".m4a" in url) else ".mp3"
                    dest = get_unique_path(out_dir / f"{title}{ext}")
                    dest.write_bytes(raw_content)
                    print(f" [ok] Audio: {dest.name}")
                    audio_saved = True
                    saved_audio_path = dest
                    break
        except requests.RequestException:
            continue

    if not audio_saved:
        print(f" [x] Failed to download audio for {song_id}")
        if notifier:
            notifier.notify_song_failed(song_id, info["title"])
        return False

    # 2. Convert to MP3 if requested
    if convert_mp3 and saved_audio_path and saved_audio_path.suffix.lower() == ".m4a":
        if has_ffmpeg():
            saved_audio_path = convert_to_mp3_safely(saved_audio_path, delete_source=True)
        else:
            print(" [!] ffmpeg not found in PATH; keeping original .m4a")

    # 3. Save Cover Artwork
    if want_cover and info.get("image_url"):
        img_dest = get_unique_path(out_dir / f"{title}.jpeg")
        try:
            with requests.get(info["image_url"], headers=HEADERS, timeout=15) as r:
                if r.status_code == 200:
                    img_dest.write_bytes(r.content)
                    print(f" [ok] Cover: {img_dest.name}")
                    extras.append("Cover")
                    cover_path = img_dest
        except requests.RequestException as e:
            print(f" [!] Cover download failed: {e}")

    # 4. Save Lyrics & Metadata
    if save_lyrics and (info.get("prompt") or info.get("tags")):
        txt_dest = get_unique_path(out_dir / f"{title}_lyrics.txt")
        content = [
            f"Title: {info['title']}",
            f"ID: {song_id}",
        ]
        if info.get("tags"):
            content.append(f"Style / Tags: {info['tags']}")
        if info.get("created_at"):
            content.append(f"Created: {info['created_at']}")
        content.append("\n" + "=" * 40 + "\n[Lyrics / Prompt]\n" + "=" * 40 + "\n")
        content.append(info.get("prompt", "(No lyrics/prompt provided)"))

        txt_dest.write_text("\n".join(content), encoding="utf-8")
        print(f" [ok] Lyrics: {txt_dest.name}")
        extras.append("Lyrics")

    # 5. Save Video (if available)
    if save_video and info.get("video_url"):
        vid_dest = get_unique_path(out_dir / f"{title}.mp4")
        try:
            with requests.get(info["video_url"], headers=HEADERS, stream=True, timeout=60) as r:
                if r.status_code == 200:
                    vid_dest.write_bytes(r.content)
                    print(f" [ok] Video: {vid_dest.name}")
                    extras.append("Video")
        except requests.RequestException as e:
            print(f" [!] Video download failed: {e}")

    description = build_description(info)

    # 6. Hand result (Title / Description / Img) to the caller, e.g. the GUI
    if on_result:
        try:
            on_result({
                "id": song_id,
                "title": info["title"],
                "description": description,
                "cover": cover_path,
                "audio": saved_audio_path,
            })
        except Exception as e:
            print(f" [!] Result callback error: {e}")

    # 7. Auto-notify Telegram (download finished)
    if notifier:
        notifier.notify_song_done(
            song_id, info["title"], saved_audio_path, extras,
            description=description, cover_path=cover_path,
        )

    return True


def interactive_mode(
    out_dir: Path,
    convert_mp3: bool,
    save_cover: bool,
    save_lyrics: bool,
    notifier: "TelegramNotifier | None" = None,
    save_video: bool = False,
):
    """Loop interactively prompting user for URLs until exit."""
    print("\n" + "=" * 52)
    print("      Suno Downloader - Interactive Mode")
    print("  Paste URL / shortlink / ID (or type 'exit' to quit)")
    print("=" * 52)
    if notifier and notifier.enabled:
        print("  Telegram auto-notify: ON")

    while True:
        try:
            user_input = input("\nSuno Link > ").strip()
            if not user_input or user_input.lower() in ("exit", "quit", "q"):
                print("Exiting...")
                break

            items = user_input.split()
            ids = []
            for it in items:
                ids.extend(resolve_item_to_ids(it))

            unique_ids = list(dict.fromkeys(ids))
            if not unique_ids:
                print("[!] No valid Suno link or ID detected. Try again.")
                continue

            for sid in unique_ids:
                download_song(
                    sid,
                    out_dir,
                    convert_mp3=convert_mp3,
                    save_cover=save_cover,
                    save_lyrics=save_lyrics,
                    save_video=save_video,
                    notifier=notifier,
                )
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break


# --------------------------------------------------------------------------- #
# Built-in GUI (tkinter, dark theme) - launched with --gui
# --------------------------------------------------------------------------- #
class _QueueWriter:
    """File-like object that forwards print() output to a queue (for the GUI log)."""

    def __init__(self, q):
        self.q = q

    def write(self, text):
        if text:
            self.q.put(text)

    def flush(self):
        pass


def run_gui():
    import queue
    import threading
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext

    BG, PANEL, FG, ACCENT, ENTRY = "#14161c", "#1e212b", "#e6e8ee", "#7c5cff", "#262a36"

    root = tk.Tk()
    root.title("Suno Downloader")
    root.geometry("860x860")
    root.configure(bg=BG)

    tg_token0, tg_chat0 = load_telegram_config()
    out_var = tk.StringVar(value=str(Path("suno_downloads").resolve()))
    v_mp3, v_cover, v_lyrics, v_video = (tk.BooleanVar(value=True), tk.BooleanVar(value=True),
                                         tk.BooleanVar(value=True), tk.BooleanVar(value=False))
    v_tg, v_tgfile = tk.BooleanVar(value=bool(tg_token0 and tg_chat0)), tk.BooleanVar(value=True)
    token_var, chat_var = tk.StringVar(value=tg_token0), tk.StringVar(value=tg_chat0)
    log_q: "queue.Queue[str]" = queue.Queue()
    res_q: "queue.Queue[dict]" = queue.Queue()
    running = {"on": False}

    def lbl(parent, text, **kw):
        return tk.Label(parent, text=text, bg=kw.pop("bg", BG), fg=FG, **kw)

    def chk(parent, text, var):
        return tk.Checkbutton(parent, text=text, variable=var, bg=BG, fg=FG, selectcolor=ENTRY,
                              activebackground=BG, activeforeground=FG)

    def entry(parent, var, **kw):
        return tk.Entry(parent, textvariable=var, bg=ENTRY, fg=FG, insertbackground=FG,
                        relief="flat", **kw)

    lbl(root, "Suno links / IDs / playlists (one per line)", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=14, pady=(12, 2))
    links_box = scrolledtext.ScrolledText(root, height=7, bg=ENTRY, fg=FG, insertbackground=FG, relief="flat")
    links_box.pack(fill="x", padx=14)

    row = tk.Frame(root, bg=BG)
    row.pack(fill="x", padx=14, pady=8)
    lbl(row, "Save to:").pack(side="left")
    entry(row, out_var).pack(side="left", fill="x", expand=True, padx=6, ipady=3)
    tk.Button(row, text="Browse", bg=PANEL, fg=FG, relief="flat",
              command=lambda: out_var.set(filedialog.askdirectory() or out_var.get())).pack(side="left")

    opts = tk.Frame(root, bg=BG)
    opts.pack(fill="x", padx=14)
    for text, var in (("MP3 320k", v_mp3), ("Cover", v_cover), ("Lyrics", v_lyrics), ("Video", v_video)):
        chk(opts, text, var).pack(side="left", padx=(0, 12))

    tgf = tk.LabelFrame(root, text=" Telegram bot ", bg=BG, fg=FG)
    tgf.pack(fill="x", padx=14, pady=10)
    chk(tgf, "Auto send when download finished", v_tg).grid(row=0, column=0, columnspan=2, sticky="w", padx=6)
    chk(tgf, "Send music file", v_tgfile).grid(row=0, column=2, sticky="w")
    lbl(tgf, "Bot token").grid(row=1, column=0, sticky="w", padx=6)
    entry(tgf, token_var, show="*").grid(row=1, column=1, columnspan=2, sticky="ew", padx=6, pady=3, ipady=3)
    lbl(tgf, "Chat ID").grid(row=2, column=0, sticky="w", padx=6)
    entry(tgf, chat_var).grid(row=2, column=1, columnspan=2, sticky="ew", padx=6, pady=3, ipady=3)
    tgf.columnconfigure(1, weight=1)

    # ---- Result panel: Img + Title (copy) + Description (copy) ----
    resf = tk.LabelFrame(root, text=" Result ", bg=BG, fg=FG)
    resf.pack(fill="x", padx=14, pady=(0, 6))
    img_lbl = tk.Label(resf, text="Img", bg=ENTRY, fg=FG, width=18, height=8)
    img_lbl.grid(row=0, column=0, rowspan=4, padx=6, pady=6)
    res_title, res_desc_hint = tk.StringVar(), tk.StringVar()

    def copy_text(text: str, btn: "tk.Button", label: str = "Copy"):
        root.clipboard_clear()
        root.clipboard_append(text)
        btn.configure(text="Copied!")
        root.after(1200, lambda: btn.configure(text=label))

    lbl(resf, "Title:").grid(row=0, column=1, sticky="w")
    entry(resf, res_title).grid(row=0, column=2, sticky="ew", padx=6, ipady=3)
    title_btn = tk.Button(resf, text="Copy", bg=PANEL, fg=FG, relief="flat",
                          command=lambda: copy_text(res_title.get(), title_btn))
    title_btn.grid(row=0, column=3, padx=6)
    lbl(resf, "Description:").grid(row=1, column=1, sticky="nw")
    desc_box = tk.Text(resf, height=5, bg=ENTRY, fg=FG, insertbackground=FG, relief="flat", wrap="word")
    desc_box.grid(row=1, column=2, rowspan=2, sticky="ew", padx=6, pady=3)
    desc_btn = tk.Button(resf, text="Copy", bg=PANEL, fg=FG, relief="flat",
                         command=lambda: copy_text(desc_box.get("1.0", "end").strip(), desc_btn))
    desc_btn.grid(row=1, column=3, padx=6, sticky="n")
    resf.columnconfigure(2, weight=1)
    img_ref = {"img": None}

    def show_result(r: dict):
        res_title.set(r.get("title", ""))
        desc_box.delete("1.0", "end")
        desc_box.insert("1.0", r.get("description", ""))
        img_ref["img"] = None
        cover = r.get("cover")
        try:
            from PIL import Image, ImageTk  # optional: pip install pillow
            im = Image.open(cover)
            im.thumbnail((170, 170))
            img_ref["img"] = ImageTk.PhotoImage(im)
            img_lbl.configure(image=img_ref["img"], text="", width=170, height=170)
        except Exception:
            img_lbl.configure(image="", text="Img\n(install pillow\nfor preview)", width=18, height=8)

    log = scrolledtext.ScrolledText(root, height=9, bg="#0d0f14", fg="#b8f7c5", state="disabled", relief="flat")
    log.pack(fill="both", expand=True, padx=14, pady=(4, 8))

    def pump():
        try:
            while True:
                text = log_q.get_nowait()
                log.configure(state="normal")
                log.insert("end", text)
                log.see("end")
                log.configure(state="disabled")
        except queue.Empty:
            pass
        try:
            while True:
                show_result(res_q.get_nowait())
        except queue.Empty:
            pass
        root.after(100, pump)

    def worker(items, out_dir, notifier):
        old_out = sys.stdout
        sys.stdout = _QueueWriter(log_q)
        try:
            ids = []
            for it in items:
                ids.extend(resolve_item_to_ids(it))
            ids = list(dict.fromkeys(ids))
            if not ids:
                print("[!] No valid Suno link or ID found.")
                return
            print(f"[*] Starting download of {len(ids)} track(s)...")
            ok = 0
            for sid in ids:
                if download_song(sid, out_dir, convert_mp3=v_mp3.get(), save_cover=v_cover.get(),
                                 save_lyrics=v_lyrics.get(), save_video=v_video.get(), notifier=notifier,
                                 on_result=res_q.put):
                    ok += 1
            print(f"\nFinished: {ok}/{len(ids)} track(s) downloaded.\nDestination: {out_dir}")
            if len(ids) > 1:
                notifier.notify_batch_done(ok, len(ids), out_dir)
        except Exception as e:  # keep the GUI alive on unexpected errors
            print(f"[x] Unexpected error: {e}")
        finally:
            sys.stdout = old_out
            running["on"] = False
            start_btn.configure(state="normal", text="Start Download")

    def start():
        if running["on"]:
            return
        items = [ln.strip() for ln in links_box.get("1.0", "end").splitlines() if ln.strip()]
        if not items:
            messagebox.showwarning("Suno Downloader", "Please paste at least one Suno link or ID.")
            return
        out_dir = Path(out_var.get()).expanduser()
        out_dir.mkdir(parents=True, exist_ok=True)
        token, chat = token_var.get().strip(), chat_var.get().strip()
        if v_tg.get() and token and not chat:
            chat = detect_chat_id(token)
            chat_var.set(chat)
        if token and chat:
            try:
                TG_CONFIG_FILE.write_text(json.dumps({"token": token, "chat_id": chat}, indent=2), encoding="utf-8")
            except OSError:
                pass
        notifier = TelegramNotifier(token if v_tg.get() else "", chat, send_files=v_tgfile.get())
        running["on"] = True
        start_btn.configure(state="disabled", text="Downloading...")
        threading.Thread(target=worker, args=(items, out_dir, notifier), daemon=True).start()

    start_btn = tk.Button(root, text="Start Download", bg=ACCENT, fg="white", relief="flat",
                          font=("Segoe UI", 11, "bold"), command=start)
    start_btn.pack(fill="x", padx=14, pady=(0, 14), ipady=6)

    pump()
    root.mainloop()


def main():
    p = argparse.ArgumentParser(description="Download songs, lyrics, and art from Suno")
    p.add_argument("items", nargs="*", help="Song URLs, shortlinks, playlist URLs, or IDs")
    p.add_argument("-f", "--file", help="Text file with URLs/IDs (one per line)")
    p.add_argument("-o", "--out", default="suno_downloads", help="Output directory")
    p.add_argument("--gui", action="store_true", help="Launch the graphical user interface")
    p.add_argument("--mp3", action="store_true", help="Auto-convert audio to 320kbps MP3 (uses ffmpeg)")
    p.add_argument("--cover", action="store_true", help="Download high-resolution cover artwork")
    p.add_argument("--lyrics", action="store_true", help="Save prompt and lyrics as .txt file")
    p.add_argument("--video", action="store_true", help="Download MP4 video if available")
    p.add_argument("--all", action="store_true", help="Download audio (as MP3), cover art, and lyrics")
    p.add_argument("--tg-token", help="Telegram bot token (or env SUNO_TG_TOKEN)")
    p.add_argument("--tg-chat", help="Telegram chat id / @channel (or env SUNO_TG_CHAT_ID)")
    p.add_argument("--tg-file", action="store_true", help="(default ON) Upload the downloaded music file to Telegram (max 50 MB)")
    p.add_argument("--tg-no-file", action="store_true", help="Send only a text notification, do not upload the music file")
    p.add_argument("--tg-test", action="store_true", help="Send a Telegram test message and exit")
    args = p.parse_args()

    if args.gui:
        try:
            run_gui()
            return
        except ImportError as e:
            print(f"[!] Unable to launch GUI (tkinter missing?): {e}")
            sys.exit(1)

    # If --all is passed, enable mp3 conversion, cover, and lyrics
    if args.all:
        args.mp3 = True
        args.cover = True
        args.lyrics = True

    # Telegram auto-notify (enabled automatically when token + chat id are found)
    tg_token, tg_chat = load_telegram_config(args.tg_token, args.tg_chat)
    notifier = TelegramNotifier(tg_token, tg_chat, send_files=not args.tg_no_file)

    if args.tg_test:
        if not notifier.enabled:
            print("[!] Telegram token / chat id not set. Use --tg-token and --tg-chat.")
            sys.exit(1)
        ok = notifier.send_message("🔔 <b>Suno Downloader</b>: Telegram connection works!")
        print("[ok] Test message sent." if ok else "[x] Test message failed.")
        sys.exit(0 if ok else 1)

    if notifier.enabled:
        print("[*] Telegram auto-notify: ON" + ("" if args.tg_no_file else " (music file upload)"))

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_items = list(args.items)
    if args.file:
        file_path = Path(args.file)
        if file_path.exists():
            raw_items.extend(file_path.read_text(encoding="utf-8").splitlines())
        else:
            print(f"[!] Error: File '{args.file}' not found.")
            sys.exit(1)

    # If no items provided via CLI or file, launch interactive mode
    if not raw_items:
        interactive_mode(
            out_dir,
            convert_mp3=args.mp3,
            save_cover=args.cover,
            save_lyrics=args.lyrics,
            notifier=notifier,
            save_video=args.video,
        )
        return

    # Batch process CLI items
    song_ids = []
    for item in raw_items:
        song_ids.extend(resolve_item_to_ids(item))

    unique_ids = list(dict.fromkeys(song_ids))
    if not unique_ids:
        print("[!] No valid Suno song URLs or IDs found.")
        sys.exit(1)

    print(f"[*] Starting download of {len(unique_ids)} track(s)...")
    success_count = 0
    for sid in unique_ids:
        if download_song(
            sid,
            out_dir,
            convert_mp3=args.mp3,
            save_cover=args.cover,
            save_lyrics=args.lyrics,
            save_video=args.video,
            notifier=notifier,
        ):
            success_count += 1

    print(f"\n========================================")
    print(f"Finished: {success_count}/{len(unique_ids)} track(s) downloaded.")
    print(f"Destination: {out_dir.resolve()}")
    print(f"========================================")

    # Auto-notify Telegram: summary when the whole batch is finished
    if len(unique_ids) > 1:
        notifier.notify_batch_done(success_count, len(unique_ids), out_dir)


if __name__ == "__main__":
    main()
