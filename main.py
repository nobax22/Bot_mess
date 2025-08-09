#!/usr/bin/env python3
# coding: utf-8
"""
main.py - Telegram Cleaner Bot (POC) siap-deploy ke Railway
- Multi-user (user login nomor + OTP)
- Uses single API_ID/API_HASH (owner-provided) from env
- Session files per-user are encrypted (Fernet MASTER_KEY)
- Cleaner: full / media-only, date filter, safe mode
- Progress sent via editing bot message
- Not production-hardened: use as POC only
"""

import os
import asyncio
import logging
import pathlib
import json
from datetime import datetime
from typing import Optional, List, Dict

from cryptography.fernet import Fernet, InvalidToken
from telethon import TelegramClient, errors
from telethon.tl.types import User, Chat, Channel, Message

from telegram import Update
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler, filters,
    ContextTypes, ConversationHandler
)
from tqdm import tqdm
from dateutil import parser as dateparser  # requires python-dateutil

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("tc_bot")

# ---------- Config / Paths ----------
HOME = str(pathlib.Path.home())
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(HOME, ".tc_cleaner"))
os.makedirs(DATA_DIR, exist_ok=True)

SESSIONS_DIR = os.path.join(DATA_DIR, "sessions")
os.makedirs(SESSIONS_DIR, exist_ok=True)

# Env required
BOT_TOKEN = os.environ.get("BOT_TOKEN")
API_ID = os.environ.get("API_ID")
API_HASH = os.environ.get("API_HASH")
MASTER_KEY = os.environ.get("MASTER_KEY")  # fernet key as base64 str

if not BOT_TOKEN or not API_ID or not API_HASH or not MASTER_KEY:
    raise RuntimeError("Set env BOT_TOKEN, API_ID, API_HASH, MASTER_KEY before running")

# convert to proper types
API_ID = int(API_ID)

fernet = Fernet(MASTER_KEY.encode())

# ---------- In-memory registries ----------
# telethon clients currently loaded in memory: user_id -> TelegramClient
CLIENTS: Dict[int, TelegramClient] = {}
# locks to prevent concurrent use of same session
SESSION_LOCKS: Dict[int, asyncio.Lock] = {}

def get_lock_for_user(uid: int) -> asyncio.Lock:
    if uid not in SESSION_LOCKS:
        SESSION_LOCKS[uid] = asyncio.Lock()
    return SESSION_LOCKS[uid]

# ---------- Session encryption helpers ----------
def session_enc_path(uid: int) -> str:
    return os.path.join(SESSIONS_DIR, f"session_{uid}.session.enc")

def session_plain_path(uid: int) -> str:
    return os.path.join(SESSIONS_DIR, f"session_{uid}.session")  # used temporarily

def encrypt_session_file(uid: int):
    p = session_plain_path(uid)
    e = session_enc_path(uid)
    if not os.path.exists(p):
        return
    with open(p, "rb") as f:
        raw = f.read()
    token = fernet.encrypt(raw)
    with open(e, "wb") as f:
        f.write(token)
    try:
        os.remove(p)
    except Exception:
        pass

def decrypt_session_to_plain(uid: int) -> Optional[str]:
    e = session_enc_path(uid)
    p = session_plain_path(uid)
    if not os.path.exists(e):
        return None
    with open(e, "rb") as f:
        token = f.read()
    try:
        raw = fernet.decrypt(token)
    except InvalidToken:
        raise RuntimeError("Invalid MASTER_KEY or corrupted session for user %s" % uid)
    with open(p, "wb") as f:
        f.write(raw)
    return p

# ---------- Telethon client lifecycle ----------
async def create_and_connect_client_for_login(uid: int) -> TelegramClient:
    """Create Telethon client with plain session (temporary) for login flow."""
    path_plain = session_plain_path(uid)
    client = TelegramClient(path_plain, API_ID, API_HASH)
    await client.connect()
    CLIENTS[uid] = client
    return client

async def load_client_from_encrypted(uid: int) -> TelegramClient:
    """Decrypt session to plain, create client and connect."""
    # decrypt to plain
    plain = decrypt_session_to_plain(uid)
    if plain is None:
        raise RuntimeError("No saved session for this user")
    client = TelegramClient(plain, API_ID, API_HASH)
    await client.connect()
    CLIENTS[uid] = client
    return client

async def disconnect_client(uid: int):
    c = CLIENTS.get(uid)
    if c:
        try:
            if await c.is_connected():
                await c.disconnect()
        except Exception:
            pass
        CLIENTS.pop(uid, None)
    # remove plain if exists
    try:
        p = session_plain_path(uid)
        if os.path.exists(p):
            os.remove(p)
    except Exception:
        pass

# ---------- Helper: parse date ----------
def parse_date(s: str) -> Optional[datetime]:
    s = (s or "").strip()
    if not s:
        return None
    try:
        return dateparser.parse(s)
    except Exception:
        try:
            return datetime.strptime(s, "%Y-%m-%d")
        except Exception:
            return None

# ---------- Cleaner core (collect ids + delete batches) ----------
async def collect_message_ids(client: TelegramClient, entity, before: Optional[datetime], after: Optional[datetime], mode: str, safe_only: bool) -> List[int]:
    ids: List[int] = []
    async for msg in client.iter_messages(entity, reverse=False):
        if not hasattr(msg, "date") or msg.date is None:
            continue
        dt = msg.date.replace(tzinfo=None)
        if before and not (dt < before):
            continue
        if after and not (dt > after):
            continue
        if safe_only:
            if getattr(msg, "sender_id", None) != getattr(client, "_self_id", None):
                continue
        if mode == "media":
            if getattr(msg, "media", None):
                ids.append(msg.id)
        else:
            ids.append(msg.id)
    return ids

async def delete_batches(client: TelegramClient, entity, ids: List[int], batch_size: int, delay_seconds: float, progress_callback=None, name=""):
    deleted = 0
    skipped = 0
    total = len(ids)
    for i in range(0, total, batch_size):
        batch = ids[i:i+batch_size]
        try:
            res = await client.delete_messages(entity, batch)
            if isinstance(res, list):
                n = len(res)
            elif isinstance(res, bool):
                n = len(batch) if res else 0
            else:
                n = len(batch)
            deleted += n
            if progress_callback:
                progress_callback(n, total, name)
        except errors.FloodWaitError as fe:
            wait = fe.seconds + 1
            await asyncio.sleep(wait)
            try:
                res = await client.delete_messages(entity, batch)
                n = len(res) if isinstance(res, list) else (len(batch) if res else 0)
                deleted += n
                if progress_callback:
                    progress_callback(n, total, name)
            except Exception:
                skipped += len(batch)
        except Exception:
            skipped += len(batch)
        await asyncio.sleep(delay_seconds)
    return {"deleted": deleted, "skipped": skipped, "total": total}

# ---------- High-level runner (sequential per-target, limited concurrency) ----------
async def run_clean_all(client: TelegramClient, targets: List[dict], mode: str, before, after, safe_only: bool, batch_size: int, delay_seconds: float, concurrency: int, update_fn=None):
    sem = asyncio.Semaphore(concurrency)
    results = []
    # estimate totals
    total_est = 0
    for t in targets:
        cnt = 0
        async for _ in client.iter_messages(t["entity"], limit=None):
            cnt += 1
        t["_count"] = cnt
        total_est += cnt

    async def worker(t):
        async with sem:
            ids = await collect_message_ids(client, t["entity"], before, after, mode, safe_only)
            r = await delete_batches(client, t["entity"], ids, batch_size, delay_seconds, update_fn, t.get("name",""))
            return {"name": t.get("name",""), **r}

    tasks = [asyncio.create_task(worker(t)) for t in targets]
    for coro in asyncio.as_completed(tasks):
        r = await coro
        results.append(r)
    return {"results": results, "total_est": total_est}

# ---------- Bot conversation states ----------
( A_API_ID, A_API_HASH, A_PHONE, A_CODE ) = range(4)  # login flow (we won't request API ID/hash from user; kept for compatibility)
(C_MODE, C_BEFORE, C_SAFE) = range(10, 13)

# pending login storage: user_id -> dict
_pending_login: Dict[int, dict] = {}

# ---------- Telegram Bot Handlers ----------
from telegram import ForceReply

async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Halo! Saya Telegram Cleaner Bot.\nGunakan /login untuk login, /scan untuk lihat chat, /clean untuk bersihkan.")

# Login: here we only ask phone & OTP (we use server's API_ID/API_HASH)
async def login_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    await update.message.reply_text("Masukkan nomor telepon Anda (+62...):", reply_markup=ForceReply(selective=True))
    return A_PHONE

async def login_phone(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    phone = update.message.text.strip()
    # create client with plain session for this uid
    try:
        client = await create_client_for_login(uid)
    except Exception as e:
        await update.message.reply_text(f"Gagal buat client: {e}")
        return ConversationHandler.END
    _pending_login[uid] = {"client": client, "phone": phone}
    try:
        await client.send_code_request(phone)
    except Exception as e:
        await update.message.reply_text(f"Gagal mengirim kode OTP: {e}")
        return ConversationHandler.END
    await update.message.reply_text("Kode OTP sudah dikirim. Masukkan kode verifikasi:", reply_markup=ForceReply(selective=True))
    return A_CODE

async def login_code(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    entry = _pending_login.get(uid)
    if not entry:
        await update.message.reply_text("Tidak ada proses login aktif. Mulai ulang dengan /login.")
        return ConversationHandler.END
    code = update.message.text.strip()
    client = entry["client"]
    phone = entry["phone"]
    try:
        await client.sign_in(phone=phone, code=code)
    except errors.SessionPasswordNeededError:
        await update.message.reply_text("Akun Anda butuh dua-langkah (2FA). Masukkan password 2FA sekarang:")
        # in this POC we won't implement 2FA flow fully; fallback to user cancel
        return ConversationHandler.END
    except Exception as e:
        await update.message.reply_text(f"Gagal sign-in: {e}")
        return ConversationHandler.END
    # success. encrypt session and remove plain
    encrypt_session_file(uid)
    await update.message.reply_text("Login sukses. Sesi Anda disimpan secara terenkripsi di server.")
    _pending_login.pop(uid, None)
    return ConversationHandler.END

# wrapper to create client for login (plain session)
async def create_client_for_login(uid: int):
    path_plain = session_plain_path(uid)
    client = TelegramClient(path_plain, API_ID, API_HASH)
    await client.connect()
    CLIENTS[uid] = client
    return client

# /scan handler: load client from encrypted if needed
async def scan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    # ensure client loaded
    client = CLIENTS.get(uid)
    if not client:
        try:
            client = await load_client_from_encrypted(uid)
        except Exception as e:
            await update.message.reply_text(f"Tidak ada sesi atau gagal memuat: {e}\nGunakan /login dahulu.")
            return
    # list dialogs (first 50)
    await update.message.reply_text("Memindai dialog (50 pertama)...")
    lines = []
    async for d in client.iter_dialogs(limit=50):
        ent = d.entity
        tname = d.name or getattr(ent, "title", None) or str(getattr(ent, "id", None))
        typ = type(ent).__name__
        lines.append(f"{tname} ({typ}) [{getattr(ent,'id',None)}]")
    if not lines:
        await update.message.reply_text("Tidak ada dialog.")
    else:
        for i in range(0, len(lines), 20):
            await update.message.reply_text("\n".join(lines[i:i+20]))

# /clean conversation: ask mode -> before date -> safe -> confirm -> run
async def clean_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    client = CLIENTS.get(uid)
    if not client:
        try:
            client = await load_client_from_encrypted(uid)
        except Exception as e:
            await update.message.reply_text(f"Tidak ada sesi: {e}. Silakan /login dulu.")
            return ConversationHandler.END
    await update.message.reply_text("Mode hapus: ketik 'all' untuk semua pesan, 'media' untuk media saja:", reply_markup=ForceReply(selective=True))
    return C_MODE

async def clean_mode(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = update.message.text.strip().lower()
    if txt not in ("all", "media"):
        await update.message.reply_text("Mode tidak dikenali. Batalkan.")
        return ConversationHandler.END
    context.user_data["mode"] = txt
    await update.message.reply_text("Masukkan tanggal BEFORE (YYYY-MM-DD) atau kosong untuk tidak ada filter:", reply_markup=ForceReply(selective=True))
    return C_BEFORE

async def clean_before(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = update.message.text.strip()
    before_dt = parse_date(s) if s else None
    context.user_data["before"] = before_dt
    await update.message.reply_text("Safe mode? ketik 'yes' untuk hanya hapus pesan Anda sendiri, lainya kosong untuk NO:", reply_markup=ForceReply(selective=True))
    return C_SAFE

async def clean_safe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    safe = update.message.text.strip().lower() == "yes"
    context.user_data["safe"] = safe
    # confirm
    mode = context.user_data.get("mode")
    before = context.user_data.get("before")
    await update.message.reply_text(f"Konfirmasi: mode={mode}, before={before}, safe={safe}. Ketik 'run' untuk mulai atau 'cancel' untuk batal.", reply_markup=ForceReply(selective=True))
    return C_SAFE  # we'll reuse this state to capture 'run' or not

async def clean_run_or_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = update.message.text.strip().lower()
    if txt == "cancel":
        await update.message.reply_text("Dibatalkan.")
        return ConversationHandler.END
    if txt != "run":
        await update.message.reply_text("Perintah tidak dikenali. Dibatalkan.")
        return ConversationHandler.END
    # run cleaning in background
    uid = update.effective_user.id
    client = CLIENTS.get(uid)
    if not client:
        try:
            client = await load_client_from_encrypted(uid)
        except Exception as e:
            await update.message.reply_text(f"Tidak ada sesi: {e}. Silakan /login.")
            return ConversationHandler.END
    # collect targets (first N dialogs to avoid extreme loads)
    targets = []
    async for d in client.iter_dialogs(limit=200):
        targets.append({"name": d.name or getattr(d.entity,"title",None) or str(getattr(d.entity,"id",None)), "entity": d.entity})
    mode = context.user_data.get("mode", "all")
    before = context.user_data.get("before", None)
    safe = context.user_data.get("safe", False)
    # start progress message
    status_msg = await update.message.reply_text("Mulai pembersihan... progress akan diperbarui di sini.")
    # progress callback
    def progress_cb(deleted_inc, total_est, current_target):
        try:
            # schedule edit in event loop
            asyncio.create_task(status_msg.edit_text(f"Target: {current_target} — +{deleted_inc} terhapus (estimasi {total_est})"))
        except Exception:
            pass
    # run in background
    asyncio.create_task(run_clean_all(client, targets, mode, before, None, safe, batch_size=50, delay_seconds=1.0, concurrency=2, update_fn=progress_cb))
    await update.message.reply_text("Task berjalan di background. Lihat pesan progress.")
    return ConversationHandler.END

# ---------- Setup Application ----------
from telegram.ext import PicklePersistence

def main():
    # persistence optional
    persistence = None
    app = ApplicationBuilder().token(BOT_TOKEN).persistence(persistence).build()

    # Login conversation: only phone+code
    conv_login = ConversationHandler(
        entry_points=[CommandHandler("login", login_start)],
        states={
            A_PHONE: [MessageHandler(filters.TEXT & ~filters.COMMAND, login_phone)],
            A_CODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, login_code)],
        },
        fallbacks=[]
    )
    conv_clean = ConversationHandler(
        entry_points=[CommandHandler("clean", clean_start)],
        states={
            C_MODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, clean_mode)],
            C_BEFORE: [MessageHandler(filters.TEXT & ~filters.COMMAND, clean_before)],
            C_SAFE: [MessageHandler(filters.TEXT & ~filters.COMMAND, clean_safe),
                     MessageHandler(filters.TEXT & ~filters.COMMAND, clean_run_or_cancel)],
        },
        fallbacks=[]
    )

    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(conv_login)
    app.add_handler(CommandHandler("scan", scan_cmd))
    app.add_handler(conv_clean)

    log.info("Bot siap. Menjalankan polling...")
    app.run_polling()

if __name__ == "__main__":
    main()
