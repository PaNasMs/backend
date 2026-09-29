import asyncio
import hashlib
import hmac
import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def relay(base, token, code, user):
    payload = json.dumps({"code": code, "chatId": str(user.id), "name": (user.full_name + (" · @" + user.username if user.username else ""))[:128], "timestamp": int(time.time())}, ensure_ascii=False).encode()
    signature = hmac.new(token.encode(), b"panasms-telegram-link-v1\n" + payload, hashlib.sha256).hexdigest()
    request = Request(base + "/api/v1/notification-telegram-relay", payload, {"Content-Type": "application/json", "Origin": base, "X-PaNasMs-Request": "1", "X-PaNasMs-Telegram-Signature": signature})
    with build_opener(NoRedirect).open(request, timeout=10) as response:
        return response.status == 204

def register(ctx):
    def wire(application, adapter):
        from telegram.ext import CommandHandler, ApplicationHandlerStop
        async def link(update, context):
            user, chat, message = update.effective_user, update.effective_chat, update.effective_message
            if not user or not chat or not message or chat.type != "private" or chat.id != user.id:
                raise ApplicationHandlerStop
            lang = (user.language_code or "en")[:2]
            texts = {
                "en": ("Send /link followed by the code shown in your NAS profile.", "Return to your NAS profile and confirm this Telegram account.", "Link failed. Check the NAS connection or generate a new code."),
                "ru": ("Отправьте /link и код из своего профиля NAS.", "Вернитесь в профиль NAS и подтвердите этот Telegram-аккаунт.", "Не удалось связать аккаунт. Проверьте связь с NAS или создайте новый код."),
                "uk": ("Надішліть /link і код зі свого профілю NAS.", "Поверніться до профілю NAS і підтвердьте цей Telegram-акаунт.", "Не вдалося зв’язати акаунт. Перевірте зв’язок із NAS або створіть новий код."),
            }.get(lang)
            if texts is None:
                texts = ("Send /link CODE from your NAS profile.", "Return to your NAS profile to confirm this account.", "Link failed. Check the NAS connection or generate a new code.")
            if len(context.args) != 1 or not re.fullmatch(r"[a-f0-9]{32}", context.args[0]):
                await message.reply_text(texts[0]); raise ApplicationHandlerStop
            try:
                base = json.loads(Path(__file__).with_name("config.json").read_text())["nas_url"].rstrip("/")
                parsed = urlsplit(base)
                if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.path:
                    raise ValueError("Invalid NAS URL")
                ok = await asyncio.to_thread(relay, base, context.bot.token, context.args[0], user)
            except Exception:
                ok = False
            await message.reply_text(texts[1 if ok else 2])
            raise ApplicationHandlerStop
        application.add_handler(CommandHandler("link", link), group=-10)
    ctx.register_platform_handler("telegram", wire)
