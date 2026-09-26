# راهنمای فارسی cleanprobe

ابزار کوچکی که دو کار انجام می‌دهد:

1. **کدام مقصد کار می‌کند؟** یک هندشیک TLS 1.3 برای نام دلخواه (SNI)
   می‌فرستد و می‌گوید کدام آی‌پی‌ها آن را قبول می‌کنند — برای پیدا کردن
   مقصد REALITY و آی‌پی تمیز.
2. **لینک‌ها سالم هستند؟** لینک‌های `vless://` را اعتبارسنجی می‌کند
   (UUID، پورت، فیلدهای REALITY و ...).

---

## نصب (ساده‌ترین راه — یک خط)

```bash
curl -fsSL https://raw.githubusercontent.com/frank0live/cleanprobe/main/install.sh | bash
```

این دستور:

- پایتون را چک می‌کند (نسخهٔ ۳.۹ به بالا لازم است)
- برنامه را در `~/.cleanprobe` نصب می‌کند
- دستور `cleanprobe` را در `~/.local/bin` می‌سازد
- **نیاز به root ندارد**

اگر آخر کار پیامی دربارهٔ PATH دید، همان یک خط `echo ...` را اجرا کن
(یا ترمینال را ببند و باز کن).

### نصب دستی (اگر اسکریپت را دوست نداری)

```bash
git clone https://github.com/frank0live/cleanprobe
cd cleanprobe
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

ویندوز: به‌جای `. .venv/bin/activate` بنویس `.venv\Scripts\activate`

---

## اول از همه: تست سالم بودن نصب (۳۰ ثانیه)

```bash
cleanprobe selftest
```

باید آخرین خط این باشد:

    selftest: 22/22 passed

اگر این را دیدی، همه‌چیز درست است. این تست فقط با خود سیستم (لوکال)
حرف می‌زند — نه اینترنت لازم دارد، نه به جای دیگری وصل می‌شود.

---

## سه کار اصلی

### ۱) تست یک مقصد

```bash
cleanprobe probe www.cloudflare.com 443 --sni www.cloudflare.com
```

خروجی واقعی:

    ok  www.cloudflare.com:443 sni=www.cloudflare.com  45ms

### ۲) اسکن یک لیست

فایل «بذر» — هر خط یک آی‌پی، یک رنج، یا یک دامنه:

    1.1.1.1
    104.16.0.0/24
    cdn.example.net

بعد اجرا کن:

```bash
cleanprobe scan --seed seeds/example.txt --sni www.cloudflare.com --ports 443,8443
```

خروجی واقعی (نمونهٔ کوچک):

    scanning 3 probe(s): 3 host(s) x 1 port(s) x 1 sni(s)
      ok                       1.1.1.1:443 sni=www.cloudflare.com    59ms tls13
      ok                       104.16.132.229:443 sni=www.cloudflare.com    58ms tls13
      timeout                  203.0.113.1:443 sni=www.cloudflare.com  3006ms
    done: 2 accepted / 3 probes

گزینه‌های مفید:

- `--workers 64` — اتصال‌های موازی بیشتر (سریع‌تر)
- `--sample 200` — از رنج‌های بزرگ، نمونهٔ تصادفی بردار
- `--only-ok` — فقط مقصدهای سالم را نشان بده
- `--json out.json` — خروجی کامل JSON، برای اسکریپت‌ها

### ۳) چک کردن لینک‌ها

```bash
cleanprobe check links.txt          # با --live هر مقصد را هم تست می‌کند
```

خروجی واقعی:

    ok      1.1.1.1:443 sni=www.cloudflare.com
    invalid example.com:443 sni=-  errors: uuid is not a valid UUID; security=reality requires sni=; pbk does not decode to a 32-byte public key; sid must be hex, at most 16 chars
    1/2 link(s) valid

---

## معنی خروجی‌ها

| وضعیت | معنی |
|---|---|
| `ok` | هندشیک TLS 1.3 کامل شد — نامزد خوب |
| `alert` | جواب داد ولی نام را رد کرد (`alert 40` = handshake_failure) |
| `timeout` | در زمان تعیین‌شده جوابی نیامد |
| `refused` / `reset` | ارتباط رد شد یا مقصد آن را بست |

نکته: معمولاً فقط نامی قبول می‌شود که خودِ مقصد آن را سرو می‌کند —
برای همین انتخاب SNI درست مهم است.

## سؤال‌های رایج

- **root لازم است؟** نه.
- **لینک‌هایم جایی فرستاده می‌شود؟** نه. `check` کاملاً محلی است،
  مگر اینکه `--live` بدهی.
- **اسکن به کجا وصل می‌شود؟** فقط به آدرس‌هایی که در فایل بذر گذاشته‌ای.
- **ویندوز؟** همان دستورها، فقط مسیر دستور
  `.venv\Scripts\cleanprobe` است.
- **چطور حذف کنم؟** `rm -rf ~/.cleanprobe ~/.local/bin/cleanprobe`
