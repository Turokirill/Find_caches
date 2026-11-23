#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
find_caches.py - находит пулы кэшей googlevideo и показывает, какие узлы живы.

НИЧЕГО НЕ МЕНЯЕТ в системе. Только читает, проверяет и пишет один файл
с готовыми строками для hosts.

Проверка узла - не только TLS-рукопожатие, но и реальный HTTP-ответ.
Узел считается живым, если TLS прошёл И пришёл HTTP-статус.

ТРЕБОВАНИЯ:
  Python 3.7+ (только стандартная библиотека, pip не нужен)
  zapret ДОЛЖЕН быть запущен - иначе youtube.com не откроется
  QUIC в браузере лучше выключить
  Браузерный DoH желательно выключить на время запуска (см. ниже)

Запуск: двойной клик по find_caches.bat или
    python find_caches.py

Если имя пула видно только в DevTools (F12 -> Network -> videoplayback),
а сам поток не догрузился и в DNS-кэш с историей не попал - задай его вручную:

    python find_caches.py sn-q4fzen7r
    python find_caches.py rr4---sn-q4fzen7r.googlevideo.com

Или создай рядом файл pools.txt и впиши имена туда, по одному в строку.
"""

import socket
import ssl
import struct
import subprocess
import sys
import re
import os
import sqlite3
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

RR = range(1, 9)

SEP = "=" * 70

OUT_FILE = "hosts_suggest.txt"

TIMEOUT = 6.0


# ================================================================ DNS мимо hosts
def dns_a(name, server="8.8.8.8", timeout=4.0):
    """Спрашивает A-запись напрямую у DNS-сервера, игнорируя файл hosts."""
    tid = 0x1234
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode("ascii")
    q += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(2048)
    except Exception:
        return []
    finally:
        s.close()
    if len(data) < 12:
        return []
    ancount = struct.unpack(">H", data[6:8])[0]
    pos = 12
    while pos < len(data) and data[pos] != 0:
        if data[pos] & 0xC0:
            pos += 2
            break
        pos += data[pos] + 1
    pos += 1 + 4
    out = []
    for _ in range(ancount):
        if pos + 12 > len(data):
            break
        if data[pos] & 0xC0:
            pos += 2
        else:
            while pos < len(data) and data[pos] != 0:
                pos += data[pos] + 1
            pos += 1
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == 1 and rdlen == 4:
            out.append("%d.%d.%d.%d" % tuple(data[pos:pos + 4]))
        pos += rdlen
    return out


# ================================================================ проверка узла
def dechunk(b):
    out = b""
    i = 0
    while True:
        j = b.find(b"\r\n", i)
        if j < 0:
            break
        try:
            n = int(b[i:j].split(b";")[0].strip(), 16)
        except Exception:
            break
        if n == 0:
            break
        out += b[j + 2:j + 2 + n]
        i = j + 2 + n + 2
    return out


def probe_node(ip, sni, timeout=TIMEOUT):
    """
    Проверяет узел по-настоящему.

    Возвращает (state, detail):
      OK      - TLS прошёл И пришёл HTTP-статус (значит данные идут)
      TLS     - TLS прошёл, но HTTP-ответа нет
      DEAD    - TLS не прошёл
      TCP     - даже TCP не открылся
    """
    try:
        s = socket.create_connection((ip, 443), timeout=timeout)
    except Exception as e:
        return "TCP", type(e).__name__

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        ss = ctx.wrap_socket(s, server_hostname=sni)
    except Exception as e:
        try:
            s.close()
        except Exception:
            pass
        return "DEAD", type(e).__name__

    # TLS прошёл - теперь требуем реальный ответ
    try:
        ss.sendall((
            "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
            "Connection: close\r\n\r\n" % (sni, UA)).encode())
        buf = b""
        while len(buf) < 65536:
            d = ss.recv(8192)
            if not d:
                break
            buf += d
        ss.close()
    except Exception as e:
        return "TLS", type(e).__name__

    if not buf:
        return "TLS", "empty"

    head = buf.partition(b"\r\n\r\n")[0]
    status = head.split(b"\r\n")[0].decode("latin1", "replace")

    # узел gvs отдаёт 404 на / - это нормально и означает, что он живой
    if "HTTP/" not in status:
        return "TLS", "no http status"

    code = ""
    m = re.search(r"HTTP/\d\.\d\s+(\d{3})", status)
    if m:
        code = m.group(1)

    if code.startswith("5") and code != "503":
        return "TLS", "http " + code

    return "OK", "http " + code


def https_get(host, path, timeout=20, limit=4_000_000):
    s = socket.create_connection((host, 443), timeout=timeout)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ss = ctx.wrap_socket(s, server_hostname=host)
    ss.sendall((
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
        "Accept: text/html\r\nAccept-Language: ru,en;q=0.9\r\n"
        "Connection: close\r\n\r\n" % (path, host, UA)).encode())
    buf = b""
    try:
        while len(buf) < limit:
            d = ss.recv(262144)
            if not d:
                break
            buf += d
    except Exception:
        pass
    ss.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    if b"chunked" in head.lower():
        body = dechunk(body)
    return head, body


# ================================================================ источники имён
def source_watch():
    """
    Источник 1: страницы watch, параметр mn= - имена пулов.

    Возвращает (found, note). note = None или причина, почему не вышло
    (например YouTube показал проверку на робота).
    """
    vids = ["dQw4w9WgXcQ", "jNQXAC9IVRw", "9bZkp7q19f0", "RkJ6ZMtCvZo"]
    found = {}
    notes = []

    def one(vid):
        try:
            head, body = https_get("www.youtube.com", "/watch?v=" + vid)
        except Exception as e:
            notes.append("сеть: " + type(e).__name__)
            return vid, set()
        status = head.split(b"\r\n")[0].decode("latin1", "replace")
        if "302" in status or "301" in status:
            loc = ""
            for line in head.decode("latin1", "replace").split("\r\n"):
                if line.lower().startswith("location:"):
                    loc = line
            if "sorry" in loc.lower() or "consent" in loc.lower():
                notes.append(
                    "YouTube отдал проверку на робота (302 на google.com/sorry).\n"
                    "   Открой в браузере любое видео, пройди проверку, потом\n"
                    "   запусти файл снова. Либо обойдись без этого шага -\n"
                    "   источники 2, 3 и 4 работают независимо.")
            else:
                notes.append("YouTube отдал редирект: " + loc[:90])
            return vid, set()
        if "200" not in status:
            notes.append("YouTube ответил: " + status[:60])
            return vid, set()
        t = body.decode("utf-8", "replace").replace("\\u0026", "&").replace("\\/", "/")
        mn = set(re.findall(r"[?&]mn=([^&\"\\]+)", t))
        hs = set(re.findall(r"https://([a-z0-9.\-]+googlevideo\.com)/videoplayback", t))
        out = set()
        for m in mn:
            m = m.replace("%2C", ",").replace("%2c", ",")
            for part in m.split(","):
                part = part.strip()
                if re.fullmatch(r"sn-[a-z0-9]+-[a-z0-9]+", part):
                    out.add(part)
        for h in hs:
            mm = re.match(r"rr\d+---(sn-[a-z0-9]+-[a-z0-9]+)\.googlevideo\.com", h)
            if mm:
                out.add(mm.group(1))
        return vid, out

    with ThreadPoolExecutor(max_workers=4) as ex:
        for vid, cls in ex.map(one, vids):
            mark = ",".join(sorted(cls)) if cls else "нет данных"
            print("   %-16s %s" % (vid, mark))
            for c in cls:
                found[c] = found.get(c, 0) + 1

    note = notes[0] if notes else None
    if note and not found:
        print("   " + note)
    return found, note


def source_dnscache():
    """Источник 2: DNS-кэш Windows. Не работает, если браузер ходит через DoH."""
    try:
        out = subprocess.run(["ipconfig", "/displaydns"], capture_output=True,
                             text=True, errors="replace", timeout=30).stdout
    except Exception:
        return {}
    found = {}
    for m in re.finditer(r"(rr\d+---(sn-[a-z0-9]+-[a-z0-9]+)\.googlevideo\.com)", out):
        found[m.group(2)] = found.get(m.group(2), 0) + 1
    return found


BROWSER_POOL_RE = re.compile(r"(rr\d+---(sn-[a-z0-9]+-[a-z0-9]+)\.googlevideo\.com)")


def _chromium_roots():
    """Пути к профилям браузеров на Chromium (Vivaldi, Chrome, Edge, Opera, Brave, Yandex)."""
    la = os.environ.get("LOCALAPPDATA", "")
    ra = os.environ.get("APPDATA", "")
    return [
        ("Vivaldi", os.path.join(la, "Vivaldi", "User Data")),
        ("Chrome", os.path.join(la, "Google", "Chrome", "User Data")),
        ("Chrome Beta", os.path.join(la, "Google", "Chrome Beta", "User Data")),
        ("Edge", os.path.join(la, "Microsoft", "Edge", "User Data")),
        ("Brave", os.path.join(la, "BraveSoftware", "Brave-Browser", "User Data")),
        ("Yandex", os.path.join(la, "Yandex", "YandexBrowser", "User Data")),
        ("Opera", os.path.join(ra, "Opera Software", "Opera Stable")),
        ("Opera GX", os.path.join(ra, "Opera Software", "Opera GX Stable")),
        ("Vivaldi (roaming)", os.path.join(ra, "Vivaldi", "User Data")),
    ]


def _firefox_roots():
    """Пути к профилям Firefox (и форков: Waterfox, LibreWolf)."""
    ra = os.environ.get("APPDATA", "")
    la = os.environ.get("LOCALAPPDATA", "")
    return [
        ("Firefox", os.path.join(ra, "Mozilla", "Firefox", "Profiles")),
        ("Firefox (dev)", os.path.join(ra, "Mozilla", "Firefox", "Profiles")),
        ("Waterfox", os.path.join(ra, "Waterfox", "Profiles")),
        ("LibreWolf", os.path.join(ra, "librewolf", "Profiles")),
        ("Firefox (local)", os.path.join(la, "Mozilla", "Firefox", "Profiles")),
    ]


def _scan_chromium(root):
    """История Chromium: файл History, таблица urls, колонка url."""
    found = {}
    if not os.path.isdir(root):
        return found
    for dirpath, _d, filenames in os.walk(root):
        if "History" not in filenames:
            continue
        src = os.path.join(dirpath, "History")
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(suffix=".db")
            os.close(fd)
            shutil.copy2(src, tmp)
            con = sqlite3.connect(tmp)
            try:
                rows = con.execute("SELECT url FROM urls").fetchall()
            finally:
                con.close()
            for (url,) in rows:
                for m in BROWSER_POOL_RE.finditer(url or ""):
                    found[m.group(2)] = found.get(m.group(2), 0) + 1
        except Exception:
            continue
        finally:
            if tmp:
                try:
                    os.remove(tmp)
                except Exception:
                    pass
    return found


def _scan_firefox(root):
    """История Firefox: файл places.sqlite, таблица moz_places, колонка url."""
    found = {}
    if not os.path.isdir(root):
        return found
    for dirpath, _d, filenames in os.walk(root):
        if "places.sqlite" not in filenames:
            continue
        src = os.path.join(dirpath, "places.sqlite")
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(suffix=".db")
            os.close(fd)
            shutil.copy2(src, tmp)
            con = sqlite3.connect(tmp)
            try:
                rows = con.execute("SELECT url FROM moz_places").fetchall()
            finally:
                con.close()
            for (url,) in rows:
                for m in BROWSER_POOL_RE.finditer(url or ""):
                    found[m.group(2)] = found.get(m.group(2), 0) + 1
        except Exception:
            continue
        finally:
            if tmp:
                try:
                    os.remove(tmp)
                except Exception:
                    pass
    return found


def source_browser_history():
    """
    Источник 3: история браузеров. Работает даже при включённом DoH,
    потому что там лежат сами URL, а не DNS-записи.

    Chromium-семейство (Vivaldi, Chrome, Edge, Opera, Brave, Yandex):
        <профиль>/History        -> таблица urls, колонка url
    Firefox и форки:
        <профиль>/places.sqlite  -> таблица moz_places, колонка url
    """
    found = {}
    seen = set()

    for name, root in _chromium_roots():
        key = os.path.normcase(os.path.abspath(root))
        if key in seen or not os.path.isdir(root):
            continue
        seen.add(key)
        part = _scan_chromium(root)
        if part:
            print("   %-12s %d записей" % (name, sum(part.values())))
            for c, n in part.items():
                found[c] = found.get(c, 0) + n

    for name, root in _firefox_roots():
        key = os.path.normcase(os.path.abspath(root))
        if key in seen or not os.path.isdir(root):
            continue
        seen.add(key)
        part = _scan_firefox(root)
        if part:
            print("   %-12s %d записей" % (name, sum(part.values())))
            for c, n in part.items():
                found[c] = found.get(c, 0) + n

    return found


def source_report_mapping():
    """Источник 4: код пула + проверка, что DNS вообще отвечает мимо hosts."""
    code = None
    try:
        s = socket.create_connection(("redirector.googlevideo.com", 80), timeout=10)
        s.sendall(b"GET /report_mapping?di=no HTTP/1.1\r\n"
                  b"Host: redirector.googlevideo.com\r\n"
                  b"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
        buf = b""
        while len(buf) < 65536:
            d = s.recv(8192)
            if not d:
                break
            buf += d
        s.close()
        body = buf.partition(b"\r\n\r\n")[2]
        if b"chunked" in buf.lower():
            body = dechunk(body)
        t = body.decode("latin1", "replace")
        m = re.search(r"=>\s*([a-z0-9\-]+)\s*\(", t)
        if m:
            code = m.group(1)
    except Exception:
        pass

    # прямая DNS-проверка: видно ли redirector мимо hosts
    red_ips = dns_a("redirector.googlevideo.com")
    return code, red_ips


# ================================================================ DoH в браузерах
def doh_state():
    """Смотрит, включён ли Secure DNS (DoH) в браузерах."""
    paths = [
        ("Vivaldi", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Vivaldi", "User Data", "Local State")),
        ("Chrome", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data", "Local State")),
        ("Edge", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "User Data", "Local State")),
        ("Opera", os.path.join(os.environ.get("APPDATA", ""), "Opera Software", "Opera Stable", "Local State")),
    ]
    res = []
    for name, p in paths:
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                t = f.read()
        except Exception:
            continue
        m = re.search(r'"dns_over_https"\s*:\s*\{[^}]*\}', t)
        if not m:
            continue
        frag = m.group(0)
        mode = re.search(r'"mode"\s*:\s*"([^"]+)"', frag)
        tmpl = re.search(r'"templates"\s*:\s*"([^"]+)"', frag)
        res.append((name, mode.group(1) if mode else "?", tmpl.group(1) if tmpl else "?"))
    return res


# ================================================================ youtube жив?
def youtube_alive():
    """
    Проверяет, что youtube.com реально отвечает, а не отдаёт заглушку.
    204 или 200 - норма. 403/451/заглушка - нет.
    """
    try:
        head, _body = https_get("www.youtube.com", "/generate_204", timeout=8, limit=8000)
    except Exception as e:
        return False, type(e).__name__
    status = head.split(b"\r\n")[0].decode("latin1", "replace")
    m = re.search(r"\s(\d{3})\s", status)
    code = m.group(1) if m else "?"
    if code in ("200", "204"):
        return True, "http " + code
    return False, "http " + code


# ================================================================ свои имена пулов
def clusters_from_args_and_file():
    """
    Имена пулов, которые пользователь задал сам:
      - аргументами командной строки
      - файлом pools.txt рядом со скриптом

    Нужно, когда имя видно только в DevTools (F12 -> Network), а в DNS-кэш
    и историю оно не попало: например, поток не догрузился.

    Принимает что угодно: sn-xxxx-xxxx, rr4---sn-xxxx-xxxx.googlevideo.com,
    целиком URL.
    """
    raw = []
    raw.extend(sys.argv[1:])

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pools.txt")
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        raw.append(line)
        except Exception:
            pass

    found = []
    for item in raw:
        # имя пула бывает из двух частей (sn-8ph2xajvh-v8ce) и из одной
        # (sn-q4fzen7r) - вторую часть Google иногда не выдаёт
        for m in re.finditer(r"(?:rr\d+---)?(sn-[a-z0-9]+(?:-[a-z0-9]+)?)", item.lower()):
            c = m.group(1)
            if c not in found:
                found.append(c)
    return found


# ================================================================ main
def main():
    print(SEP)
    print(" ПОИСК ПУЛОВ КЭШЕЙ googlevideo И ПРОВЕРКА УЗЛОВ")
    print(" Проверка: TCP + TLS + реальный HTTP-ответ.")
    print(" Ничего не меняет. Итог пишет в %s" % OUT_FILE)
    print(SEP)
    print()

    ok, why = youtube_alive()
    if ok:
        print(" youtube.com открывается (%s) - можно продолжать." % why)
    else:
        print(" !!! youtube.com НЕ открывается (%s)." % why)
        print(" !!! Запусти zapret ОТ ИМЕНИ АДМИНИСТРАТОРА и перезапусти этот файл.")
        print(" !!! Без zapret видео не поедет вообще, даже с правильным hosts.")
        print()
        print(" !!! Проверить, что zapret работает, из cmd так:")
        print('       curl -s -o NUL -w "%{http_code}" https://www.youtube.com/generate_204')
        print("     Должно быть 204. Если 000 - zapret не работает.")
        print("     В браузере этот адрес открывать бесполезно: 204 - пустая страница,")
        print("     вкладка останется на ней, и адрес из строки просто исчезнет.")
    print()

    # --- DoH
    dohs = doh_state()
    if dohs:
        print(" Secure DNS (DoH) в браузерах:")
        for name, mode, tmpl in dohs:
            print("   %-8s mode=%-8s %s" % (name, mode, tmpl))
        print("   ВНИМАНИЕ: при включённом DoH браузер не пишет имена в DNS-кэш")
        print("   Windows, поэтому источник 2 может оказаться пустым.")
        print("   Источники 1, 3 и 4 от этого не зависят.")
        print()
    else:
        print(" Secure DNS (DoH): не найден в настройках браузеров.")
        print()

    clusters = {}

    print("[1/4] Имена пулов со страниц YouTube (mn=)")
    if ok:
        wfound, _wnote = source_watch()
        for c, n in wfound.items():
            clusters[c] = clusters.get(c, 0) + n
    else:
        print("   пропущено: youtube.com не открывается")
    print()

    print("[2/4] DNS-кэш Windows (ipconfig /displaydns)")
    cached = source_dnscache()
    for c, n in cached.items():
        print("   %-28s встречалось %d раз" % (c, n))
        clusters[c] = clusters.get(c, 0) + n
    if not cached:
        print("   пусто. Обычно значит: браузер ходит через DoH, или кэш очищен.")
        print("   На время можно выключить Secure DNS в браузере и открыть видео заново.")
    print()

    print("[3/4] История браузеров (работает и при DoH)")
    hist = source_browser_history()
    for c, n in hist.items():
        print("   %-28s встречалось %d раз" % (c, n))
        clusters[c] = clusters.get(c, 0) + n
    if not hist:
        print("   ничего не найдено.")
        print("   Искал: Vivaldi, Chrome, Edge, Opera, Brave, Yandex,")
        print("   Firefox и форки (Waterfox, LibreWolf).")
        print("   Если браузер другой или профиль в нестандартном месте -")
        print("   открой видео, потом посмотри имя пула в F12 -> Network -> videoplayback.")
    print()

    print("[4/4] report_mapping и DNS мимо hosts")
    code, red_ips = source_report_mapping()
    if code:
        print("   код пула: %s" % code)
    else:
        print("   код пула: не определился")
    if red_ips:
        print("   redirector.googlevideo.com -> %s (DNS отвечает)" % ", ".join(red_ips))
    else:
        print("   redirector.googlevideo.com -> DNS не ответил")
    print()

    # --- имена пулов, заданные вручную (аргументы или pools.txt)
    manual = clusters_from_args_and_file()
    if manual:
        print("[+] Свои имена пулов (аргументы / pools.txt)")
        for c in manual:
            print("   %s" % c)
            clusters[c] = clusters.get(c, 0) + 1
        print()

    pools = []
    if code:
        pools.append(("rrN.%s" % code, ["rr%d.%s.googlevideo.com" % (i, code) for i in RR]))
    for c in clusters:
        pools.append(("rrN---%s" % c, ["rr%d---%s.googlevideo.com" % (i, c) for i in RR]))

    if not pools:
        print("Не удалось найти ни одного пула.")
        print("Открой любое видео на YouTube, потом запусти файл снова.")
        pause()
        return

    # --- сбор всех узлов и одна общая параллельная проверка
    jobs = []
    for pool_name, names in pools:
        for n in names:
            jobs.append((pool_name, n))

    def work(item):
        pool_name, n = item
        ips = dns_a(n)
        if not ips:
            return pool_name, n, None, "NXDOMAIN", ""
        ip = ips[0]
        state, detail = probe_node(ip, n)
        if state != "OK":
            # вторая попытка: сеть бывает рваной
            state2, detail2 = probe_node(ip, n)
            if state2 == "OK":
                state, detail = state2, detail2
        return pool_name, n, ip, state, detail

    print(SEP)
    print(" ПРОВЕРКА УЗЛОВ (TCP + TLS + HTTP)")
    print(SEP)
    print()

    rows = {}
    with ThreadPoolExecutor(max_workers=32) as ex:
        for pool_name, n, ip, state, detail in ex.map(work, jobs):
            rows.setdefault(pool_name, []).append((n, ip, state, detail))

    # --- убираем дубли пулов для показа
    # rrN.vimpelcom-ovb1 и rrN---sn-8ph2xajvh-v8ce - это ОДНИ И ТЕ ЖЕ узлы,
    # просто с разными именами. Показываем только sn-форму (именно её
    # YouTube подставляет в ссылки videoplayback), но в файл пишем обе:
    # если сервер когда-нибудь отдаст другую форму, строка уже будет.
    ordered = sorted(pools, key=lambda p: (0 if "---sn-" in p[0] else 1))
    seen_ipsets = []
    display_pools = []
    for pool_name, names in ordered:
        ipset = frozenset(x[1] for x in rows.get(pool_name, []) if x[1])
        if not ipset:
            display_pools.append((pool_name, names))
            continue
        if ipset in seen_ipsets:
            continue
        seen_ipsets.append(ipset)
        display_pools.append((pool_name, names))

    suggestions = []

    for pool_name, names in display_pools:
        info = rows.get(pool_name, [])
        alive = [x for x in info if x[2] == "OK"]
        tls_only = [x for x in info if x[2] == "TLS"]
        dead = [x for x in info if x[2] in ("DEAD", "TCP")]
        nx = [x for x in info if x[2] == "NXDOMAIN"]

        print(" пул %s" % pool_name)
        for n, ip, state, detail in info:
            mark = {"OK": "ЖИВ ", "TLS": "TLS ", "DEAD": "МЁРТВ",
                    "TCP": "МЁРТВ", "NXDOMAIN": "НЕТ  "}[state]
            print("   %-50s %-15s %s %s" % (n, ip or "-", mark, detail))
        print("   итого: живых %d, только-TLS %d, мёртвых %d, нет в DNS %d"
              % (len(alive), len(tls_only), len(dead), len(nx)))
        print()

        # пул целиком не существует в DNS - это не наш пул
        if nx and not alive and not dead and not tls_only:
            print("   Такого пула нет в DNS: ни одно из восьми имён не находится.")
            print("   Обычно это рекламные потоки (имена вида sn-aigl6nzs, sn-q4fzen7r)")
            print("   или устаревший пул, который YouTube уже не использует.")
            print("   Правки в hosts не нужны, на видео это не влияет.")
            print()
            continue

        if tls_only:
            print("   ВНИМАНИЕ: %d узл(ов) проходят TLS, но не отдают HTTP." % len(tls_only))
            print("   Это и есть случай 'пул жив, а видео не работает'.")
            print()

        if alive and (dead or tls_only):
            bad = dead + tls_only
            for idx, (n, ip, state, detail) in enumerate(bad):
                target = alive[idx % len(alive)][1]
                suggestions.append((target, n))
            print("   предложено строк для hosts: %d" % len(bad))
            print()

        if not alive and not nx:
            print("   В этом пуле нет ни одного живого узла - перенаправлять некуда.")
            print("   Нужен VPN или ждать, пока кэш оживёт.")
            print()

    # --- дубли пулов: пишем в файл и их тоже
    # Для пула rrN.<код> узлы те же самые, что у rrN---sn-..., поэтому
    # берём живые IP из совпавшего пула и подставляем в его имена.
    alive_by_ipset = {}
    for pool_name, names in display_pools:
        info = rows.get(pool_name, [])
        alive = [x for x in info if x[2] == "OK"]
        ipset = frozenset(x[1] for x in info if x[1])
        if alive and ipset:
            alive_by_ipset[ipset] = [x[1] for x in alive]

    shown_names = set(p for p, _ in display_pools)
    for pool_name, names in ordered:
        if pool_name in shown_names:
            continue
        info = rows.get(pool_name, [])
        ipset = frozenset(x[1] for x in info if x[1])
        targets = alive_by_ipset.get(ipset)
        if not targets:
            continue
        bad = [x for x in info if x[2] != "OK" and x[1]]
        for idx, (n, ip, state, detail) in enumerate(bad):
            suggestions.append((targets[idx % len(targets)], n))

    # --- файл результата
    if suggestions:
        try:
            with open(OUT_FILE, "w", encoding="utf-8", newline="\r\n") as f:
                for ip, name in suggestions:
                    f.write("%s %s\n" % (ip, name))
            print(SEP)
            print(" ГОТОВО: %d строк записано в %s" % (len(suggestions), OUT_FILE))
            print(" Путь: %s" % os.path.abspath(OUT_FILE))
            print(SEP)
        except Exception as e:
            print("Не смог записать %s: %s" % (OUT_FILE, e))
            print("Вот строки:")
            for ip, name in suggestions:
                print("%s %s" % (ip, name))
    else:
        print(SEP)
        print(" Перенаправлять нечего: либо все узлы живы, либо живых нет вовсе.")
        print(SEP)

    print()
    print(SEP)
    print(" ЧТО ДЕЛАТЬ ДАЛЬШЕ")
    print(SEP)
    print(" 1. Открой C:\\Windows\\System32\\drivers\\etc\\hosts Блокнотом от админа.")
    print(" 2. Удали оттуда ВСЕ старые строки с googlevideo (особенно с 0.0.0.0).")
    print(" 3. Вставь содержимое %s - там только строки 'IP имя'," % OUT_FILE)
    print("    без комментариев и лишнего текста.")
    print(" 4. Сохрани и выполни: ipconfig /flushdns")
    print(" 5. Полностью закрой браузер (все окна) и открой заново.")
    print()
    print(" ПРОВЕРЬ ПЕРЕД ЗАПУСКОМ:")
    print("   - zapret включён (иначе youtube.com вообще не откроется)")
    print("   - QUIC в браузере выключен (иначе часть трафика идёт мимо правил")
    print("     и мимо hosts-проверки; в Chrome/Vivaldi: chrome://flags/#enable-quic)")
    print("   - Secure DNS включай ПОСЛЕ того, как вставил строки в hosts.")
    print("     Если включить раньше, браузер может закэшировать старые IP.")
    print()
    print(" ПРО DoH-СЕРВЕРЫ В HOSTS (по желанию, из #16448):")
    print("   Если Secure DNS не стартует, можно закрепить его адреса в hosts:")
    print("     1.1.1.1 one.one.one.one")
    print("     2606:4700:4700::1111 one.one.one.one")
    print("     8.8.4.4 dns.google")
    print("     2001:4860:4860::8844 dns.google")
    print("     146.112.41.2 doh.opendns.com")
    print("     2620:119:fc::2 doh.opendns.com")
    print()
    pause()


def pause():
    try:
        input("Нажми Enter, чтобы закрыть...")
    except Exception:
        pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПрервано.")
    except Exception as e:
        print("\nОШИБКА: %s: %s" % (type(e).__name__, e))
        import traceback
        traceback.print_exc()
        pause()
