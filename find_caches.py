#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
find_caches.py - находит пулы кэшей googlevideo и показывает, какие узлы живы.

НИЧЕГО НЕ МЕНЯЕТ. Только читает и печатает.
В конце выдаёт готовые строки для hosts - их надо вставить руками.

Запуск: двойной клик или
    python find_caches.py
"""

import socket
import ssl
import struct
import subprocess
import sys
import re
import os
from concurrent.futures import ThreadPoolExecutor

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

RR = range(1, 9)

SEP = "=" * 70


# ---------------------------------------------------------------- DNS (мимо hosts)
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


# ---------------------------------------------------------------- TLS-проверка узла
def tls_ok(ip, sni, timeout=3.0):
    try:
        s = socket.create_connection((ip, 443), timeout=timeout)
    except Exception:
        return "TCP"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ss = ctx.wrap_socket(s, server_hostname=sni)
        ss.close()
        return "OK"
    except Exception:
        return "FAIL"


def rate(ip, sni, rounds=3):
    return [tls_ok(ip, sni) for _ in range(rounds)]


# ---------------------------------------------------------------- HTTPS GET
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
    return body


# ---------------------------------------------------------------- источник 1: mn=
def clusters_from_watch():
    """Смотрит страницы watch и достаёт параметр mn= - это и есть имена пулов."""
    vids = ["dQw4w9WgXcQ", "jNQXAC9IVRw", "9bZkp7q19f0", "RkJ6ZMtCvZo"]
    found = {}

    def one(vid):
        try:
            body = https_get("www.youtube.com", "/watch?v=" + vid)
        except Exception:
            return vid, set()
        t = body.decode("utf-8", "replace").replace("\\u0026", "&").replace("\\/", "/")
        mn = set(re.findall(r"[?&]mn=([^&\"\\]+)", t))
        hs = set(re.findall(r"https://([a-z0-9.\-]+googlevideo\.com)/videoplayback", t))
        out = set()
        for m in mn:
            m = m.replace("%2C", ",").replace("%2c", ",").replace("%2C", ",")
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
    return found


# ---------------------------------------------------------------- источник 2: hosts/DNS-кэш
def clusters_from_dnscache():
    try:
        out = subprocess.run(["ipconfig", "/displaydns"], capture_output=True,
                             text=True, errors="replace", timeout=30).stdout
    except Exception:
        return {}
    found = {}
    for m in re.finditer(r"(rr\d+---(sn-[a-z0-9]+-[a-z0-9]+)\.googlevideo\.com)", out):
        found[m.group(2)] = found.get(m.group(2), 0) + 1
    return found


# ---------------------------------------------------------------- источник 3: report_mapping
def code_from_report():
    try:
        s = socket.create_connection(("redirector.googlevideo.com", 80), timeout=10)
        s.sendall(b"GET /report_mapping?di=no HTTP/1.1\r\nHost: redirector.googlevideo.com\r\n"
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
        return m.group(1) if m else None
    except Exception:
        return None


# ---------------------------------------------------------------- основной отчёт
def main():
    print(SEP)
    print(" ПОИСК ПУЛОВ КЭШЕЙ googlevideo И ПРОВЕРКА УЗЛОВ")
    print(" Файл ничего не меняет. Только читает и печатает.")
    print(SEP)
    print()

    clusters = {}

    print("[1/4] Имена пулов со страниц YouTube (параметр mn=)")
    if not zapret_alive():
        print("   ВНИМАНИЕ: похоже, youtube.com не открывается.")
        print("   Запусти zapret и перезапусти этот файл, иначе этот шаг пропустится.")
    else:
        for c, n in clusters_from_watch().items():
            clusters[c] = clusters.get(c, 0) + n
    print()

    print("[2/4] Уже виденные имена из DNS-кэша Windows")
    cached = clusters_from_dnscache()
    for c, n in cached.items():
        print("   %-28s встречалось %d раз" % (c, n))
        clusters[c] = clusters.get(c, 0) + n
    if not cached:
        print("   пусто (браузер ещё не ходил на кэши, либо кэш очищен)")
    print()

    print("[3/4] Код твоего пула через report_mapping")
    code = code_from_report()
    human = []
    if code:
        print("   код: %s  ->  узлы вида rr1.%s.googlevideo.com" % (code, code))
        human = ["rr%d.%s.googlevideo.com" % (i, code) for i in RR]
    else:
        print("   не определился")
    print()

    if not clusters and not human:
        print("Не удалось найти ни одного пула. Проверь, что zapret запущен, и повтори.")
        pause()
        return

    print("[4/4] Проверка узлов")
    print()

    results = {}

    def check_cluster(cl):
        names = ["rr%d---%s.googlevideo.com" % (i, cl) for i in RR]
        info = []
        for n in names:
            ips = dns_a(n)
            if not ips:
                info.append((n, None, "NXDOMAIN", []))
                continue
            ip = ips[0]
            info.append((n, ip, "", rate(ip, n)))
        return cl, info

    def check_human(code):
        names = ["rr%d.%s.googlevideo.com" % (i, code) for i in RR]
        info = []
        for n in names:
            ips = dns_a(n)
            if not ips:
                info.append((n, None, "NXDOMAIN", []))
                continue
            ip = ips[0]
            info.append((n, ip, "", rate(ip, n)))
        return code, info

    tasks = [("cluster:" + c) for c in clusters] + [("human:" + code)] if code else \
            [("cluster:" + c) for c in clusters]

    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = []
        for t in tasks:
            kind, val = t.split(":", 1)
            futs.append(ex.submit(check_cluster if kind == "cluster" else check_human, val))
        for f in futs:
            k, info = f.result()
            results[k] = info

    for k, info in results.items():
        alive = [x for x in info if x[1] and x[3].count("OK") >= 2]
        dead = [x for x in info if x[1] and x[3].count("OK") < 2]
        nx = [x for x in info if not x[1]]
        print("   пул %s" % k)
        for n, ip, err, r in info:
            if err:
                print("     %-52s %s" % (n, err))
                continue
            ok = r.count("OK")
            state = "ЖИВ " if ok >= 2 else "МЁРТВ"
            print("     %-52s %-15s %s  (%d/%d)" % (n, ip, state, ok, len(r)))
        print("     итого: живых %d, мёртвых %d" % (len(alive), len(dead)))
        print()

        if dead and alive:
            print("     --- строки для hosts (мёртвое имя -> живой IP) ---")
            for idx, (n, ip, err, r) in enumerate(dead):
                best = alive[idx % len(alive)][1]
                print("     %-15s %s" % (best, n))
            print()

    print(SEP)
    print(" ЧТО ДЕЛАТЬ ДАЛЬШЕ")
    print(SEP)
    print(" 1. Открой C:\\Windows\\System32\\drivers\\etc\\hosts в Блокноте от админа.")
    print(" 2. Убери оттуда все старые строки с googlevideo (особенно с 0.0.0.0).")
    print(" 3. Вставь строки из блока выше: сначала IP, потом имя, через пробел.")
    print(" 4. Сохрани, затем в командной строке: ipconfig /flushdns")
    print(" 5. Полностью закрой и заново открой браузер.")
    print()
    print(" Строки пересчитывать после каждого изменения сети или когда видео")
    print(" снова начнёт падать 'через раз' - узел, живой сегодня, завтра может")
    print(" быть мёртвым, и наоборот.")
    print()
    pause()


def zapret_alive():
    try:
        https_get("www.youtube.com", "/generate_204", timeout=6, limit=1000)
        return True
    except Exception:
        return False


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
