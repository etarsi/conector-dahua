# -*- coding: utf-8 -*-
"""Oyente crudo del stream de eventos: vuelca TODO lo que manda el equipo.
Sirve para descubrir que codigo de evento emite realmente al fichar."""
import socket, sys, time, urllib.request as U
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

IP, USER, CLAVE = sys.argv[1], "admin", "Sebigus2025*$"
MINUTOS = float(sys.argv[2]) if len(sys.argv) > 2 else 10

g = U.HTTPPasswordMgrWithDefaultRealm()
g.add_password(None, f"http://{IP}/", USER, CLAVE)
op = U.build_opener(U.HTTPDigestAuthHandler(g))
url = f"http://{IP}/cgi-bin/eventManager.cgi?action=attach&codes=[All]&heartbeat=5"

print(f"[{time.strftime('%H:%M:%S')}] escuchando {IP} durante {MINUTOS} min", flush=True)
r = op.open(url, timeout=20)
r.fp.raw._sock.settimeout(60)
fin = time.time() + MINUTOS * 60
buf = b""
latidos = 0
while time.time() < fin:
    try:
        t = r.read(1024)
    except socket.timeout:
        print(f"[{time.strftime('%H:%M:%S')}] -- 60s sin datos --", flush=True); continue
    if not t:
        print("-- el equipo cerro el stream --", flush=True); break
    buf += t
    while b"--myboundary" in buf:
        i = buf.index(b"--myboundary")
        j = buf.find(b"--myboundary", i + 12)
        if j == -1:
            break
        bloque = buf[i:j].decode("utf-8", "replace")
        buf = buf[j:]
        if "Heartbeat" in bloque:
            latidos += 1
            if latidos % 12 == 1:
                print(f"[{time.strftime('%H:%M:%S')}] latido #{latidos} (stream vivo)", flush=True)
        else:
            print(f"\n[{time.strftime('%H:%M:%S')}] ***** EVENTO *****\n{bloque}\n", flush=True)
print(f"[{time.strftime('%H:%M:%S')}] fin. latidos={latidos}", flush=True)
