#!/usr/bin/env python3
# Minimal bore-protocol server (ekzhang/bore) for testing wld's bore client.
# Frames: NUL-delimited JSON. Client sends {"Hello":p}; we reply {"Hello":PUB}.
# For each conn to the public port we send {"Connection":"uuid"} on control; the
# client opens a new control conn and sends {"Accept":"uuid"}; we splice.
import socket, threading, json, sys, uuid as uuidlib, select

CTRL_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7835
pending = {}
lock = threading.Lock()

def read_frame(sock, buf):
    while b'\x00' not in buf[0]:
        d = sock.recv(4096)
        if not d:
            return None
        buf[0] += d
    i = buf[0].index(b'\x00')
    frame = buf[0][:i]
    buf[0] = buf[0][i+1:]
    return frame

def send_frame(sock, obj):
    sock.sendall(json.dumps(obj).encode() + b'\x00')

def splice(a, b):
    aeof = beof = False
    try:
        while not (aeof and beof):
            rl = [s for s, e in ((a, aeof), (b, beof)) if not e]
            if not rl:
                break
            r, _, _ = select.select(rl, [], [])
            if a in r:
                d = a.recv(65536)
                if not d:
                    aeof = True; b.shutdown(socket.SHUT_WR)
                else:
                    b.sendall(d)
            if b in r:
                d = b.recv(65536)
                if not d:
                    beof = True; a.shutdown(socket.SHUT_WR)
                else:
                    a.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try: s.close()
            except OSError: pass

def public_acceptor(pub_sock, ctrl):
    while True:
        try:
            conn, _ = pub_sock.accept()
        except OSError:
            return
        uid = str(uuidlib.uuid4())
        with lock:
            pending[uid] = conn
        try:
            send_frame(ctrl, {"Connection": uid})
        except OSError:
            return

def handle(conn):
    buf = [b'']
    frame = read_frame(conn, buf)
    if frame is None:
        conn.close(); return
    msg = json.loads(frame)
    if "Hello" in msg:
        pub = socket.socket(); pub.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        pub.bind(('127.0.0.1', 0)); pub.listen(16)
        pubport = pub.getsockname()[1]
        send_frame(conn, {"Hello": pubport})
        print(f"[fakebore] public 127.0.0.1:{pubport}", flush=True)
        threading.Thread(target=public_acceptor, args=(pub, conn), daemon=True).start()
        try:
            while True:
                r, _, _ = select.select([conn], [], [], 5)
                if conn in r:
                    if not conn.recv(4096):
                        break
                else:
                    send_frame(conn, "Heartbeat")
        except OSError:
            pass
    elif "Accept" in msg:
        with lock:
            pub_conn = pending.pop(msg["Accept"], None)
        if pub_conn is not None:
            splice(conn, pub_conn)
        else:
            conn.close()
    else:
        conn.close()

def main():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', CTRL_PORT)); s.listen(64)
    print(f"[fakebore] control on 127.0.0.1:{CTRL_PORT}", flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

main()
