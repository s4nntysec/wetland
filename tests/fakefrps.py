#!/usr/bin/env python3
# Minimal frp server (fatedier/frp, tcpMux=false) for testing wld's frp client.
# Framing: [1 type byte][8-byte big-endian length][JSON]. Flow:
#   Login('o')->LoginResp('1'); NewProxy('p')->NewProxyResp('2'); for each public
#   connection send ReqWorkConn('r'); the client dials a work conn and sends
#   NewWorkConn('w'); we reply StartWorkConn('s') and splice public<->work.
import socket, threading, json, sys, uuid, select, queue

CTRL_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7000
pending = queue.Queue()   # public connections awaiting a work conn (single proxy)

def readmsg(sock, buf):
    while len(buf[0]) < 9:
        d = sock.recv(4096)
        if not d: return None, None
        buf[0] += d
    t = chr(buf[0][0]); L = int.from_bytes(buf[0][1:9], 'big')
    while len(buf[0]) < 9 + L:
        d = sock.recv(4096)
        if not d: return None, None
        buf[0] += d
    payload = buf[0][9:9+L]; buf[0] = buf[0][9+L:]
    return t, (json.loads(payload) if L else {})

def writemsg(sock, t, obj):
    p = json.dumps(obj).encode()
    sock.sendall(t.encode() + len(p).to_bytes(8, 'big') + p)

def splice(a, b, pre=b''):
    if pre:
        try: b.sendall(pre)
        except OSError: pass
    aeof = beof = False
    try:
        while not (aeof and beof):
            rl = [s for s, e in ((a, aeof), (b, beof)) if not e]
            if not rl: break
            r, _, _ = select.select(rl, [], [])
            if a in r:
                d = a.recv(65536)
                if not d: aeof = True; b.shutdown(socket.SHUT_WR)
                else: b.sendall(d)
            if b in r:
                d = b.recv(65536)
                if not d: beof = True; a.shutdown(socket.SHUT_WR)
                else: a.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try: s.close()
            except OSError: pass

def public_acceptor(pub, ctrl):
    while True:
        try: conn, _ = pub.accept()
        except OSError: return
        pending.put(conn)
        try: writemsg(ctrl, 'r', {})       # ReqWorkConn
        except OSError: return

def handle_control(sock, buf, login):
    run_id = str(uuid.uuid4())
    writemsg(sock, '1', {"version": "0.58.1", "run_id": run_id, "error": ""})
    # expect NewProxy
    t, msg = readmsg(sock, buf)
    if t != 'p':
        sock.close(); return
    want = int(msg.get("remote_port", 0) or 0)
    pub = socket.socket(); pub.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        pub.bind(('127.0.0.1', want));
    except OSError:
        pub.bind(('127.0.0.1', 0))
    pub.listen(16)
    port = pub.getsockname()[1]
    writemsg(sock, '2', {"proxy_name": msg.get("proxy_name", ""), "remote_addr": f":{port}", "error": ""})
    print(f"[fakefrps] proxy bound on 127.0.0.1:{port}", flush=True)
    threading.Thread(target=public_acceptor, args=(pub, sock), daemon=True).start()
    # control loop: answer Ping with Pong
    try:
        while True:
            t, msg = readmsg(sock, buf)
            if t is None: break
            if t == 'h': writemsg(sock, '4', {"error": ""})
    except OSError:
        pass

def handle_work(sock, buf):
    # pair with the oldest pending public connection
    try: pub_conn = pending.get(timeout=10)
    except queue.Empty:
        sock.close(); return
    writemsg(sock, 's', {"proxy_name": "wld", "error": ""})   # StartWorkConn
    # any bytes already buffered on the work conn are raw proxy data
    splice(pub_conn, sock, pre=bytes(buf[0]))

def handle(sock):
    buf = [b'']
    t, msg = readmsg(sock, buf)
    if t == 'o':
        handle_control(sock, buf, msg)
    elif t == 'w':
        handle_work(sock, buf)
    else:
        sock.close()

def main():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', CTRL_PORT)); s.listen(64)
    print(f"[fakefrps] control on 127.0.0.1:{CTRL_PORT}", flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

main()
