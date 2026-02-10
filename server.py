"""
GOTROOT Recon Agent - API Server
=================================
FastAPI backend with CRUD APIs + serves Web UI.
Run: python server.py
Open: http://localhost:8000
"""

import os
import json
import time
import socket
import ssl
import http.client
import ipaddress
from urllib.parse import urlparse, urljoin
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

import db

app = FastAPI(title="GOTROOT Recon Agent", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])


# ═══════════════════════════════════════
# Sessions API
# ═══════════════════════════════════════

@app.get("/api/sessions")
def api_list_sessions():
    return db.list_sessions()

@app.post("/api/sessions")
async def api_create_session(req: Request):
    data = await req.json()
    sid = db.create_session(
        name=data.get("name", "New Session"),
        target_url=data.get("target_url", ""),
        description=data.get("description", ""))
    return {"id": sid, "status": "created"}

@app.get("/api/sessions/{sid}")
def api_get_session(sid: int):
    s = db.get_session(sid)
    if not s: raise HTTPException(404)
    return s

@app.put("/api/sessions/{sid}")
async def api_update_session(sid: int, req: Request):
    data = await req.json()
    db.update_session(sid, **data)
    return {"status": "updated"}

@app.delete("/api/sessions/{sid}")
def api_delete_session(sid: int):
    db.delete_session(sid)
    return {"status": "deleted"}


# ═══════════════════════════════════════
# Targets API
# ═══════════════════════════════════════

@app.get("/api/targets/{sid}")
def api_list_targets(sid: int):
    return db.list_targets(sid)

@app.post("/api/targets")
async def api_create_target(req: Request):
    data = await req.json()
    sid = data.pop("session_id", None)
    domain = data.pop("domain", "")
    if not sid or not domain:
        raise HTTPException(400, "session_id and domain required")
    tid = db.create_target(sid, domain, **data)
    return {"id": tid, "status": "created"}

@app.put("/api/targets/{tid}")
async def api_update_target(tid: int, req: Request):
    data = await req.json()
    db.update_target(tid, **data)
    return {"status": "updated"}

@app.delete("/api/targets/{tid}")
def api_delete_target(tid: int):
    db.delete_target(tid)
    return {"status": "deleted"}


# ═══════════════════════════════════════
# Findings API
# ═══════════════════════════════════════

@app.get("/api/findings")
def api_list_all_findings():
    return db.list_findings()

@app.get("/api/findings/{sid}")
def api_list_findings(sid: int):
    return db.list_findings(sid)

@app.post("/api/findings")
async def api_create_finding(req: Request):
    data = await req.json()
    sid = data.pop("session_id", None)
    fid = db.create_finding(session_id=sid, **data)
    return {"id": fid, "status": "created"}

@app.put("/api/findings/{fid}")
async def api_update_finding(fid: int, req: Request):
    data = await req.json()
    db.update_finding(fid, **data)
    return {"status": "updated"}

@app.delete("/api/findings/{fid}")
def api_delete_finding(fid: int):
    db.delete_finding(fid)
    return {"status": "deleted"}


# ═══════════════════════════════════════
# Import Recon JSON
# ═══════════════════════════════════════

@app.post("/api/import")
async def api_import(req: Request):
    data = await req.json()
    session_name = data.get("session_name", f"Import {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    recon_data = data.get("recon_data")

    if not recon_data:
        raise HTTPException(400, "recon_data required")

    if isinstance(recon_data, str):
        try:
            recon_data = json.loads(recon_data)
        except:
            raise HTTPException(400, "Invalid JSON")

    sid = db.create_session(name=session_name,
                            target_url=recon_data.get("root_domain", ""))
    count = db.import_recon_json(sid, recon_data)
    return {"session_id": sid, "targets_imported": count, "status": "imported"}


# -------------------- Live Scan --------------------
DEFAULT_PORTS = [80, 443, 8080, 8443, 22, 21, 25, 110, 143, 3306, 5432, 6379, 9200, 27017]
DEFAULT_PATHS = [
    "/admin", "/login", "/signin", "/dashboard", "/.git", "/.env",
    "/phpmyadmin", "/wp-admin", "/server-status", "/api", "/debug"
]

def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False

def _guess_root_domain(host: str) -> str:
    if _is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host

def _normalize_target(raw: str):
    raw = (raw or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    host = p.hostname or raw
    scheme = p.scheme if p.scheme in ("http", "https") else "https"
    port = p.port
    base = f"{scheme}://{host}"
    if port:
        base = f"{base}:{port}"
    return {"raw": raw, "host": host, "scheme": scheme, "port": port, "base": base}

def _parse_ports(raw):
    if raw is None:
        return DEFAULT_PORTS[:]
    if isinstance(raw, list):
        ports = raw
    else:
        s = str(raw)
        ports = []
        for part in s.replace(" ", "").split(","):
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                try:
                    a = int(a); b = int(b)
                    if a > b:
                        a, b = b, a
                    ports.extend(list(range(a, b + 1)))
                except Exception:
                    continue
            else:
                try:
                    ports.append(int(part))
                except Exception:
                    continue
    uniq = sorted({p for p in ports if 0 < int(p) < 65536})
    return uniq

def _parse_paths(raw):
    if raw is None:
        return DEFAULT_PATHS[:]
    if isinstance(raw, list):
        paths = raw
    else:
        paths = str(raw).splitlines()
    cleaned = []
    for p in paths:
        p = str(p).strip()
        if not p:
            continue
        if not p.startswith("/"):
            p = "/" + p
        cleaned.append(p)
    return cleaned or DEFAULT_PATHS[:]

def _resolve_ips(host: str):
    ips = set()
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip = info[4][0]
            ips.add(ip)
    except Exception:
        pass
    return sorted(ips)

def _guess_service(port: int):
    mapping = {
        80: "http", 443: "https", 8080: "http-alt", 8443: "https-alt",
        22: "ssh", 21: "ftp", 25: "smtp", 110: "pop3", 143: "imap",
        3306: "mysql", 5432: "postgres", 6379: "redis", 9200: "elasticsearch",
        27017: "mongodb"
    }
    return mapping.get(int(port), "open")

def _scan_ports(host: str, ports, timeout=1.0):
    open_ports = []
    port_detail = {}
    for p in ports:
        try:
            with socket.create_connection((host, int(p)), timeout=timeout):
                open_ports.append(int(p))
                port_detail[str(p)] = _guess_service(int(p))
        except Exception:
            continue
    return open_ports, port_detail

def _http_request(url: str, method="HEAD", timeout=5):
    p = urlparse(url)
    host = p.hostname
    if not host:
        raise ValueError("invalid host")
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    headers = {"User-Agent": "GOTROOT-Scanner/1.0"}
    if p.scheme == "https":
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.request(method, path, headers=headers)
    resp = conn.getresponse()
    status = resp.status
    hdrs = {k.lower(): v for (k, v) in resp.getheaders()}
    resp.read()
    conn.close()
    return status, hdrs

def _fetch_with_redirects(url: str, timeout=5, max_redirects=5):
    cur = url
    chain = []
    server = ""
    for _ in range(max_redirects + 1):
        try:
            status, headers = _http_request(cur, "HEAD", timeout=timeout)
        except Exception:
            try:
                status, headers = _http_request(cur, "GET", timeout=timeout)
            except Exception:
                return None
        chain.append(status)
        server = headers.get("server", server)
        loc = headers.get("location")
        if status in (301, 302, 303, 307, 308) and loc:
            cur = urljoin(cur, loc)
            continue
        return {"url": url, "final_url": cur, "status": status, "server": server,
                "cdn": False, "cdn_name": "", "cdn_type": "", "chain_status_codes": chain}
    return {"url": url, "final_url": cur, "status": chain[-1] if chain else 0,
            "server": server, "cdn": False, "cdn_name": "", "cdn_type": "",
            "chain_status_codes": chain}

@app.post("/api/scan")
async def api_scan(req: Request):
    data = await req.json()
    target_url = data.get("target_url", "")
    if not target_url:
        raise HTTPException(400, "target_url required")

    parsed = _normalize_target(target_url)
    if not parsed:
        raise HTTPException(400, "invalid target_url")

    opts = data.get("options", {}) or {}
    do_ports = bool(opts.get("port_scan", True))
    do_paths = bool(opts.get("dir_scan", True))
    do_http = bool(opts.get("http_probe", True))
    timeout = float(opts.get("timeout", 3))
    ports = _parse_ports(opts.get("ports"))
    paths = _parse_paths(opts.get("paths"))

    session_name = data.get("session_name") or f"Scan {parsed['host']} {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    sid = db.create_session(name=session_name, target_url=parsed["host"], description="Live scan")
    db.update_session(sid, status="recording")

    ips = _resolve_ips(parsed["host"])
    open_ports, port_detail = ([], {})
    if do_ports:
        open_ports, port_detail = _scan_ports(parsed["host"], ports, timeout=timeout)

    alive = []
    if do_http:
        primary = parsed["base"]
        res = _fetch_with_redirects(primary, timeout=timeout)
        if res:
            alive.append(res)
        # Try http if https failed
        if not alive and parsed["scheme"] == "https":
            fallback = primary.replace("https://", "http://", 1)
            res = _fetch_with_redirects(fallback, timeout=timeout)
            if res:
                alive.append(res)

    dirb = []
    if do_paths:
        base = alive[0]["final_url"] if alive else parsed["base"]
        for p in paths:
            try:
                status, _ = _http_request(urljoin(base, p), "HEAD", timeout=timeout)
            except Exception:
                try:
                    status, _ = _http_request(urljoin(base, p), "GET", timeout=timeout)
                except Exception:
                    continue
            if status in (200, 204, 301, 302, 307, 308, 401, 403):
                dirb.append(p)

    recon_data = {
        "root_domain": _guess_root_domain(parsed["host"]),
        "targets": [{
            "domain": parsed["host"],
            "ips": ips,
            "ports": open_ports,
            "port_detail": port_detail,
            "dns_meta": {"ptr": {"exists": False, "values": [], "forward_match": False}},
            "alive": alive,
            "dirb": dirb,
            "infra": {}
        }]
    }

    count = db.import_recon_json(sid, recon_data)
    db.update_session(sid, status="done", target_url=recon_data["root_domain"])
    return {
        "session_id": sid,
        "targets_imported": count,
        "status": "scanned",
        "summary": {
            "ips": len(ips),
            "ports": len(open_ports),
            "alive": len(alive),
            "paths": len(dirb)
        }
    }

# ═══════════════════════════════════════
# Graph API
# ═══════════════════════════════════════

@app.get("/api/graph/{sid}")
def api_get_graph(sid: int):
    return db.get_graph(sid)

@app.delete("/api/graph/{sid}")
def api_clear_graph(sid: int):
    db.clear_graph(sid)
    return {"status": "cleared"}


# ═══════════════════════════════════════
# Correlations API
# ═══════════════════════════════════════

@app.get("/api/correlations/{sid}")
def api_list_correlations(sid: int):
    return db.list_correlations(sid)


# ═══════════════════════════════════════
# Stats
# ═══════════════════════════════════════

@app.get("/api/stats")
def api_stats():
    sessions = db.list_sessions()
    all_findings = db.list_findings()
    sev_count = {}
    for f in all_findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1
    return {
        "sessions": len(sessions),
        "findings": len(all_findings),
        "severity": sev_count,
        "active_sessions": sum(1 for s in sessions if s["status"] not in ("idle","done")),
    }

@app.get("/api/health")
def api_health():
    return {"status": "ok", "version": "1.0", "db": db.DB_PATH}


# ═══════════════════════════════════════
# Serve Web UI
# ═══════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
def serve_ui():
    # Try to load from file first, fallback to minimal
    ui_path = os.path.join(os.path.dirname(__file__), "ui.html")
    if os.path.exists(ui_path):
        with open(ui_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<html><body><h1>GOTROOT Recon Agent</h1><p>ui.html not found</p></body></html>"


# ═══════════════════════════════════════
# Main
# ═══════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"""
  ╔══════════════════════════════════════════╗
  ║  GOTROOT Recon Agent v1.0               ║
  ╚══════════════════════════════════════════╝

  Web UI:  http://localhost:{port}
  API:     http://localhost:{port}/api/health
  DB:      {db.DB_PATH}
""")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
