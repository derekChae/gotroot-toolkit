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
