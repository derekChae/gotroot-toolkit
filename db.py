"""
GOTROOT Recon Agent - Database Layer
=====================================
SQLite database for persistent storage of recon sessions,
targets, events, correlation groups, findings, and graph data.
"""

import sqlite3
import json
import os
import time
from datetime import datetime
from contextlib import contextmanager

DB_PATH = os.environ.get("GR_DB_PATH", "gr_recon.db")


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target_url TEXT NOT NULL DEFAULT '',
            description TEXT DEFAULT '',
            status TEXT DEFAULT 'idle',
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            root_domain TEXT DEFAULT '',
            ips TEXT DEFAULT '[]',
            ports TEXT DEFAULT '[]',
            port_detail TEXT DEFAULT '{}',
            dns_meta TEXT DEFAULT '{}',
            alive TEXT DEFAULT '[]',
            dirb TEXT DEFAULT '[]',
            infra TEXT DEFAULT '{}',
            risk_score INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            timestamp REAL NOT NULL,
            event_type TEXT NOT NULL,
            data TEXT DEFAULT '{}',
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            trigger_time REAL NOT NULL,
            click_element TEXT DEFAULT '',
            click_coords TEXT DEFAULT '[]',
            click_selector TEXT DEFAULT '',
            ui_label TEXT DEFAULT '',
            risk_note TEXT DEFAULT '',
            endpoints TEXT DEFAULT '[]',
            dom_changes TEXT DEFAULT '[]',
            screenshot_before TEXT DEFAULT '',
            screenshot_after TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            correlation_id INTEGER,
            title TEXT NOT NULL,
            severity TEXT DEFAULT 'INFO',
            category TEXT DEFAULT '',
            detail TEXT DEFAULT '',
            recommendation TEXT DEFAULT '',
            endpoint TEXT DEFAULT '',
            screenshot TEXT DEFAULT '',
            status TEXT DEFAULT 'open',
            created_at TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS graph_nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            node_id TEXT NOT NULL,
            node_type TEXT NOT NULL,
            label TEXT NOT NULL,
            data TEXT DEFAULT '{}',
            risk_score INTEGER DEFAULT 0,
            x REAL DEFAULT 0,
            y REAL DEFAULT 0,
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
            UNIQUE(session_id, node_id)
        );

        CREATE TABLE IF NOT EXISTS graph_edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            source_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            edge_type TEXT DEFAULT 'connects',
            label TEXT DEFAULT '',
            data TEXT DEFAULT '{}',
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );
        """)


# ═══════════════════════════════════════
# Sessions CRUD
# ═══════════════════════════════════════

def create_session(name, target_url="", description=""):
    with get_db() as db:
        c = db.execute(
            "INSERT INTO sessions(name,target_url,description) VALUES(?,?,?)",
            (name, target_url, description))
        return c.lastrowid

def list_sessions():
    with get_db() as db:
        rows = db.execute("""
            SELECT s.*, 
                   COUNT(DISTINCT t.id) as target_count,
                   COUNT(DISTINCT f.id) as finding_count,
                   COUNT(DISTINCT c.id) as correlation_count
            FROM sessions s
            LEFT JOIN targets t ON t.session_id=s.id
            LEFT JOIN findings f ON f.session_id=s.id
            LEFT JOIN correlations c ON c.session_id=s.id
            GROUP BY s.id ORDER BY s.updated_at DESC
        """).fetchall()
        return [dict(r) for r in rows]

def get_session(sid):
    with get_db() as db:
        r = db.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        return dict(r) if r else None

def update_session(sid, **kwargs):
    allowed = {"name", "target_url", "description", "status"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return False
    fields["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sets = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values()) + [sid]
    with get_db() as db:
        db.execute(f"UPDATE sessions SET {sets} WHERE id=?", vals)
    return True

def delete_session(sid):
    with get_db() as db:
        db.execute("DELETE FROM sessions WHERE id=?", (sid,))
    return True


# ═══════════════════════════════════════
# Targets CRUD
# ═══════════════════════════════════════

def create_target(session_id, domain, **kwargs):
    json_fields = {"ips", "ports", "port_detail", "dns_meta", "alive", "dirb", "infra"}
    params = {"session_id": session_id, "domain": domain}
    for k, v in kwargs.items():
        if k in json_fields:
            params[k] = json.dumps(v) if not isinstance(v, str) else v
        else:
            params[k] = v
    cols = ", ".join(params.keys())
    placeholders = ", ".join("?" * len(params))
    with get_db() as db:
        c = db.execute(f"INSERT INTO targets({cols}) VALUES({placeholders})",
                       list(params.values()))
        return c.lastrowid

def list_targets(session_id):
    with get_db() as db:
        rows = db.execute("SELECT * FROM targets WHERE session_id=? ORDER BY risk_score DESC",
                          (session_id,)).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for k in ["ips","ports","port_detail","dns_meta","alive","dirb","infra"]:
                try:
                    d[k] = json.loads(d[k]) if d[k] else {}
                except:
                    pass
            result.append(d)
        return result

def get_target(tid):
    with get_db() as db:
        r = db.execute("SELECT * FROM targets WHERE id=?", (tid,)).fetchone()
        if not r:
            return None
        d = dict(r)
        for k in ["ips","ports","port_detail","dns_meta","alive","dirb","infra"]:
            try:
                d[k] = json.loads(d[k]) if d[k] else {}
            except:
                pass
        return d

def update_target(tid, **kwargs):
    json_fields = {"ips","ports","port_detail","dns_meta","alive","dirb","infra"}
    fields = {}
    for k, v in kwargs.items():
        if k in json_fields:
            fields[k] = json.dumps(v) if not isinstance(v, str) else v
        elif k in {"domain","root_domain","risk_score"}:
            fields[k] = v
    if not fields:
        return False
    sets = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values()) + [tid]
    with get_db() as db:
        db.execute(f"UPDATE targets SET {sets} WHERE id=?", vals)
    return True

def delete_target(tid):
    with get_db() as db:
        db.execute("DELETE FROM targets WHERE id=?", (tid,))
    return True


# ═══════════════════════════════════════
# Findings CRUD
# ═══════════════════════════════════════

def create_finding(session_id=None, **kwargs):
    params = {"session_id": session_id}
    allowed = {"title","severity","category","detail","recommendation",
               "endpoint","screenshot","status","correlation_id"}
    for k, v in kwargs.items():
        if k in allowed:
            params[k] = v
    cols = ", ".join(params.keys())
    placeholders = ", ".join("?" * len(params))
    with get_db() as db:
        c = db.execute(f"INSERT INTO findings({cols}) VALUES({placeholders})",
                       list(params.values()))
        return c.lastrowid

def list_findings(session_id=None):
    with get_db() as db:
        if session_id:
            rows = db.execute(
                "SELECT * FROM findings WHERE session_id=? ORDER BY "
                "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
                "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END",
                (session_id,)).fetchall()
        else:
            rows = db.execute("SELECT * FROM findings ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

def update_finding(fid, **kwargs):
    allowed = {"title","severity","category","detail","recommendation",
               "endpoint","screenshot","status"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return False
    sets = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values()) + [fid]
    with get_db() as db:
        db.execute(f"UPDATE findings SET {sets} WHERE id=?", vals)
    return True

def delete_finding(fid):
    with get_db() as db:
        db.execute("DELETE FROM findings WHERE id=?", (fid,))
    return True


# ═══════════════════════════════════════
# Correlations
# ═══════════════════════════════════════

def save_correlation(session_id, group):
    with get_db() as db:
        db.execute("""
            INSERT INTO correlations(session_id, group_id, trigger_time,
                click_element, click_coords, click_selector, ui_label, risk_note,
                endpoints, dom_changes, screenshot_before, screenshot_after)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (session_id, group.get("group_id",0), group.get("trigger_time",0),
             group.get("click_element",""), json.dumps(group.get("click_coords",[])),
             group.get("click_selector",""), group.get("ui_label",""),
             group.get("risk_note",""), json.dumps(group.get("endpoints",[])),
             json.dumps(group.get("dom_changes",[])),
             group.get("screenshot_before",""), group.get("screenshot_after","")))

def list_correlations(session_id):
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM correlations WHERE session_id=? ORDER BY trigger_time",
            (session_id,)).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for k in ["click_coords","endpoints","dom_changes"]:
                try:
                    d[k] = json.loads(d[k])
                except:
                    pass
            result.append(d)
        return result


# ═══════════════════════════════════════
# Graph Nodes & Edges
# ═══════════════════════════════════════

def save_node(session_id, node_id, node_type, label, data=None, risk_score=0):
    with get_db() as db:
        db.execute("""
            INSERT OR REPLACE INTO graph_nodes(session_id,node_id,node_type,label,data,risk_score)
            VALUES(?,?,?,?,?,?)""",
            (session_id, node_id, node_type, label,
             json.dumps(data or {}), risk_score))

def save_edge(session_id, source_id, target_id, edge_type="connects", label="", data=None):
    with get_db() as db:
        db.execute("""
            INSERT INTO graph_edges(session_id,source_id,target_id,edge_type,label,data)
            VALUES(?,?,?,?,?,?)""",
            (session_id, source_id, target_id, edge_type, label,
             json.dumps(data or {})))

def get_graph(session_id):
    with get_db() as db:
        nodes = db.execute(
            "SELECT * FROM graph_nodes WHERE session_id=?", (session_id,)).fetchall()
        edges = db.execute(
            "SELECT * FROM graph_edges WHERE session_id=?", (session_id,)).fetchall()
        return {
            "nodes": [{**dict(n), "data": json.loads(n["data"] or "{}")} for n in nodes],
            "links": [{**dict(e), "source": e["source_id"], "target": e["target_id"],
                        "data": json.loads(e["data"] or "{}")} for e in edges]
        }

def clear_graph(session_id):
    with get_db() as db:
        db.execute("DELETE FROM graph_nodes WHERE session_id=?", (session_id,))
        db.execute("DELETE FROM graph_edges WHERE session_id=?", (session_id,))


# ═══════════════════════════════════════
# Import Recon JSON → Graph
# ═══════════════════════════════════════

def import_recon_json(session_id, data):
    """Import the recon JSON format into targets + graph nodes/edges"""
    root_domain = data.get("root_domain", "unknown")
    targets_data = data.get("targets", [])

    # Root domain node
    save_node(session_id, f"domain:{root_domain}", "domain", root_domain,
              {"type": "root_domain"}, risk_score=10)

    imported = 0
    for t in targets_data:
        domain = t.get("domain", "")
        if not domain:
            continue

        # Save target to DB
        tid = create_target(
            session_id=session_id, domain=domain, root_domain=root_domain,
            ips=t.get("ips", []), ports=t.get("ports", []),
            port_detail=t.get("port_detail", {}), dns_meta=t.get("dns_meta", {}),
            alive=t.get("alive", []), dirb=t.get("dirb", []),
            infra=t.get("infra", {}))

        # Calculate risk score
        risk = _calc_risk(t)
        update_target(tid, risk_score=risk)

        # Domain node
        save_node(session_id, f"domain:{domain}", "subdomain", domain,
                  {"target_id": tid, "infra": t.get("infra", {})}, risk_score=risk)
        save_edge(session_id, f"domain:{root_domain}", f"domain:{domain}",
                  "has_subdomain", domain.split(".")[0])

        # IP nodes
        for ip in t.get("ips", []):
            save_node(session_id, f"ip:{ip}", "ip", ip,
                      {"ptr": t.get("dns_meta", {}).get("ptr", {}).get("values", [])})
            save_edge(session_id, f"domain:{domain}", f"ip:{ip}", "resolves_to")

        # Port nodes
        port_detail = t.get("port_detail", {})
        for port in t.get("ports", []):
            p_str = str(port)
            service = port_detail.get(p_str, port_detail.get(port, "unknown"))
            if not isinstance(service, str):
                service = str(service)
            p_risk = _port_risk(port, service)
            save_node(session_id, f"port:{domain}:{port}", "port",
                      f":{port} ({service})", {"service": service, "port": port}, p_risk)
            save_edge(session_id, f"domain:{domain}", f"port:{domain}:{port}", "exposes")

        # Alive URLs
        for alive in t.get("alive", []):
            url = alive.get("url", "")
            if url:
                save_node(session_id, f"url:{url}", "url", url,
                          {"server": alive.get("server",""), "cdn": alive.get("cdn_name",""),
                           "status": alive.get("status",0), "chain": alive.get("chain_status_codes",[])})
                save_edge(session_id, f"domain:{domain}", f"url:{url}", "serves")

                final = alive.get("final_url", "")
                if final and final != url:
                    save_node(session_id, f"url:{final}", "url", final, {"type": "redirect_target"})
                    save_edge(session_id, f"url:{url}", f"url:{final}", "redirects_to")

        # Directory bruteforce results
        for path in t.get("dirb", []):
            if isinstance(path, str):
                path = path.strip()
                if path:
                    p_risk = _path_risk(path)
                    save_node(session_id, f"path:{domain}{path}", "path", path,
                              {"domain": domain}, p_risk)
                    save_edge(session_id, f"domain:{domain}", f"path:{domain}{path}", "contains")

                    # Auto-generate findings for sensitive paths
                    if p_risk >= 60:
                        create_finding(session_id=session_id, title=f"Sensitive Path: {path}",
                                       severity="HIGH" if p_risk >= 80 else "MEDIUM",
                                       category="Exposure", endpoint=f"{domain}{path}",
                                       detail=f"Directory bruteforce found {path} on {domain}",
                                       recommendation=f"Restrict access to {path}")

        imported += 1

    # Update session
    update_session(session_id, status="imported",
                   target_url=root_domain)
    return imported


def _calc_risk(target):
    score = 0
    ports = target.get("ports", [])
    if 8080 in ports: score += 15
    if 3306 in ports: score += 25
    if 22 in ports: score += 10

    port_detail = target.get("port_detail", {})
    for p, svc in port_detail.items():
        svc_str = str(svc).lower()
        if "apache 2.4.49" in svc_str: score += 40  # CVE-2021-41773
        if "apache 2.4.50" in svc_str: score += 35  # CVE-2021-42013
        if "nginx 1.0" in svc_str: score += 20

    for path in target.get("dirb", []):
        score += _path_risk(str(path)) // 5

    if target.get("infra", {}).get("type") == "cloud":
        score += 5

    return min(score, 100)


def _port_risk(port, service=""):
    svc = str(service).lower()
    risk = 0
    high_ports = {21:25, 22:15, 23:30, 25:10, 3306:30, 5432:30, 6379:35,
                  8080:15, 8443:10, 9200:25, 27017:35}
    risk += high_ports.get(int(port), 5)
    if "apache 2.4.49" in svc: risk += 40
    return min(risk, 100)


def _path_risk(path):
    path = path.lower().strip()
    high = {"/admin":80, "/phpmyadmin":90, "/.env":95, "/.git":95,
            "/.htaccess":85, "/backup":75, "/wp-admin":80, "/debug":70,
            "/server-status":70, "/phpinfo":75, "/console":80, "/shell":95}
    for p, r in high.items():
        if p in path:
            return r
    if "/api" in path: return 30
    if "/login" in path: return 40
    return 10


# Initialize on import
init_db()
