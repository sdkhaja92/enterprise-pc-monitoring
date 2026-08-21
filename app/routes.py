from flask import Blueprint, jsonify, render_template, request, current_app, redirect, url_for, session
from datetime import datetime, timezone
from .database import get_db
from .auth import login_required, role_required, current_user
from .services import valid_api_key, store_metrics, create_ticket as service_create_ticket, normalize_ioc, refresh_ioc_matches
from .ai import get_ai_settings, save_ai_settings, test_ai_connection, analyze_alert, analyze_incident, list_models

web_bp = Blueprint("web", __name__)
api_bp = Blueprint("api", __name__)


def api_authenticated():
    """Allow API access for an authenticated browser session or a valid agent API key."""
    user = current_user()
    if user:
        return True
    header_key = request.headers.get("X-API-Key", "")
    auth = request.headers.get("Authorization", "")
    bearer = auth[7:] if auth.lower().startswith("bearer ") else ""
    body = request.get_json(silent=True) or {}
    return valid_api_key(header_key or bearer or body.get("api_key"))


def api_login_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not api_authenticated():
            return jsonify({"ok": False, "error": "Authentication required"}), 401
        return view(*args, **kwargs)
    return wrapped


@web_bp.get("/")
@login_required
def dashboard():
    conn = get_db()
    rows = conn.execute("SELECT * FROM pcs ORDER BY pc_name").fetchall()
    alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE resolved=0"
    ).fetchone()[0]
    tickets = conn.execute(
        "SELECT COUNT(*) FROM tickets WHERE status='Open'"
    ).fetchone()[0]
    conn.close()

    now = datetime.now(timezone.utc)
    pcs = []

    for row in rows:
        item = dict(row)
        status = "Offline"
        if row["last_seen"]:
            try:
                seen = datetime.fromisoformat(row["last_seen"])
                age = (now - seen).total_seconds()
                if age <= current_app.config["ONLINE_WINDOW_SECONDS"]:
                    status = "Online"
            except ValueError:
                pass
        item["status"] = status
        pcs.append(item)

    online = sum(1 for p in pcs if p["status"] == "Online")

    conn = get_db()
    active_alerts = [dict(x) for x in conn.execute("""
        SELECT pc_name, severity, message, created_at
        FROM alerts WHERE resolved=0
        ORDER BY id DESC LIMIT 8
    """).fetchall()]
    conn.close()

    return render_template(
        "dashboard.html",
        user=current_user(),
        pcs=pcs,
        active_alerts=active_alerts,
        stats={
            "pcs": len(pcs),
            "online": online,
            "alerts": alerts,
            "tickets": tickets,
        }
    )


@web_bp.get("/endpoint/<path:pc_name>")
@login_required
def endpoint_detail(pc_name):
    conn = get_db()
    pc = conn.execute(
        "SELECT * FROM pcs WHERE pc_name=?",
        (pc_name,)
    ).fetchone()

    if pc is None:
        conn.close()
        return "Endpoint not found", 404

    metrics = conn.execute("""
        SELECT cpu, ram, disk, gpu, created_at
        FROM metrics
        WHERE pc_name=?
        ORDER BY id DESC
        LIMIT 60
    """, (pc_name,)).fetchall()

    alerts = conn.execute("""
        SELECT severity, message, created_at, resolved
        FROM alerts
        WHERE pc_name=?
        ORDER BY id DESC
        LIMIT 20
    """, (pc_name,)).fetchall()

    hardware = conn.execute(
        "SELECT * FROM endpoint_hardware WHERE pc_name=?",
        (pc_name,)
    ).fetchone()

    conn.close()

    from datetime import datetime, timezone
    status = "Offline"
    try:
        seen = datetime.fromisoformat(pc["last_seen"])
        if (datetime.now(timezone.utc) - seen).total_seconds() <= current_app.config["ONLINE_WINDOW_SECONDS"]:
            status = "Online"
    except Exception:
        pass

    return render_template(
        "endpoint.html",
        pc=dict(pc),
        status=status,
        metrics=[dict(x) for x in reversed(metrics)],
        alerts=[dict(x) for x in alerts],
        hardware=dict(hardware) if hardware else {},
    )


@web_bp.get("/ai-settings")
@role_required("Admin")
def ai_settings():
    return render_template("ai_settings.html", user=current_user(), settings=get_ai_settings(include_secret=False), saved=request.args.get("saved") == "1", error=request.args.get("error"))


@web_bp.post("/ai-settings")
@role_required("Admin")
def ai_settings_save():
    try:
        save_ai_settings(request.form, username=session.get("username"))
        return redirect(url_for("web.ai_settings", saved="1"))
    except Exception as exc:
        return redirect(url_for("web.ai_settings", error=str(exc)))


@web_bp.post("/ai/models")
@role_required("Admin")
def ai_models():
    try:
        settings = get_ai_settings(include_secret=True)
        for key in ("provider", "base_url", "model", "timeout"):
            if key in request.form:
                settings[key] = request.form.get(key)
        if request.form.get("api_key") not in (None, "", "********"):
            settings["api_key"] = request.form.get("api_key")
        # HTML forms submit strings; the AI layer normalizes timeout and flags.
        return jsonify({"ok": True, "models": list_models(settings)})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@web_bp.post("/ai/test")
@role_required("Admin")
def ai_test():
    try:
        settings = get_ai_settings(include_secret=True)
        if request.form:
            for key in ("provider", "base_url", "model", "timeout"):
                if key in request.form:
                    settings[key] = request.form.get(key)
            if request.form.get("api_key") not in (None, "", "********"):
                settings["api_key"] = request.form.get("api_key")
            # Test is intentionally allowed even when the Copilot checkbox is
            # currently off; it validates the selected provider configuration.
            settings["enabled"] = 1
            settings["privacy_mode"] = 1 if request.form.get("privacy_mode") else 0
        result = test_ai_connection(settings)
        return jsonify({"ok": True, "message": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@web_bp.post("/alerts/<int:alert_id>/ai-analyze")
@role_required("Admin", "Operator")
def ai_analyze_alert(alert_id):
    try:
        result = analyze_alert(alert_id)
        return jsonify({"ok": True, "analysis": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@web_bp.post("/incidents/<int:incident_id>/ai-analyze")
@role_required("Admin", "Operator")
def ai_analyze_incident(incident_id):
    try:
        result = analyze_incident(incident_id)
        return jsonify({"ok": True, "analysis": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@api_bp.post("/update")
@api_login_required
def update():
    data = request.get_json(silent=True) or {}

    if not valid_api_key(data.get("api_key")):
        return jsonify({"ok": False, "error": "Invalid API key"}), 401

    if not data.get("pc_name"):
        return jsonify({"ok": False, "error": "pc_name is required"}), 400

    store_metrics(data)
    return jsonify({"ok": True, "message": "Endpoint metrics updated"})


@api_bp.get("/pcs")
@api_login_required
def pcs():
    conn = get_db()
    rows = [dict(r) for r in conn.execute(
        "SELECT pc_name,ip,cpu,ram,disk,department,last_seen FROM pcs ORDER BY pc_name"
    ).fetchall()]
    conn.close()
    return jsonify(rows)


@api_bp.get("/pcs/<path:pc_name>/metrics")
@api_login_required
def pc_metrics(pc_name):
    limit = request.args.get("limit", default=60, type=int)
    limit = max(1, min(limit, 500))

    conn = get_db()
    rows = [dict(r) for r in conn.execute(
        f"""
        SELECT cpu,ram,disk,gpu,created_at
        FROM metrics
        WHERE pc_name=?
        ORDER BY id DESC
        LIMIT {limit}
        """,
        (pc_name,)
    ).fetchall()]
    conn.close()

    rows.reverse()
    return jsonify(rows)


@api_bp.get("/alerts")
@api_login_required
def alerts():
    conn = get_db()
    rows = [dict(x) for x in conn.execute(
        "SELECT * FROM alerts WHERE resolved=0 ORDER BY id DESC"
    ).fetchall()]
    conn.close()
    return jsonify(rows)


@api_bp.post("/tickets")
@api_login_required
def tickets():
    data = request.get_json(silent=True) or {}

    if not valid_api_key(data.get("api_key")):
        return jsonify({"ok": False, "error": "Invalid API key"}), 401

    if not data.get("title"):
        return jsonify({"ok": False, "error": "title is required"}), 400

    ticket_id = service_create_ticket(data)
    return jsonify({"ok": True, "ticket_id": ticket_id})






@web_bp.get("/tickets")
@login_required
def ticket_center():
    conn=get_db()
    tickets=[dict(x) for x in conn.execute("""
        SELECT id,pc_name,alert_id,title,description,priority,status,assignee,created_at,updated_at
        FROM tickets ORDER BY id DESC LIMIT 500
    """).fetchall()]
    summary={
        "open":conn.execute("SELECT COUNT(*) FROM tickets WHERE status='Open'").fetchone()[0],
        "progress":conn.execute("SELECT COUNT(*) FROM tickets WHERE status='In Progress'").fetchone()[0],
        "resolved":conn.execute("SELECT COUNT(*) FROM tickets WHERE status='Resolved'").fetchone()[0],
        "total":conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0],
    }
    conn.close()
    return render_template("tickets.html",tickets=tickets,summary=summary)

@web_bp.post("/tickets/create")
@role_required('Admin','Operator')
def create_ticket():
    data=request.form
    pc_name=(data.get("pc_name") or "").strip()
    title=(data.get("title") or "").strip()
    description=(data.get("description") or "").strip()
    if not pc_name or not title or not description:
        return jsonify({"ok":False,"error":"PC, title and description are required"}),400
    import datetime
    now=datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn=get_db()
    cur=conn.execute("""
        INSERT INTO tickets(pc_name,alert_id,title,description,priority,status,assignee,created_at,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?)
    """,(pc_name,int(data.get("alert_id")) if data.get("alert_id") else None,title,description,
        data.get("priority","Medium"),"Open",data.get("assignee","IT Operations"),now,now))
    conn.commit(); ticket_id=cur.lastrowid; conn.close()
    return jsonify({"ok":True,"ticket_id":ticket_id})

@web_bp.post("/tickets/<int:ticket_id>/status")
@role_required('Admin','Operator')
def update_ticket_status(ticket_id):
    status=request.form.get("status","Open")
    if status not in ("Open","In Progress","Resolved"):
        return jsonify({"ok":False,"error":"Invalid status"}),400
    import datetime
    now=datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn=get_db()
    conn.execute("UPDATE tickets SET status=?,updated_at=? WHERE id=?",(status,now,ticket_id))
    conn.commit(); conn.close()
    return jsonify({"ok":True})

@web_bp.post("/alerts/<int:alert_id>/ticket")
@role_required('Admin','Operator')
def create_ticket_from_alert(alert_id):
    conn=get_db()
    alert=conn.execute("SELECT id,pc_name,severity,message FROM alerts WHERE id=?",(alert_id,)).fetchone()
    if not alert:
        conn.close(); return jsonify({"ok":False,"error":"Alert not found"}),404
    import datetime
    now=datetime.datetime.now(datetime.timezone.utc).isoformat()
    priority="High" if alert["severity"]=="High" else "Medium"
    title=f"{alert['severity']} Alert — {alert['pc_name']}"
    cur=conn.execute("""
        INSERT INTO tickets(pc_name,alert_id,title,description,priority,status,assignee,created_at,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?)
    """,(alert["pc_name"],alert["id"],title,alert["message"],priority,"Open","IT Operations",now,now))
    conn.commit(); tid=cur.lastrowid; conn.close()
    return jsonify({"ok":True,"ticket_id":tid})

@web_bp.get("/alerts")
@login_required
def alert_center():
    conn = get_db()
    alerts = [dict(x) for x in conn.execute("""
        SELECT id, pc_name, severity, message, created_at, resolved
        FROM alerts
        ORDER BY resolved ASC, id DESC
        LIMIT 500
    """).fetchall()]
    for alert in alerts:
        row = conn.execute("""
            SELECT created_at, provider, model FROM ai_analysis
            WHERE target_type='alert' AND target_id=?
            ORDER BY id DESC LIMIT 1
        """, (alert["id"],)).fetchone()
        alert["ai_analyzed"] = bool(row)
        alert["ai_last_analyzed"] = dict(row) if row else None

    summary = {
        "active": conn.execute("SELECT COUNT(*) FROM alerts WHERE resolved=0").fetchone()[0],
        "high": conn.execute("SELECT COUNT(*) FROM alerts WHERE resolved=0 AND severity='High'").fetchone()[0],
        "warning": conn.execute("SELECT COUNT(*) FROM alerts WHERE resolved=0 AND severity='Warning'").fetchone()[0],
        "resolved": conn.execute("SELECT COUNT(*) FROM alerts WHERE resolved=1").fetchone()[0],
    }
    conn.close()
    return render_template("alerts.html", alerts=alerts, summary=summary, user=current_user())


@web_bp.post("/alerts/<int:alert_id>/resolve")
@role_required('Admin','Operator')
def resolve_alert(alert_id):
    conn = get_db()
    conn.execute("UPDATE alerts SET resolved=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@api_bp.post("/alerts/<int:alert_id>/resolve")
@api_login_required
def api_resolve_alert(alert_id):
    data = request.get_json(silent=True) or {}
    if not valid_api_key(data.get("api_key")):
        return jsonify({"ok": False, "error": "Invalid API key"}), 401
    conn = get_db()
    cur = conn.execute("UPDATE alerts SET resolved=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "updated": cur.rowcount})

@web_bp.get("/endpoint/<path:pc_name>/software")
@login_required
def software_inventory(pc_name):
    conn = get_db()
    pc = conn.execute("SELECT * FROM pcs WHERE pc_name=?", (pc_name,)).fetchone()
    if pc is None:
        conn.close()
        return "Endpoint not found", 404
    software = [dict(x) for x in conn.execute(
        "SELECT name,version,publisher,install_date,architecture,updated_at FROM software_inventory WHERE pc_name=? ORDER BY name COLLATE NOCASE",
        (pc_name,)
    ).fetchall()]
    conn.close()
    return render_template("software.html", pc=dict(pc), software=software)

@api_bp.get("/pcs/<path:pc_name>/software")
@api_login_required
def pc_software(pc_name):
    conn = get_db()
    rows = [dict(x) for x in conn.execute(
        "SELECT name,version,publisher,install_date,architecture,updated_at FROM software_inventory WHERE pc_name=? ORDER BY name COLLATE NOCASE",
        (pc_name,)
    ).fetchall()]
    conn.close()
    return jsonify(rows)


@web_bp.get("/endpoint/<path:pc_name>/processes")
@login_required
def process_service_inventory(pc_name):
    conn = get_db()
    pc = conn.execute("SELECT * FROM pcs WHERE pc_name=?", (pc_name,)).fetchone()
    if pc is None:
        conn.close()
        return "Endpoint not found", 404
    processes = [dict(x) for x in conn.execute(
        "SELECT pid,name,username,cpu_percent,memory_mb,status,collected_at FROM process_inventory WHERE pc_name=? ORDER BY cpu_percent DESC, memory_mb DESC LIMIT 100",
        (pc_name,)
    ).fetchall()]
    services = [dict(x) for x in conn.execute(
        "SELECT service_name,display_name,state,start_mode,collected_at FROM service_inventory WHERE pc_name=? ORDER BY service_name COLLATE NOCASE LIMIT 500",
        (pc_name,)
    ).fetchall()]
    conn.close()
    return render_template("processes.html", pc=dict(pc), processes=processes, services=services)


@api_bp.get("/pcs/<path:pc_name>/processes")
@api_login_required
def pc_processes(pc_name):
    conn = get_db()
    rows = [dict(x) for x in conn.execute(
        "SELECT pid,name,username,cpu_percent,memory_mb,status,collected_at FROM process_inventory WHERE pc_name=? ORDER BY cpu_percent DESC, memory_mb DESC LIMIT 100",
        (pc_name,)
    ).fetchall()]
    conn.close()
    return jsonify(rows)


@api_bp.get("/pcs/<path:pc_name>/services")
@api_login_required
def pc_services(pc_name):
    conn = get_db()
    rows = [dict(x) for x in conn.execute(
        "SELECT service_name,display_name,state,start_mode,collected_at FROM service_inventory WHERE pc_name=? ORDER BY service_name COLLATE NOCASE LIMIT 500",
        (pc_name,)
    ).fetchall()]
    conn.close()
    return jsonify(rows)

@web_bp.get("/security")
@login_required
def security_center():
    conn=get_db()
    events=[dict(x) for x in conn.execute("SELECT id,pc_name,event_record_id,event_id,log_name,level,provider,computer,account_name,source_ip,message,event_time,collected_at FROM security_events ORDER BY id DESC LIMIT 500").fetchall()]
    summary={"total":conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0],"failed_logons":conn.execute("SELECT COUNT(*) FROM security_events WHERE event_id=4625").fetchone()[0],"privileged":conn.execute("SELECT COUNT(*) FROM security_events WHERE event_id=4672").fetchone()[0],"service_installs":conn.execute("SELECT COUNT(*) FROM security_events WHERE event_id=7045").fetchone()[0]}
    recent_failed=[dict(x) for x in conn.execute("SELECT pc_name,account_name,source_ip,message,event_time FROM security_events WHERE event_id=4625 ORDER BY id DESC LIMIT 100").fetchall()]
    conn.close()
    return render_template("security.html",events=events,recent_failed=recent_failed,summary=summary)

@api_bp.get("/security/events")
@api_login_required
def security_events():
    limit=max(1,min(request.args.get("limit",100,type=int),500))
    conn=get_db()
    rows=[dict(x) for x in conn.execute(f"SELECT id,pc_name,event_record_id,event_id,log_name,level,provider,computer,account_name,source_ip,message,event_time,collected_at FROM security_events ORDER BY id DESC LIMIT {limit}").fetchall()]
    conn.close()
    return jsonify(rows)

@api_bp.get("/pcs/<path:pc_name>/security")
@api_login_required
def pc_security_events(pc_name):
    limit=max(1,min(request.args.get("limit",100,type=int),500))
    conn=get_db()
    rows=[dict(x) for x in conn.execute(f"SELECT id,pc_name,event_record_id,event_id,log_name,level,provider,computer,account_name,source_ip,message,event_time,collected_at FROM security_events WHERE pc_name=? ORDER BY id DESC LIMIT {limit}",(pc_name,)).fetchall()]
    conn.close()
    return jsonify(rows)

@web_bp.get("/risk")
@login_required
def risk_center():
    conn = get_db()
    rows = [dict(x) for x in conn.execute("""
        SELECT p.pc_name,p.ip,p.department,p.last_seen,
               COALESCE(r.score,0) AS score,
               COALESCE(r.level,'Low') AS level,
               COALESCE(r.reasons,'No elevated risk signals detected') AS reasons,
               COALESCE(r.defender_status,'Unknown') AS defender_status,
               r.updated_at
        FROM pcs p
        LEFT JOIN endpoint_risk r ON r.pc_name=p.pc_name
        ORDER BY score DESC, p.pc_name COLLATE NOCASE
    """).fetchall()]

    summary = {
        "critical": sum(1 for x in rows if x["level"] == "Critical"),
        "high": sum(1 for x in rows if x["level"] == "High"),
        "medium": sum(1 for x in rows if x["level"] == "Medium"),
        "low": sum(1 for x in rows if x["level"] == "Low"),
    }
    conn.close()
    return render_template("risk.html", rows=rows, summary=summary)


@web_bp.get("/endpoint/<path:pc_name>/risk")
@login_required
def endpoint_risk(pc_name):
    conn = get_db()
    pc = conn.execute("SELECT * FROM pcs WHERE pc_name=?", (pc_name,)).fetchone()
    risk = conn.execute("SELECT * FROM endpoint_risk WHERE pc_name=?", (pc_name,)).fetchone()
    connections = [dict(x) for x in conn.execute("""
        SELECT pid,process_name,local_address,local_port,remote_address,remote_port,status,collected_at
        FROM network_connections WHERE pc_name=?
        ORDER BY id DESC LIMIT 100
    """, (pc_name,)).fetchall()]
    conn.close()
    if pc is None:
        return "Endpoint not found", 404
    return render_template(
        "endpoint_risk.html",
        pc=dict(pc), risk=dict(risk) if risk else {
            "score": 0, "level": "Low",
            "reasons": "No telemetry received yet.",
            "defender_status": "Unknown", "updated_at": "-"
        },
        connections=connections
    )


@api_bp.get("/risk")
@api_login_required
def api_risk():
    conn = get_db()
    rows = [dict(x) for x in conn.execute("""
        SELECT p.pc_name,p.ip,p.department,
               COALESCE(r.score,0) AS score,
               COALESCE(r.level,'Low') AS level,
               COALESCE(r.reasons,'No elevated risk signals detected') AS reasons,
               COALESCE(r.defender_status,'Unknown') AS defender_status,
               r.updated_at
        FROM pcs p LEFT JOIN endpoint_risk r ON r.pc_name=p.pc_name
        ORDER BY score DESC
    """).fetchall()]
    conn.close()
    return jsonify(rows)


@api_bp.get("/pcs/<path:pc_name>/connections")
@api_login_required
def pc_connections(pc_name):
    conn = get_db()
    rows = [dict(x) for x in conn.execute("""
        SELECT pid,process_name,local_address,local_port,
               remote_address,remote_port,status,collected_at
        FROM network_connections WHERE pc_name=?
        ORDER BY id DESC LIMIT 200
    """, (pc_name,)).fetchall()]
    conn.close()
    return jsonify(rows)


@web_bp.get("/incidents")
@login_required
def incident_center():
    conn = get_db()
    incidents = [dict(x) for x in conn.execute("""
        SELECT i.*, COALESCE(r.score,0) AS risk_score,
               COALESCE(r.level,'Low') AS risk_level
        FROM incidents i
        LEFT JOIN endpoint_risk r ON r.pc_name=i.pc_name
        ORDER BY
          CASE i.status WHEN 'Open' THEN 0 WHEN 'Investigating' THEN 1
                        WHEN 'Contained' THEN 2 ELSE 3 END,
          CASE i.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1
                          WHEN 'Medium' THEN 2 ELSE 3 END,
          i.updated_at DESC
    """).fetchall()]
    conn.close()
    return render_template("incidents.html", incidents=incidents)


@web_bp.get("/incidents/<int:incident_id>")
@login_required
def incident_detail(incident_id):
    conn = get_db()
    incident = conn.execute("""
        SELECT i.*, COALESCE(r.score,0) AS risk_score,
               COALESCE(r.level,'Low') AS risk_level
        FROM incidents i LEFT JOIN endpoint_risk r ON r.pc_name=i.pc_name
        WHERE i.id=?
    """, (incident_id,)).fetchone()

    if not incident:
        conn.close()
        return "Incident not found", 404

    events = [dict(x) for x in conn.execute(
        "SELECT * FROM incident_events WHERE incident_id=? ORDER BY event_time ASC, id ASC",
        (incident_id,)
    ).fetchall()]
    notes = [dict(x) for x in conn.execute(
        "SELECT * FROM incident_notes WHERE incident_id=? ORDER BY created_at DESC",
        (incident_id,)
    ).fetchall()]

    security = []
    processes = []
    connections = []

    if incident["pc_name"]:
        security = [dict(x) for x in conn.execute("""
            SELECT event_id,account_name,source_ip,provider,event_time,message
            FROM security_events
            WHERE pc_name=?
            ORDER BY id DESC LIMIT 80
        """, (incident["pc_name"],)).fetchall()]

        processes = [dict(x) for x in conn.execute("""
            SELECT pid,name,username,cpu_percent,memory_mb,status,collected_at
            FROM process_inventory WHERE pc_name=?
            ORDER BY cpu_percent DESC, memory_mb DESC LIMIT 30
        """, (incident["pc_name"],)).fetchall()]

        connections = [dict(x) for x in conn.execute("""
            SELECT pid,process_name,local_address,local_port,
                   remote_address,remote_port,status,collected_at
            FROM network_connections WHERE pc_name=?
            ORDER BY id DESC LIMIT 60
        """, (incident["pc_name"],)).fetchall()]

    ai_history = [dict(x) for x in conn.execute("""
        SELECT id,provider,model,analysis,created_by,created_at
        FROM ai_analysis WHERE target_type='incident' AND target_id=?
        ORDER BY id DESC LIMIT 10
    """, (incident_id,)).fetchall()]

    conn.close()
    return render_template(
        "incident_detail.html",
        incident=dict(incident), events=events, notes=notes,
        security=security, processes=processes, connections=connections,
        ai_history=ai_history, user=current_user()
    )


@web_bp.post("/incidents/<int:incident_id>/status")
@role_required("Admin", "Operator")
def update_incident_status(incident_id):
    status = request.form.get("status", "Open")
    allowed = {"Open", "Investigating", "Contained", "Resolved"}
    if status not in allowed:
        return "Invalid status", 400

    conn = get_db()
    conn.execute(
        "UPDATE incidents SET status=?,updated_at=datetime('now') WHERE id=?",
        (status, incident_id)
    )
    conn.commit()
    conn.close()
    return redirect(url_for("web.incident_detail", incident_id=incident_id))


@web_bp.post("/incidents/<int:incident_id>/notes")
@role_required("Admin", "Operator")
def add_incident_note(incident_id):
    note = request.form.get("note", "").strip()
    if not note:
        return redirect(url_for("web.incident_detail", incident_id=incident_id))

    author = session.get("username") or (current_user() or {}).get("username") or "operator"
    conn = get_db()
    conn.execute(
        "INSERT INTO incident_notes(incident_id,author,note,created_at) "
        "VALUES(?,?,?,datetime('now'))",
        (incident_id, author, note)
    )
    conn.execute(
        "UPDATE incidents SET updated_at=datetime('now') WHERE id=?",
        (incident_id,)
    )
    conn.commit()
    conn.close()
    return redirect(url_for("web.incident_detail", incident_id=incident_id))


@web_bp.get("/threat-intelligence")
@login_required
def threat_intelligence():
    conn = get_db()
    iocs = [dict(x) for x in conn.execute("""
        SELECT i.*, COUNT(m.id) AS match_count
        FROM iocs i
        LEFT JOIN ioc_matches m ON m.ioc_id=i.id
        GROUP BY i.id
        ORDER BY match_count DESC, i.updated_at DESC
    """).fetchall()]

    matches = [dict(x) for x in conn.execute("""
        SELECT m.*, i.indicator_type, i.indicator, i.severity, i.confidence, i.source
        FROM ioc_matches m
        JOIN iocs i ON i.id=m.ioc_id
        ORDER BY m.matched_at DESC
        LIMIT 300
    """).fetchall()]

    summary = {
        "total": len(iocs),
        "matches": conn.execute("SELECT COUNT(*) FROM ioc_matches").fetchone()[0],
        "high": conn.execute(
            "SELECT COUNT(*) FROM iocs WHERE severity IN ('High','Critical')"
        ).fetchone()[0],
        "endpoints": conn.execute(
            "SELECT COUNT(DISTINCT pc_name) FROM ioc_matches"
        ).fetchone()[0]
    }
    conn.close()
    return render_template(
        "threat_intelligence.html",
        iocs=iocs, matches=matches, summary=summary
    )


@web_bp.post("/threat-intelligence/ioc")
@role_required("Admin", "Operator")
def add_ioc():
    indicator_type = request.form.get("indicator_type", "ip").strip().lower()
    indicator = request.form.get("indicator", "").strip()
    severity = request.form.get("severity", "Medium")
    source = request.form.get("source", "Manual").strip()
    description = request.form.get("description", "").strip()
    tags = request.form.get("tags", "").strip()

    allowed_types = {"ip", "domain", "hash"}
    allowed_severity = {"Low", "Medium", "High", "Critical"}
    if indicator_type not in allowed_types or not indicator:
        return redirect(url_for("web.threat_intelligence"))
    if severity not in allowed_severity:
        severity = "Medium"

    confidence = request.form.get("confidence", 50, type=int)
    confidence = max(0, min(confidence, 100))
    now = datetime.utcnow().isoformat(timespec="seconds")

    conn = get_db()
    conn.execute("""
        INSERT INTO iocs
        (indicator_type,indicator,normalized,severity,confidence,source,description,tags,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(indicator_type,normalized) DO UPDATE SET
        severity=excluded.severity,
        confidence=excluded.confidence,
        source=excluded.source,
        description=excluded.description,
        tags=excluded.tags,
        updated_at=excluded.updated_at
    """, (
        indicator_type, indicator, normalize_ioc(indicator_type, indicator),
        severity, confidence, source, description, tags, now, now
    ))

    # Correlate against every currently known endpoint.
    pcs = [x["pc_name"] for x in conn.execute("SELECT pc_name FROM pcs").fetchall()]
    for pc_name in pcs:
        refresh_ioc_matches(conn, pc_name, now)

    conn.commit()
    conn.close()
    return redirect(url_for("web.threat_intelligence"))


@web_bp.post("/threat-intelligence/ioc/<int:ioc_id>/delete")
@role_required("Admin")
def delete_ioc(ioc_id):
    conn = get_db()
    conn.execute("DELETE FROM ioc_matches WHERE ioc_id=?", (ioc_id,))
    conn.execute("DELETE FROM iocs WHERE id=?", (ioc_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("web.threat_intelligence"))


@web_bp.get("/threat-intelligence/ioc/<int:ioc_id>")
@login_required
def ioc_detail(ioc_id):
    conn = get_db()
    ioc = conn.execute("SELECT * FROM iocs WHERE id=?", (ioc_id,)).fetchone()
    if not ioc:
        conn.close()
        return "IOC not found", 404

    matches = [dict(x) for x in conn.execute("""
        SELECT * FROM ioc_matches
        WHERE ioc_id=?
        ORDER BY matched_at DESC
    """, (ioc_id,)).fetchall()]
    conn.close()
    return render_template("ioc_detail.html", ioc=dict(ioc), matches=matches)


@api_bp.get("/threat-intelligence/iocs")
@api_login_required
def api_iocs():
    conn = get_db()
    rows = [dict(x) for x in conn.execute("""
        SELECT i.*, COUNT(m.id) AS match_count
        FROM iocs i LEFT JOIN ioc_matches m ON m.ioc_id=i.id
        GROUP BY i.id ORDER BY match_count DESC
    """).fetchall()]
    conn.close()
    return jsonify(rows)


@api_bp.get("/threat-intelligence/matches")
@api_login_required
def api_ioc_matches():
    conn = get_db()
    rows = [dict(x) for x in conn.execute("""
        SELECT m.*, i.indicator_type, i.indicator, i.severity, i.confidence, i.source
        FROM ioc_matches m JOIN iocs i ON i.id=m.ioc_id
        ORDER BY m.matched_at DESC LIMIT 500
    """).fetchall()]
    conn.close()
    return jsonify(rows)


@web_bp.get("/soc")
@login_required
def soc_center():
    conn = get_db()

    fleet = conn.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(
                CASE
                    WHEN last_seen IS NOT NULL
                    AND julianday('now') - julianday(last_seen) <= (? / 86400.0)
                    THEN 1
                    ELSE 0
                END
            ) AS online
        FROM pcs
    """, (current_app.config["ONLINE_WINDOW_SECONDS"],)).fetchone()

    # Fallback if an older database does not have a settings row/value.
    total = int(fleet["total"] or 0)
    online = int(fleet["online"] or 0)

    incidents = conn.execute("""
        SELECT COUNT(*) AS c FROM incidents
        WHERE status IN ('Open','Investigating','Contained')
    """).fetchone()["c"]

    critical_incidents = conn.execute("""
        SELECT COUNT(*) AS c FROM incidents
        WHERE status IN ('Open','Investigating','Contained')
        AND severity='Critical'
    """).fetchone()["c"]

    high_risk = conn.execute("""
        SELECT COUNT(*) AS c FROM endpoint_risk
        WHERE level IN ('High','Critical')
    """).fetchone()["c"]

    ioc_matches = conn.execute("""
        SELECT COUNT(*) AS c FROM ioc_matches
        WHERE julianday(matched_at) >= julianday('now','-24 hours')
    """).fetchone()["c"]

    failed_24h = conn.execute("""
        SELECT COUNT(*) AS c FROM security_events
        WHERE event_id=4625
        AND julianday(event_time) >= julianday('now','-24 hours')
    """).fetchone()["c"]

    alerts = conn.execute("""
        SELECT id,pc_name,severity,message,created_at,resolved
        FROM alerts
        WHERE resolved=0
        ORDER BY
          CASE severity WHEN 'High' THEN 0 WHEN 'Warning' THEN 1 ELSE 2 END,
          id DESC
        LIMIT 30
    """).fetchall()

    top_risk = conn.execute("""
        SELECT p.pc_name,p.ip,COALESCE(r.score,0) AS score,
               COALESCE(r.level,'Low') AS level,
               COALESCE(r.defender_status,'Unknown') AS defender_status
        FROM pcs p LEFT JOIN endpoint_risk r ON r.pc_name=p.pc_name
        ORDER BY score DESC LIMIT 10
    """).fetchall()

    activity = conn.execute("""
        SELECT activity_type,pc_name,severity,title,detail,created_at
        FROM soc_activity ORDER BY id DESC LIMIT 50
    """).fetchall()

    conn.close()

    metrics = {
        "total": total,
        "online": online,
        "incidents": int(incidents or 0),
        "critical_incidents": int(critical_incidents or 0),
        "high_risk": int(high_risk or 0),
        "ioc_matches": int(ioc_matches or 0),
        "failed_24h": int(failed_24h or 0),
    }

    return render_template(
        "soc.html",
        metrics=metrics,
        alerts=[dict(x) for x in alerts],
        top_risk=[dict(x) for x in top_risk],
        activity=[dict(x) for x in activity],
        user=current_user()
    )


@api_bp.get("/soc/summary")
@api_login_required
def soc_summary():
    conn = get_db()
    result = {
        "fleet_total": conn.execute("SELECT COUNT(*) FROM pcs").fetchone()[0],
        "open_incidents": conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('Open','Investigating','Contained')"
        ).fetchone()[0],
        "critical_incidents": conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('Open','Investigating','Contained') AND severity='Critical'"
        ).fetchone()[0],
        "high_risk_endpoints": conn.execute(
            "SELECT COUNT(*) FROM endpoint_risk WHERE level IN ('High','Critical')"
        ).fetchone()[0],
        "ioc_matches_24h": conn.execute(
            "SELECT COUNT(*) FROM ioc_matches WHERE julianday(matched_at)>=julianday('now','-24 hours')"
        ).fetchone()[0],
        "failed_logons_24h": conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE event_id=4625 AND julianday(event_time)>=julianday('now','-24 hours')"
        ).fetchone()[0],
    }
    conn.close()
    return jsonify(result)


@api_bp.get("/soc/activity")
@api_login_required
def soc_activity_api():
    conn = get_db()
    rows = [dict(x) for x in conn.execute("""
        SELECT activity_type,pc_name,severity,title,detail,created_at
        FROM soc_activity ORDER BY id DESC LIMIT 100
    """).fetchall()]
    conn.close()
    return jsonify(rows)


@web_bp.get("/detections")
@login_required
def detection_center():
    conn = get_db()
    rows = conn.execute("""
        SELECT id,pc_name,severity,rule_id,title,mitre_id,evidence,
               first_seen,last_seen,count,status
        FROM detections
        ORDER BY
          CASE severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END,
          id DESC
        LIMIT 200
    """).fetchall()
    summary = {
        "open": conn.execute("SELECT COUNT(*) FROM detections WHERE status='Open'").fetchone()[0],
        "high": conn.execute("SELECT COUNT(*) FROM detections WHERE status='Open' AND severity='High'").fetchone()[0],
        "medium": conn.execute("SELECT COUNT(*) FROM detections WHERE status='Open' AND severity='Medium'").fetchone()[0],
    }
    conn.close()
    return render_template("detections.html", detections=[dict(x) for x in rows], summary=summary)


@api_bp.get("/detections")
@api_login_required
def detections_api():
    conn = get_db()
    rows = [dict(x) for x in conn.execute("""
        SELECT id,pc_name,severity,rule_id,title,mitre_id,evidence,
               first_seen,last_seen,count,status
        FROM detections ORDER BY id DESC LIMIT 200
    """).fetchall()]
    conn.close()
    return jsonify(rows)


@api_bp.get("/detections/summary")
@api_login_required
def detections_summary_api():
    conn = get_db()
    result = {
        "open": conn.execute("SELECT COUNT(*) FROM detections WHERE status='Open'").fetchone()[0],
        "high": conn.execute("SELECT COUNT(*) FROM detections WHERE status='Open' AND severity='High'").fetchone()[0],
        "medium": conn.execute("SELECT COUNT(*) FROM detections WHERE status='Open' AND severity='Medium'").fetchone()[0],
        "closed": conn.execute("SELECT COUNT(*) FROM detections WHERE status='Closed'").fetchone()[0],
    }
    conn.close()
    return jsonify(result)
