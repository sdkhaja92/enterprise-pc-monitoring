from datetime import datetime, timezone
from .database import get_db


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def valid_api_key(value):
    from flask import current_app
    return bool(value) and value == current_app.config["MONITOR_API_KEY"]


def store_metrics(data):
    timestamp = now_iso()
    conn = get_db()

    conn.execute("""
        INSERT INTO pcs
        (pc_name, api_key, ip, cpu, ram, disk, department, software, gpu, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(pc_name) DO UPDATE SET
            api_key=excluded.api_key,
            ip=excluded.ip,
            cpu=excluded.cpu,
            ram=excluded.ram,
            disk=excluded.disk,
            department=excluded.department,
            software=excluded.software,
            gpu=excluded.gpu,
            last_seen=excluded.last_seen
    """, (
        data["pc_name"],
        data.get("api_key", ""),
        data.get("ip", ""),
        float(data.get("cpu", 0)),
        float(data.get("ram", 0)),
        float(data.get("disk", 0)),
        data.get("department", "General"),
        data.get("software", ""),
        data.get("gpu_info", ""),
        timestamp,  # FIX: last_seen value
    ))

    conn.execute("""
        INSERT INTO endpoint_hardware
        (pc_name, os_name, os_version, architecture, cpu_model, cpu_cores, ram_total_gb, gpu_model, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(pc_name) DO UPDATE SET
            os_name=excluded.os_name,
            os_version=excluded.os_version,
            architecture=excluded.architecture,
            cpu_model=excluded.cpu_model,
            cpu_cores=excluded.cpu_cores,
            ram_total_gb=excluded.ram_total_gb,
            gpu_model=excluded.gpu_model,
            updated_at=excluded.updated_at
    """, (
        data["pc_name"],
        data.get("os_name", ""),
        data.get("os_version", ""),
        data.get("architecture", ""),
        data.get("cpu_model", ""),
        int(data.get("cpu_cores", 0) or 0),
        float(data.get("ram_total_gb", 0) or 0),
        data.get("gpu_info", ""),
        timestamp,
    ))

    conn.execute("""
        INSERT INTO metrics(pc_name, cpu, ram, disk, gpu, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        data["pc_name"],
        float(data.get("cpu", 0)),
        float(data.get("ram", 0)),
        float(data.get("disk", 0)),
        float(data.get("gpu", 0)),
        timestamp,
    ))

    cpu = float(data.get("cpu", 0))
    ram = float(data.get("ram", 0))
    disk = float(data.get("disk", 0))

    def set_alert(message, severity):
        active = conn.execute(
            "SELECT id FROM alerts WHERE pc_name=? AND message=? AND resolved=0 LIMIT 1",
            (data["pc_name"], message)
        ).fetchone()
        if not active:
            conn.execute(
                "INSERT INTO alerts(pc_name,severity,message,created_at) VALUES(?,?,?,?)",
                (data["pc_name"], severity, message, timestamp)
            )

    def resolve_alert(message):
        conn.execute(
            "UPDATE alerts SET resolved=1 WHERE pc_name=? AND message=? AND resolved=0",
            (data["pc_name"], message)
        )

    if cpu >= 90:
        set_alert("CPU usage exceeded 90%.", "High")
    else:
        resolve_alert("CPU usage exceeded 90%.")

    if ram >= 90:
        set_alert("RAM usage exceeded 90%.", "High")
    else:
        resolve_alert("RAM usage exceeded 90%.")

    if disk >= 90:
        set_alert("Disk usage exceeded 90%.", "High")
        resolve_alert("Disk usage exceeded 80%.")
    elif disk >= 80:
        set_alert("Disk usage exceeded 80%.", "Warning")
    else:
        resolve_alert("Disk usage exceeded 80%.")
        resolve_alert("Disk usage exceeded 90%.")


    software_items = data.get("software_inventory") or []
    if isinstance(software_items, list):
        conn.execute("DELETE FROM software_inventory WHERE pc_name=?", (data["pc_name"],))
        for item in software_items:
            if isinstance(item, dict) and item.get("name"):
                conn.execute("""
                    INSERT INTO software_inventory
                    (pc_name, name, version, publisher, install_date, architecture, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    data["pc_name"], str(item.get("name","")),
                    str(item.get("version","")), str(item.get("publisher","")),
                    str(item.get("install_date","")), str(item.get("architecture","")),
                    timestamp
                ))


    processes = data.get("processes") or []
    if isinstance(processes, list):
        conn.execute("DELETE FROM process_inventory WHERE pc_name=?", (data["pc_name"],))
        for item in processes:
            if isinstance(item, dict) and item.get("name"):
                conn.execute(
                    "INSERT INTO process_inventory (pc_name,pid,name,username,cpu_percent,memory_mb,status,collected_at,exe_path,command_line,parent_pid,create_time) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        data["pc_name"], int(item.get("pid",0) or 0),
                        str(item.get("name","")), str(item.get("username","")),
                        float(item.get("cpu_percent",0) or 0),
                        float(item.get("memory_mb",0) or 0),
                        str(item.get("status","")), timestamp,
                        str(item.get("exe_path", item.get("path", ""))),
                        str(item.get("command_line", "")),
                        int(item.get("parent_pid", 0) or 0),
                        str(item.get("create_time", ""))
                    )
                )

    services = data.get("services") or []
    if isinstance(services, list):
        conn.execute("DELETE FROM service_inventory WHERE pc_name=?", (data["pc_name"],))
        for item in services:
            if isinstance(item, dict) and item.get("service_name"):
                conn.execute(
                    "INSERT INTO service_inventory (pc_name,service_name,display_name,state,start_mode,collected_at) VALUES (?,?,?,?,?,?)",
                    (
                        data["pc_name"], str(item.get("service_name","")),
                        str(item.get("display_name","")), str(item.get("state","")),
                        str(item.get("start_mode","")), timestamp
                    )
                )


    security_events = data.get("security_events") or []
    if isinstance(security_events, list):
        for item in security_events:
            if not isinstance(item, dict) or not item.get("event_id"):
                continue
            conn.execute("INSERT OR IGNORE INTO security_events (pc_name,event_record_id,event_id,log_name,level,provider,computer,account_name,source_ip,message,event_time,collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                data["pc_name"], str(item.get("event_record_id","")), int(item.get("event_id",0) or 0),
                str(item.get("log_name","")), str(item.get("level","")), str(item.get("provider","")),
                str(item.get("computer","")), str(item.get("account_name","")), str(item.get("source_ip","")),
                str(item.get("message",""))[:1200], str(item.get("event_time",timestamp)), timestamp))

    failed_recent = conn.execute("SELECT COUNT(*) FROM security_events WHERE pc_name=? AND event_id=4625 AND julianday(event_time) >= julianday('now','-10 minutes')", (data["pc_name"],)).fetchone()[0]
    if failed_recent >= 5:
        set_alert(f"Multiple Windows failed logons detected ({failed_recent} in the last 10 minutes).", "High")
    else:
        conn.execute("UPDATE alerts SET resolved=1 WHERE pc_name=? AND resolved=0 AND message LIKE 'Multiple Windows failed logons detected (%'", (data["pc_name"],))

    service_installs = conn.execute("SELECT COUNT(*) FROM security_events WHERE pc_name=? AND event_id=7045 AND julianday(event_time) >= julianday('now','-10 minutes')", (data["pc_name"],)).fetchone()[0]
    if service_installs >= 1:
        set_alert("A Windows service installation event was detected.", "Warning")

    network_connections = data.get("network_connections") or []
    if isinstance(network_connections, list):
        conn.execute("DELETE FROM network_connections WHERE pc_name=?", (data["pc_name"],))
        for item in network_connections:
            if not isinstance(item, dict):
                continue
            conn.execute(
                "INSERT INTO network_connections "
                "(pc_name,pid,process_name,local_address,local_port,remote_address,remote_port,status,collected_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    data["pc_name"], int(item.get("pid", 0) or 0),
                    str(item.get("process_name", "")),
                    str(item.get("local_address", "")),
                    int(item.get("local_port", 0) or 0),
                    str(item.get("remote_address", "")),
                    int(item.get("remote_port", 0) or 0),
                    str(item.get("status", "")), timestamp
                )
            )

    defender_status = str(data.get("defender_status", "Unknown"))
    risk_score, risk_level, risk_reasons = calculate_endpoint_risk(
        conn, data["pc_name"], defender_status
    )
    conn.execute(
        "INSERT INTO endpoint_risk(pc_name,score,level,reasons,defender_status,updated_at) "
        "VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(pc_name) DO UPDATE SET "
        "score=excluded.score,level=excluded.level,reasons=excluded.reasons,"
        "defender_status=excluded.defender_status,updated_at=excluded.updated_at",
        (
            data["pc_name"], risk_score, risk_level, risk_reasons,
            defender_status, timestamp
        )
    )

    if risk_level == "Critical":
        set_alert("Endpoint risk score is Critical.", "High")
    elif risk_level == "High":
        set_alert("Endpoint risk score is High.", "High")
    else:
        resolve_alert("Endpoint risk score is Critical.")
        resolve_alert("Endpoint risk score is High.")


    sync_incidents(conn, data["pc_name"], timestamp)
    refresh_ioc_matches(conn, data["pc_name"], timestamp)
    refresh_soc_activity(conn, data["pc_name"], timestamp)
    run_detection_engine(conn, data["pc_name"], timestamp)
    conn.commit()
    conn.close()




def run_detection_engine(conn, pc_name, timestamp):
    """Defensive, rule-based detections from telemetry already collected by the agent."""
    rules = []

    def add(key, severity, rule_id, title, mitre, evidence):
        rules.append((key, severity, rule_id, title, mitre, evidence))

    failed = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE pc_name=? AND event_id=4625 "
        "AND julianday(event_time)>=julianday('now','-10 minutes')", (pc_name,)
    ).fetchone()[0]
    if failed >= 5:
        add(f"{pc_name}:failed-logon-burst", "High", "DET-AUTH-001",
            "Failed logon burst", "T1110",
            f"{failed} failed logons observed in the last 10 minutes.")

    service_installs = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE pc_name=? AND event_id=7045 "
        "AND julianday(event_time)>=julianday('now','-30 minutes')", (pc_name,)
    ).fetchone()[0]
    if service_installs:
        add(f"{pc_name}:service-install", "High", "DET-SVC-001",
            "New Windows service installation", "T1543.003",
            f"{service_installs} service installation event(s) observed.")

    new_accounts = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE pc_name=? AND event_id=4720 "
        "AND julianday(event_time)>=julianday('now','-30 minutes')", (pc_name,)
    ).fetchone()[0]
    if new_accounts:
        add(f"{pc_name}:account-created", "High", "DET-ACCOUNT-001",
            "Windows account creation observed", "T1136.001",
            f"{new_accounts} account creation event(s) observed.")

    privileged = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE pc_name=? AND event_id=4672 "
        "AND julianday(event_time)>=julianday('now','-15 minutes')", (pc_name,)
    ).fetchone()[0]
    if privileged >= 5:
        add(f"{pc_name}:privileged-logon-burst", "Medium", "DET-AUTH-002",
            "Repeated privileged logons", "T1078",
            f"{privileged} privileged logon events observed in the last 15 minutes.")

    suspicious = {
        "powershell.exe": ("Medium","DET-PROC-001","PowerShell process observed","T1059.001"),
        "pwsh.exe": ("Medium","DET-PROC-001","PowerShell process observed","T1059.001"),
        "cmd.exe": ("Low","DET-PROC-002","Windows command shell observed","T1059.003"),
        "mshta.exe": ("High","DET-PROC-003","MSHTA process observed","T1218.005"),
        "regsvr32.exe": ("High","DET-PROC-004","Regsvr32 process observed","T1218.010"),
        "rundll32.exe": ("High","DET-PROC-005","Rundll32 process observed","T1218.011"),
        "wscript.exe": ("Medium","DET-PROC-006","Windows Script Host observed","T1059.005"),
        "cscript.exe": ("Medium","DET-PROC-006","Windows Script Host observed","T1059.005"),
    }
    proc_rows = conn.execute(
        "SELECT name,COUNT(*) AS c FROM process_inventory WHERE pc_name=? GROUP BY LOWER(name)",
        (pc_name,)
    ).fetchall()
    for row in proc_rows:
        name = str(row["name"] or "").lower()
        if name in suspicious:
            sev, rid, title, mitre = suspicious[name]
            add(f"{pc_name}:process:{name}", sev, rid, title, mitre,
                f"Process inventory contains {name} ({row['c']} observed instance(s)).")

    # IOC correlation is deliberately treated as a high-confidence detection.
    iocs = conn.execute("""
        SELECT COUNT(*) FROM ioc_matches
        WHERE pc_name=? AND julianday(matched_at)>=julianday('now','-30 minutes')
    """, (pc_name,)).fetchone()[0]
    if iocs:
        add(f"{pc_name}:ioc-match", "High", "DET-IOC-001",
            "Threat intelligence IOC match", "T1071",
            f"{iocs} IOC correlation(s) observed in the last 30 minutes.")

    active_keys = set()
    for key, severity, rule_id, title, mitre, evidence in rules:
        active_keys.add(key)
        existing = conn.execute(
            "SELECT id,count FROM detections WHERE detection_key=? AND status='Open'", (key,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE detections SET last_seen=?,count=?,evidence=?,severity=?,"
                "rule_id=?,title=?,mitre_id=? WHERE id=?",
                (timestamp, int(existing["count"])+1, evidence, severity, rule_id, title, mitre, existing["id"])
            )
        else:
            conn.execute("""
                INSERT INTO detections
                (detection_key,pc_name,severity,rule_id,title,mitre_id,evidence,first_seen,last_seen,count,status)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """, (key,pc_name,severity,rule_id,title,mitre,evidence,timestamp,timestamp,1,"Open"))

    # Auto-close only detections whose signal is no longer present.
    conn.execute("""
        UPDATE detections SET status='Closed'
        WHERE pc_name=? AND status='Open'
        AND detection_key NOT IN ({})
    """.format(",".join("?" for _ in active_keys) if active_keys else "''"),
        (pc_name, *active_keys) if active_keys else (pc_name,)
    )


def calculate_endpoint_risk(conn, pc_name, defender_status="Unknown"):
    score = 0
    reasons = []

    failed = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE pc_name=? "
        "AND event_id=4625 AND julianday(event_time) >= julianday('now','-30 minutes')",
        (pc_name,)
    ).fetchone()[0]
    if failed >= 10:
        score += 35
        reasons.append(f"{failed} failed logons in 30 minutes")
    elif failed >= 5:
        score += 20
        reasons.append(f"{failed} failed logons in 30 minutes")

    installs = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE pc_name=? "
        "AND event_id=7045 AND julianday(event_time) >= julianday('now','-30 minutes')",
        (pc_name,)
    ).fetchone()[0]
    if installs:
        score += min(25, installs * 10)
        reasons.append(f"{installs} service installation event(s)")

    privileged = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE pc_name=? "
        "AND event_id=4672 AND julianday(event_time) >= julianday('now','-30 minutes')",
        (pc_name,)
    ).fetchone()[0]
    if privileged >= 10:
        score += 15
        reasons.append(f"{privileged} privileged logons")
    elif privileged >= 5:
        score += 8
        reasons.append(f"{privileged} privileged logons")

    high_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE pc_name=? AND resolved=0 AND severity='High'",
        (pc_name,)
    ).fetchone()[0]
    if high_alerts:
        score += min(25, high_alerts * 10)
        reasons.append(f"{high_alerts} active high-severity alert(s)")

    if defender_status == "Attention Required":
        score += 25
        reasons.append("Microsoft Defender protection requires attention")
    elif defender_status == "Unavailable":
        score += 5
        reasons.append("Microsoft Defender status unavailable")

    score = min(100, score)
    if score >= 70:
        level = "Critical"
    elif score >= 45:
        level = "High"
    elif score >= 20:
        level = "Medium"
    else:
        level = "Low"

    reason_text = " | ".join(reasons) if reasons else "No elevated risk signals detected"
    return score, level, reason_text



def sync_incidents(conn, pc_name, timestamp):
    """Create/update triage incidents from strong endpoint security signals."""
    signals = []

    failed = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE pc_name=? "
        "AND event_id=4625 AND julianday(event_time)>=julianday('now','-30 minutes')",
        (pc_name,)
    ).fetchone()[0]
    if failed >= 5:
        severity = "High" if failed < 10 else "Critical"
        signals.append((
            "AUTH-BRUTE",
            f"Repeated failed logons on {pc_name}",
            severity,
            "Authentication",
            f"{failed} Windows Event ID 4625 events in the last 30 minutes."
        ))

    service_installs = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE pc_name=? "
        "AND event_id=7045 AND julianday(event_time)>=julianday('now','-30 minutes')",
        (pc_name,)
    ).fetchone()[0]
    if service_installs:
        signals.append((
            "SERVICE-INSTALL",
            f"Windows service installation on {pc_name}",
            "High",
            "Persistence",
            f"{service_installs} Event ID 7045 service installation event(s) observed."
        ))

    risk = conn.execute(
        "SELECT score,level,reasons FROM endpoint_risk WHERE pc_name=?",
        (pc_name,)
    ).fetchone()
    if risk and risk["level"] in ("High", "Critical"):
        signals.append((
            "ENDPOINT-RISK",
            f"{risk['level']} endpoint risk: {pc_name}",
            risk["level"],
            "Endpoint Risk",
            str(risk["reasons"] or "")
        ))

    for key, title, severity, category, summary in signals:
        incident_key = f"{pc_name}:{key}"
        existing = conn.execute(
            "SELECT id,status FROM incidents WHERE incident_key=?",
            (incident_key,)
        ).fetchone()

        if existing:
            if existing["status"] == "Resolved":
                conn.execute(
                    "UPDATE incidents SET status='Open',severity=?,summary=?,updated_at=? WHERE id=?",
                    (severity, summary, timestamp, existing["id"])
                )
            else:
                conn.execute(
                    "UPDATE incidents SET severity=?,summary=?,updated_at=? WHERE id=?",
                    (severity, summary, timestamp, existing["id"])
                )
            incident_id = existing["id"]
        else:
            cur = conn.execute(
                "INSERT INTO incidents "
                "(incident_key,title,severity,status,pc_name,category,summary,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (incident_key,title,severity,"Open",pc_name,category,summary,timestamp,timestamp)
            )
            incident_id = cur.lastrowid

        conn.execute(
            "INSERT INTO incident_events "
            "(incident_id,event_type,source_id,event_time,title,detail) VALUES (?,?,?,?,?,?)",
            (incident_id, "Detection", 0, timestamp, title, summary)
        )




def normalize_ioc(indicator_type, indicator):
    value = str(indicator or "").strip()
    if indicator_type in ("ip", "domain", "hash"):
        return value.lower()
    return value.lower()


def refresh_ioc_matches(conn, pc_name, timestamp):
    """Correlate configured IOCs with endpoint telemetry already stored locally."""
    iocs = conn.execute("SELECT * FROM iocs").fetchall()

    for ioc in iocs:
        indicator = ioc["normalized"]
        itype = ioc["indicator_type"]

        candidates = []

        if itype == "ip":
            rows = conn.execute("""
                SELECT id,remote_address,process_name,remote_port,status,collected_at
                FROM network_connections
                WHERE pc_name=? AND lower(remote_address)=?
            """, (pc_name, indicator)).fetchall()
            for row in rows:
                candidates.append((
                    "network_connection", row["id"], row["remote_address"],
                    f"Process={row['process_name'] or 'unknown'}; RemotePort={row['remote_port']}; Status={row['status']}"
                ))

            rows = conn.execute("""
                SELECT id,event_id,source_ip,account_name,message,event_time
                FROM security_events
                WHERE pc_name=? AND lower(source_ip)=?
            """, (pc_name, indicator)).fetchall()
            for row in rows:
                candidates.append((
                    "security_event", row["id"], row["source_ip"],
                    f"EventID={row['event_id']}; Account={row['account_name'] or 'unknown'}; {row['message'][:300]}"
                ))

        elif itype == "domain":
            rows = conn.execute("""
                SELECT id,remote_address,process_name,remote_port,status,collected_at
                FROM network_connections
                WHERE pc_name=? AND lower(remote_address)=?
            """, (pc_name, indicator)).fetchall()
            for row in rows:
                candidates.append((
                    "network_connection", row["id"], row["remote_address"],
                    f"Process={row['process_name'] or 'unknown'}; RemotePort={row['remote_port']}; Status={row['status']}"
                ))

        elif itype == "hash":
            # Hash matching becomes active when future process telemetry stores a hash.
            # Keep this path intentionally schema-compatible without guessing hashes.
            pass

        for source_table, source_id, matched_value, context in candidates:
            conn.execute("""
                INSERT OR IGNORE INTO ioc_matches
                (ioc_id,pc_name,match_type,matched_value,source_table,source_id,context,matched_at)
                VALUES (?,?,?,?,?,?,?,?)
            """, (
                ioc["id"], pc_name, "exact",
                matched_value, source_table, source_id, context, timestamp
            ))



def refresh_soc_activity(conn, pc_name, timestamp):
    """Create a compact SOC activity stream from current telemetry."""
    rows = conn.execute("""
        SELECT event_id,account_name,source_ip,message,event_time
        FROM security_events
        WHERE pc_name=?
        ORDER BY id DESC LIMIT 12
    """, (pc_name,)).fetchall()

    for row in rows:
        severity = "Info"
        title = f"Windows Event {row['event_id']} on {pc_name}"
        if row["event_id"] == 4625:
            severity = "Warning"
            title = f"Failed logon detected on {pc_name}"
        elif row["event_id"] == 4672:
            severity = "Warning"
            title = f"Privileged logon detected on {pc_name}"
        elif row["event_id"] == 7045:
            severity = "High"
            title = f"Service installation detected on {pc_name}"

        detail = f"Account={row['account_name'] or 'unknown'}; SourceIP={row['source_ip'] or 'n/a'}; {row['message'][:350]}"
        conn.execute("""
            INSERT INTO soc_activity(activity_type,pc_name,severity,title,detail,created_at)
            SELECT ?,?,?,?,?,?
            WHERE NOT EXISTS (
                SELECT 1 FROM soc_activity
                WHERE activity_type=? AND pc_name=? AND title=? AND detail=?
            )
        """, (
            "security_event", pc_name, severity, title, detail, timestamp,
            "security_event", pc_name, title, detail
        ))

    ioc_rows = conn.execute("""
        SELECT i.indicator,m.pc_name,m.source_table,m.context,m.matched_at
        FROM ioc_matches m JOIN iocs i ON i.id=m.ioc_id
        WHERE m.pc_name=?
        ORDER BY m.id DESC LIMIT 8
    """, (pc_name,)).fetchall()

    for row in ioc_rows:
        conn.execute("""
            INSERT INTO soc_activity(activity_type,pc_name,severity,title,detail,created_at)
            SELECT ?,?,?,?,?,?
            WHERE NOT EXISTS (
                SELECT 1 FROM soc_activity
                WHERE activity_type=? AND pc_name=? AND title=? AND detail=?
            )
        """, (
            "ioc_match", pc_name, "High",
            f"IOC match observed on {pc_name}",
            f"IOC={row['indicator']}; Source={row['source_table']}; {row['context']}",
            timestamp,
            "ioc_match", pc_name,
            f"IOC match observed on {pc_name}",
            f"IOC={row['indicator']}; Source={row['source_table']}; {row['context']}"
        ))

    conn.execute("""
        DELETE FROM soc_activity
        WHERE id NOT IN (
            SELECT id FROM soc_activity ORDER BY id DESC LIMIT 1000
        )
    """)


def create_ticket(data):
    conn = get_db()
    now = now_iso()
    cur = conn.execute("""
        INSERT INTO tickets(pc_name, alert_id, title, description, priority, status, assignee, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("pc_name"),
        data.get("alert_id"),
        data["title"],
        data.get("description", ""),
        data.get("priority", "Medium"),
        data.get("status", "Open"),
        data.get("assignee", "IT Operations"),
        now, now
    ))
    conn.commit()
    ticket_id = cur.lastrowid
    conn.close()
    return ticket_id
