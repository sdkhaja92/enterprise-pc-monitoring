import argparse
import json
import os
import platform
import socket
import subprocess
import time

import psutil
import requests


def powershell_value(script, default=""):
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode == 0:
            value = result.stdout.strip()
            return value or default
    except Exception:
        pass
    return default


def collect_hardware():
    os_name = platform.system() or "Unknown"
    os_version = platform.version() or ""
    architecture = platform.machine() or ""

    cpu_model = platform.processor() or ""
    cpu_cores = psutil.cpu_count(logical=False) or psutil.cpu_count() or 0
    ram_total_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2)

    if os_name == "Windows":
        cpu_model = powershell_value(
            "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)",
            cpu_model
        )
        os_caption = powershell_value(
            "(Get-CimInstance Win32_OperatingSystem | Select-Object -First 1 -ExpandProperty Caption)",
            os_name
        )
        os_version = powershell_value(
            "(Get-CimInstance Win32_OperatingSystem | Select-Object -First 1 -ExpandProperty Version)",
            os_version
        )
        architecture = powershell_value(
            "(Get-CimInstance Win32_OperatingSystem | Select-Object -First 1 -ExpandProperty OSArchitecture)",
            architecture
        )
        gpu_info = powershell_value(
            "(Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name) -join '; '",
            ""
        )
        os_name = os_caption
    else:
        gpu_info = ""

    return {
        "os_name": os_name,
        "os_version": os_version,
        "architecture": architecture,
        "cpu_model": cpu_model,
        "cpu_cores": cpu_cores,
        "ram_total_gb": ram_total_gb,
        "gpu_info": gpu_info,
    }



def collect_software_inventory():
    if os.name != "nt":
        return []
    command = r'''$paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty $paths -ErrorAction SilentlyContinue |
      Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 } |
      Select-Object DisplayName,DisplayVersion,Publisher,InstallDate |
      Sort-Object DisplayName -Unique |
      ConvertTo-Json -Compress'''
    try:
        r = subprocess.run(["powershell","-NoProfile","-Command",command],
                           capture_output=True,text=True,timeout=30)
        if r.returncode != 0 or not r.stdout.strip():
            return []
        raw = json.loads(r.stdout)
        if isinstance(raw, dict):
            raw = [raw]
        return [{
            "name": str(x.get("DisplayName") or "").strip(),
            "version": str(x.get("DisplayVersion") or "").strip(),
            "publisher": str(x.get("Publisher") or "").strip(),
            "install_date": str(x.get("InstallDate") or "").strip(),
            "architecture": ""
        } for x in raw if str(x.get("DisplayName") or "").strip()]
    except Exception:
        return []



def collect_processes(limit=25):
    items = []
    try:
        procs = []
        for p in psutil.process_iter(["pid", "name", "username", "status", "memory_info"]):
            try:
                p.cpu_percent(None)
                procs.append(p)
            except Exception:
                pass
        time.sleep(0.15)
        for p in procs:
            try:
                cpu = p.cpu_percent(None)
                mem = p.info.get("memory_info")
                try:
                    exe_path = p.exe() or ""
                except Exception:
                    exe_path = ""
                try:
                    command_line = " ".join(p.cmdline() or [])[:2000]
                except Exception:
                    command_line = ""
                try:
                    parent_pid = int(p.ppid() or 0)
                except Exception:
                    parent_pid = 0
                try:
                    create_time = str(p.create_time())
                except Exception:
                    create_time = ""
                items.append({
                    "pid": p.pid,
                    "name": p.info.get("name") or "Unknown",
                    "username": p.info.get("username") or "",
                    "cpu_percent": round(cpu, 2),
                    "memory_mb": round((mem.rss if mem else 0) / (1024 ** 2), 2),
                    "status": p.info.get("status") or "",
                    "exe_path": exe_path,
                    "command_line": command_line,
                    "parent_pid": parent_pid,
                    "create_time": create_time,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except Exception:
        return []
    items.sort(key=lambda x: (x["cpu_percent"], x["memory_mb"]), reverse=True)
    return items[:limit]


def collect_services(limit=200):
    if os.name != "nt":
        return []
    command = "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode | Sort-Object Name | ConvertTo-Json -Compress"
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=20
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        raw = json.loads(result.stdout)
        if isinstance(raw, dict):
            raw = [raw]
        return [{
            "service_name": str(x.get("Name") or "").strip(),
            "display_name": str(x.get("DisplayName") or "").strip(),
            "state": str(x.get("State") or "").strip(),
            "start_mode": str(x.get("StartMode") or "").strip(),
        } for x in raw if x.get("Name")][:limit]
    except Exception:
        return []


def collect_security_events(limit=60):
    """Collect Windows security telemetry and expose collector failures."""
    if os.name != "nt":
        return []

    ps_script = r'''$start=(Get-Date).AddMinutes(-10)
$events=@()
try{$events+=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625,4672,4688,4720,4728,4732;StartTime=$start} -ErrorAction Stop}catch{Write-Error ("Security log read failed: " + $_.Exception.Message)}
try{$events+=Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=$start} -ErrorAction Stop}catch{Write-Error ("System log read failed: " + $_.Exception.Message)}
$events|Sort-Object TimeCreated -Descending|Select-Object -First 60|ForEach-Object{
$account='';$ip='';$details=''
try{$xml=[xml]$_.ToXml();$nodes=@{};foreach($n in $xml.Event.EventData.Data){if($n.Name){$nodes[$n.Name]=[string]$n.'#text'}};if($nodes.ContainsKey('TargetUserName')){$account=$nodes['TargetUserName']}elseif($nodes.ContainsKey('SubjectUserName')){$account=$nodes['SubjectUserName']};if($nodes.ContainsKey('IpAddress')){$ip=$nodes['IpAddress']};foreach($k in @('FailureReason','Status','SubStatus','LogonType')){if($nodes.ContainsKey($k)){$details += " $k=$($nodes[$k])"}}}catch{}
[PSCustomObject]@{event_record_id=[string]$_.RecordId;event_id=[int]$_.Id;log_name=[string]$_.LogName;level=[string]$_.LevelDisplayName;provider=[string]$_.ProviderName;computer=[string]$_.MachineName;account_name=$account;source_ip=$ip;message=(([string]$_.Message)-replace '`r?`n',' ')+$details;event_time=$_.TimeCreated.ToUniversalTime().ToString('o')}
}|ConvertTo-Json -Compress'''

    def normalize(raw):
        if isinstance(raw, dict): raw=[raw]
        out=[]
        for x in raw or []:
            try: eid=int(x.get('event_id') or 0)
            except Exception: eid=0
            if not eid: continue
            out.append({
                'event_record_id':str(x.get('event_record_id') or ''), 'event_id':eid,
                'log_name':str(x.get('log_name') or ''), 'level':str(x.get('level') or ''),
                'provider':str(x.get('provider') or ''), 'computer':str(x.get('computer') or ''),
                'account_name':str(x.get('account_name') or ''), 'source_ip':str(x.get('source_ip') or ''),
                'message':str(x.get('message') or '')[:1200], 'event_time':str(x.get('event_time') or '')
            })
        return out[:limit]

    try:
        result=subprocess.run(['powershell','-NoProfile','-ExecutionPolicy','Bypass','-Command',ps_script],capture_output=True,text=True,timeout=25,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if result.stderr.strip(): print('[security-events]', result.stderr.strip()[:500])
        if result.stdout.strip():
            parsed=normalize(json.loads(result.stdout))
            if parsed: return parsed
    except Exception as exc:
        print('[security-events] PowerShell collector error:', exc)

    # Fallback: native Windows event query for machines where Get-WinEvent is unavailable.
    try:
        import xml.etree.ElementTree as ET
        q='*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4688 or EventID=4720 or EventID=4728 or EventID=4732) and TimeCreated[timediff(@SystemTime) <= 600000]]]'
        result=subprocess.run(['wevtutil','qe','Security',f'/q:{q}','/f:xml',f'/c:{limit}'],capture_output=True,text=True,timeout=25,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if result.returncode != 0:
            print('[security-events] wevtutil failed:', result.stderr.strip()[:500]); return []
        out=[]
        for block in result.stdout.split('</Event>'):
            if '<Event' not in block: continue
            root=ET.fromstring(block+'</Event>'); system=root.find('./System');
            if system is None: continue
            eid=system.find('./EventID'); rid=system.find('./EventRecordID'); provider=system.find('./Provider'); computer=system.find('./Computer'); tm=system.find('./TimeCreated')
            data={}
            for n in root.findall('./EventData/Data'):
                if n.attrib.get('Name'): data[n.attrib['Name']]=n.text or ''
            out.append({'event_record_id':rid.text if rid is not None else '', 'event_id':int(eid.text) if eid is not None and eid.text else 0,
                'log_name':'Security','level':'','provider':provider.attrib.get('Name','') if provider is not None else '',
                'computer':computer.text if computer is not None else '', 'account_name':data.get('TargetUserName') or data.get('SubjectUserName',''),
                'source_ip':data.get('IpAddress',''), 'message':'Windows Security Event '+(eid.text if eid is not None else ''),
                'event_time':tm.attrib.get('SystemTime','') if tm is not None else ''})
        return normalize(out)
    except Exception as exc:
        print('[security-events] wevtutil collector error:', exc); return []

def collect_defender_status():
    if os.name != "nt":
        return "Not Windows"
    command = "(Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled | ConvertTo-Json -Compress)"
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
        if result.returncode != 0 or not result.stdout.strip():
            return "Unavailable"
        x = json.loads(result.stdout)
        enabled = all(bool(x.get(k)) for k in [
            "AMServiceEnabled", "AntivirusEnabled",
            "RealTimeProtectionEnabled", "AntispywareEnabled"
        ])
        return "Protected" if enabled else "Attention Required"
    except Exception:
        return "Unavailable"


def collect_network_connections(limit=80):
    items = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if not c.raddr:
                continue
            try:
                pid = int(c.pid or 0)
            except Exception:
                pid = 0
            process_name = ""
            if pid:
                try:
                    process_name = psutil.Process(pid).name()
                except Exception:
                    pass
            items.append({
                "pid": pid,
                "process_name": process_name,
                "local_address": c.laddr.ip if c.laddr else "",
                "local_port": c.laddr.port if c.laddr else 0,
                "remote_address": c.raddr.ip if c.raddr else "",
                "remote_port": c.raddr.port if c.raddr else 0,
                "status": str(c.status or "")
            })
    except Exception:
        return []
    return items[:limit]


def collect_metrics():
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = "127.0.0.1"

    disk_path = os.environ.get("MONITOR_DISK_PATH", os.path.abspath(os.sep))

    try:
        disk = psutil.disk_usage(disk_path).percent
    except Exception:
        disk = 0

    data = {
        "pc_name": socket.gethostname(),
        "ip": ip,
        "cpu": round(psutil.cpu_percent(interval=1), 2),
        "ram": round(psutil.virtual_memory().percent, 2),
        "disk": round(disk, 2),
        "gpu": 0,
        "department": os.environ.get("MONITOR_DEPARTMENT", "General"),
        "software": "",
        "software_inventory": collect_software_inventory(),
        "processes": collect_processes(),
        "services": collect_services(),
        "security_events": collect_security_events(),
        "defender_status": collect_defender_status(),
        "network_connections": collect_network_connections(),
    }
    data.update(collect_hardware())
    return data


def main():
    parser = argparse.ArgumentParser(description="Enterprise PC Monitoring Agent")
    parser.add_argument("--server-url", default="http://127.0.0.1:5000")
    parser.add_argument("--interval", type=int, default=30)
    args = parser.parse_args()

    api_key = os.environ.get("MONITOR_API_KEY")
    if not api_key:
        raise SystemExit("Set MONITOR_API_KEY before starting the agent.")

    url = args.server_url.rstrip("/") + "/api/update"
    print(f"Agent started. Sending metrics to {url}")

    while True:
        try:
            data = collect_metrics()
            data["api_key"] = api_key
            response = requests.post(url, json=data, timeout=10)
            print(response.status_code, response.text[:200])
        except Exception as exc:
            print("Agent error:", exc)

        time.sleep(max(5, args.interval))


if __name__ == "__main__":
    main()
