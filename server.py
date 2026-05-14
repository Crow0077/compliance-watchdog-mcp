#!/usr/bin/env python3
"""Compliance Watchdog MCP v1.0 — Autonomous compliance monitoring. 4 tools."""
import asyncio, json, os, urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from mcp.server.fastmcp import FastMCP

SUITE_URL = os.environ.get("COMPLIANCE_SUITE_URL", "http://localhost:8111/mcp")
DATA_DIR = Path(os.environ.get("WATCHDOG_DATA_DIR", os.path.expanduser("~/.compliance-watchdog")))
ALERT_LOG = DATA_DIR / "alerts.jsonl"
TREND_FILE = DATA_DIR / "trends.json"
DATA_DIR.mkdir(parents=True, exist_ok=True)
PORT = int(os.environ.get("WATCHDOG_PORT", os.environ.get("PORT", "8112")))
mcp = FastMCP("compliance-watchdog", host="0.0.0.0", port=PORT)
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

def send_alert(level: str, message: str):
    entry = {"timestamp": datetime.now().isoformat(), "level": level, "message": message}
    with open(ALERT_LOG, "a") as f: f.write(json.dumps(entry) + "\n")
    if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID and level in ("critical", "warning"):
        emoji = "🚨" if level == "critical" else "⚠️"
        text = f"{emoji} <b>Compliance Watchdog</b>\n{message}"
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
            data = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": text[:4000], "parse_mode": "HTML"}).encode()
            urllib.request.urlopen(urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}), timeout=10)
        except: pass

async def call_suite_tool(tool_name: str, args: dict = None) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(SUITE_URL, json={"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"watchdog","version":"1.0"}}}, headers={"Accept":"application/json, text/event-stream"})
        sid = r.headers.get("mcp-session-id","")
        h = {"Accept":"application/json, text/event-stream"}
        if sid: h["mcp-session-id"] = sid
        r = await client.post(SUITE_URL, json={"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":tool_name,"arguments":args or {}}}, headers=h)
        for line in r.text.split("\n"):
            if line.startswith("data:"):
                try:
                    d = json.loads(line[5:].strip())
                    if "result" in d: return {"success":True,"data":d["result"]}
                except: continue
        return {"success":False,"error":"No parseable response"}

def load_trends() -> dict:
    return json.loads(TREND_FILE.read_text()) if TREND_FILE.exists() else {"scores":[],"last_checked":None}

def save_trends(trends: dict):
    trends["last_checked"] = datetime.now().isoformat()
    TREND_FILE.write_text(json.dumps(trends, indent=2))

@mcp.tool()
async def watchdog_check() -> str:
    """Run full health check on Compliance Suite: reachability, chain integrity, firewall, CIS score trends. Alerts on degradation."""
    report = f"=== WATCHDOG CHECK === {datetime.now().isoformat()}\n\n"
    result = await call_suite_tool("compliance_status")
    if not result.get("success"):
        send_alert("critical","Compliance Suite DOWN")
        return report + "🔴 Suite unreachable"
    status_data = None
    for c in result["data"].get("content",[]):
        if c.get("type")=="text":
            try: status_data = json.loads(c["text"])
            except: pass
    if status_data:
        chain = status_data.get("chain","?")
        fw = status_data.get("fw","?")
        report += f"Chain: {'🟢 VALID' if chain=='VALID' else '🔴 BROKEN'}\n"
        report += f"FW: {'🟢 ON' if fw=='ON' else '🔴 OFF'}\n"
        if chain != "VALID": send_alert("critical","Audit chain BROKEN")
        if fw == "OFF": send_alert("critical","Firewall OFF")
    trends = load_trends()
    result = await call_suite_tool("compliance_scorecard")
    if result.get("success"):
        for c in result["data"].get("content",[]):
            if c.get("type")=="text":
                try:
                    sc = json.loads(c["text"])
                    cis = sc.get("cis_pct",0)
                    trends["scores"].append({"timestamp":datetime.now().isoformat(),"cis_pct":cis,"risk":sc.get("risk","?")})
                    if len(trends["scores"])>100: trends["scores"]=trends["scores"][-100:]
                    save_trends(trends)
                    report += f"CIS: {cis}% | Risk: {sc.get('risk','?')}\n"
                except: pass
    report += "✅ All clear\n" if "🔴" not in report else ""
    return report

@mcp.tool()
async def watchdog_history(hours: int = 24) -> str:
    """View recent watchdog alerts."""
    if not ALERT_LOG.exists(): return "No alerts yet."
    cut = datetime.now()-timedelta(hours=hours)
    alerts = []
    for line in ALERT_LOG.read_text().strip().split("\n"):
        if not line: continue
        try:
            a = json.loads(line)
            if datetime.fromisoformat(a["timestamp"])>=cut: alerts.append(a)
        except: pass
    if not alerts: return f"No alerts in {hours}h ✅"
    rpt = f"Alerts ({hours}h): {len(alerts)}\n\n"
    for a in alerts[-20:]: rpt += f"{'🚨' if a['level']=='critical' else '⚠️'} [{a['timestamp'][:19]}] {a['message'][:120]}\n"
    return rpt

@mcp.tool()
async def watchdog_trends() -> str:
    """CIS score trend analysis."""
    trends = load_trends()
    scores = trends.get("scores",[])
    if len(scores)<2: return "Need 2+ data points."
    first, last = scores[0], scores[-1]
    ch = last["cis_pct"]-first["cis_pct"]
    rpt = f"=== CIS TRENDS ===\n{first['timestamp'][:19]} → {last['timestamp'][:19]}\n{first['cis_pct']}% → {last['cis_pct']}% ({ch:+.0f}%)\n{'🟢 IMPROVING' if ch>0 else '🔴 DEGRADING' if ch<0 else '⚪ STABLE'}\n\n"
    for s in scores[-10:]: rpt += f"  {s['timestamp'][:16]}  {s['cis_pct']:5.1f}% {'█'*int(s['cis_pct']/5)}\n"
    return rpt

@mcp.tool()
async def watchdog_status() -> str:
    """Quick status: is Watchdog operational and connected?"""
    result = await call_suite_tool("compliance_status")
    suite_ok = result.get("success",False)
    ac = len(ALERT_LOG.read_text().strip().split("\n")) if ALERT_LOG.exists() else 0
    trends = load_trends()
    return json.dumps({"watchdog":"OPERATIONAL","suite":"CONNECTED" if suite_ok else "DISCONNECTED","alerts":ac,"trends":len(trends.get("scores",[])),"ts":datetime.now().isoformat()}, indent=2)

if __name__ == "__main__":
    print(f"Compliance Watchdog MCP — Port {PORT}")
    mcp.run(transport="streamable-http")
