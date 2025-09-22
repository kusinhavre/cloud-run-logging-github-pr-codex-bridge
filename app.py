import os, json, base64, time, hashlib
from datetime import datetime, timedelta, timezone
from flask import Flask, request, abort
import requests
from google.cloud import logging_v2

app = Flask(__name__)

# ---- Config ----
PROJECT_ID   = os.environ.get("GCP_PROJECT") or os.environ["GOOGLE_CLOUD_PROJECT"]
REGION       = os.environ.get("REGION", "")
SERVICES     = [s.strip() for s in os.environ.get("CLOUD_RUN_SERVICES", "").split(",") if s.strip()]
REPO_MAP     = json.loads(os.environ.get("REPO_MAP_JSON", "{}"))  # {"svc-a":"owner/repo", ...}
DEFAULT_REPO = os.environ.get("DEFAULT_REPO")  # fallback "owner/repo" if service not in REPO_MAP

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]  # store in Secret Manager
CODEX_HANDLE = os.environ.get("CODEX_HANDLE", "codex")  # mention target, e.g. "codex"
BASIC_USER   = os.environ.get("WEBHOOK_USER")
BASIC_PASS   = os.environ.get("WEBHOOK_PASS")

WINDOW_MIN   = int(os.environ.get("WINDOW_MIN", "5"))  # minutes around incident
MAX_LINES    = int(os.environ.get("MAX_LINES", "40"))  # total lines to include
MAX_CHARS    = int(os.environ.get("MAX_CHARS", "20000"))

# ---- Helpers ----
def check_basic_auth(req):
    if not BASIC_USER and not BASIC_PASS:
        return True
    auth = req.headers.get("Authorization")
    if not auth or not auth.startswith("Basic "):
        abort(401, www_authenticate='Basic realm="gcm-webhook"')
    try:
        user, pwd = base64.b64decode(auth.split()[1]).decode().split(":", 1)
    except Exception:
        abort(401)
    if user != BASIC_USER or pwd != BASIC_PASS:
        abort(401)
    return True

def svc_clause():
    if not SERVICES:
        return None
    return " OR ".join([f'resource.labels.service_name="{s}"' for s in SERVICES])

def filter_requests_weird():
    f = [
        'resource.type="cloud_run_revision"',
        'logName=~"projects/.*/logs/run.googleapis.com%2Frequests"',
        'NOT httpRequest.userAgent:"GoogleHC"',
        'NOT httpRequest.requestUrl:"/health"',
    ]
    if REGION:  f.append(f'resource.labels.location="{REGION}"')
    if SERVICES: f.append(f'({svc_clause()})')
    # not in {200,201,202,204,206,301,302,303,304,307,308,404}
    f.append("""
    (
      httpRequest.status<200 OR
      (httpRequest.status>=300 AND httpRequest.status!=301 AND httpRequest.status!=302 AND httpRequest.status!=303
                                 AND httpRequest.status!=304 AND httpRequest.status!=307 AND httpRequest.status!=308) OR
      (httpRequest.status>206 AND httpRequest.status<300) OR
      (httpRequest.status=404 ? false : false)
    )
    """.strip())
    return "\n".join(f)

def filter_container_errors(trace=None):
    f = ['resource.type="cloud_run_revision"']
    if REGION:  f.append(f'resource.labels.location="{REGION}"')
    if SERVICES: f.append(f'({svc_clause()})')
    f.append('(severity>=ERROR OR textPayload:("Traceback" OR "Exception" OR "CRITICAL" OR "panic:") OR jsonPayload.message:("error" OR "exception"))')
    if trace:
        f.append(f'trace="{trace}"')
    return "\n".join(f)

def fetch_logs(filter_text, start, end, page_size=100):
    client = logging_v2.Client(project=PROJECT_ID)
    time_filter = f'timestamp>="{start.isoformat()}" AND timestamp<="{end.isoformat()}"'
    final = f"{filter_text}\n{time_filter}"
    entries = client.list_entries(filter_=final, order_by=logging_v2.DESCENDING, page_size=page_size)
    out = []
    for e in entries:
        # Support textPayload/jsonPayload; show minimal but useful fields
        payload = e.payload if isinstance(e.payload, str) else (e.payload or {})
        if isinstance(payload, dict):
            payload = payload.get("message") or payload.get("msg") or json.dumps(payload)[:2000]
        status = getattr(e, "http_request", None).status if getattr(e, "http_request", None) else None
        url    = getattr(e, "http_request", None).request_url if getattr(e, "http_request", None) else None
        out.append({
            "ts": (e.timestamp.isoformat() if e.timestamp else ""),
            "sev": e.severity,
            "svc": e.resource.labels.get("service_name") if e.resource and e.resource.labels else None,
            "trace": e.trace,
            "status": status,
            "url": url,
            "text": str(payload)[:2000]
        })
    return out

def choose_repo(services_seen):
    # prefer an explicit mapping; otherwise default
    for s in services_seen:
        if s in REPO_MAP:
            return REPO_MAP[s]
    return DEFAULT_REPO

def latest_pr_number(owner, repo):
    r = requests.get(
        f"https://api.github.com/repos/{owner}/{repo}/pulls",
        params={"state":"all","per_page":1,"sort":"updated","direction":"desc"},
        headers={"Authorization": f"Bearer {GITHUB_TOKEN}", "Accept":"application/vnd.github+json"}
    )
    r.raise_for_status()
    arr = r.json()
    if not arr:
        return None
    return arr[0]["number"]

def post_pr_comment(owner, repo, pr_number, body):
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    r = requests.post(url,
        headers={"Authorization": f"Bearer {GITHUB_TOKEN}", "Accept":"application/vnd.github+json"},
        json={"body": body})
    r.raise_for_status()
    return r.json().get("html_url")

def format_lines(lines, max_lines=30, max_chars=8000):
    lines = lines[:max_lines]
    blob = "\n\n".join(
        f'{i+1:02d} {e["ts"]} {e["sev"]} svc={e.get("svc")} status={e.get("status")} url={e.get("url")}\n{e["text"]}'
        for i, e in enumerate(lines)
    )
    if len(blob) > max_chars:
        blob = blob[:max_chars] + "\n…(truncated)…"
    return "```\n" + blob + "\n```" if blob else "_No logs in window._"

@app.post("/alert")
def alert():
    if not check_basic_auth(request):
        abort(401)

    payload = request.get_json(silent=True) or {}
    inc = payload.get("incident", {})
    started_at = inc.get("started_at") or int(time.time())
    t0 = datetime.fromtimestamp(int(started_at), tz=timezone.utc) - timedelta(minutes=WINDOW_MIN)
    t1 = datetime.fromtimestamp(int(started_at), tz=timezone.utc) + timedelta(minutes=WINDOW_MIN)

    # Pull request logs with weird statuses
    req_logs = fetch_logs(filter_requests_weird(), t0, t1)
    # Try to pull container errors; if any request had a trace, focus on it
    trace = next((e["trace"] for e in req_logs if e.get("trace")), None)
    err_logs = fetch_logs(filter_container_errors(trace), t0, t1)

    services_seen = [e["svc"] for e in (req_logs + err_logs) if e.get("svc")]
    repo_slug = choose_repo(services_seen)
    if not repo_slug:
        abort(500, "No repo mapping (REPO_MAP_JSON/DEFAULT_REPO) matched the services in logs")

    owner, repo = repo_slug.split("/", 1)
    pr = latest_pr_number(owner, repo)
    if not pr:
        abort(500, f"No pull requests found in {repo_slug}; create one once so we can comment on it.")

    # Build comment
    header = f"Paging @{CODEX_HANDLE} — unusual HTTP statuses or errors detected"
    req_block = format_lines(req_logs, max_lines=MAX_LINES//2, max_chars=MAX_CHARS//2)
    err_block = format_lines(err_logs, max_lines=MAX_LINES//2, max_chars=MAX_CHARS//2)

    body = (
        f"{header}\n\n"
        f"**Window:** `{t0.isoformat()} – {t1.isoformat()}` (±{WINDOW_MIN}m)\n"
        f"**Services seen:** `{', '.join(sorted(set(s for s in services_seen if s)) or ['unknown'])}`\n\n"
        f"**Request anomalies:**\n{req_block}\n\n"
        f"**Container errors (same trace if available):**\n{err_block}\n\n"
        f"<details><summary>Raw webhook payload</summary>\n\n```json\n{json.dumps(payload)[:6000]}\n```\n</details>"
    )

    link = post_pr_comment(owner, repo, pr, body)
    return {"repo": repo_slug, "pr": pr, "comment_url": link}, 200
