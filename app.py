import os, json, base64, time, hashlib
from datetime import datetime, timedelta, timezone
from flask import Flask, request, abort
import requests
import re
import base64, hmac
from flask import Response
from google.cloud import logging_v2
from google.api_core import exceptions as gcloud_exceptions
from google.auth import exceptions as google_auth_exceptions

app = Flask(__name__)

# ---- Config ----
def _first_env_value(*names):
    for name in names:
        value = os.environ.get(name)
        if value:
            value = value.strip()
            if value:
                return value
    return None


PROJECT_ID   = _first_env_value("GCP_PROJECT", "GOOGLE_CLOUD_PROJECT", "PROJECT_ID")
REGION       = os.environ.get("REGION", "")
SERVICES     = [s.strip() for s in os.environ.get("CLOUD_RUN_SERVICES", "").split(",") if s.strip()]
REPO_MAP     = json.loads(os.environ.get("REPO_MAP_JSON", "{}"))  # {"svc-a":"owner/repo", ...}
DEFAULT_REPO = os.environ.get("DEFAULT_REPO", "owner/repo")  # fallback "owner/repo" if service not in REPO_MAP

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]  # store in Secret Manager
CODEX_HANDLE = os.environ.get("CODEX_HANDLE", "codex")  # mention target, e.g. "codex"
def _strip_secret(value):
    if value is None:
        return None
    value = value.strip()
    return value or None


BASIC_USER   = _strip_secret(os.environ.get("WEBHOOK_USER"))
BASIC_PASS   = _strip_secret(os.environ.get("WEBHOOK_PASS"))

WINDOW_MIN   = int(os.environ.get("WINDOW_MIN", "5"))  # minutes around incident
MAX_LINES    = int(os.environ.get("MAX_LINES", "40"))  # total lines to include
MAX_CHARS    = int(os.environ.get("MAX_CHARS", "20000"))

# ---- Helpers ----
def extract_hints(payload):
    inc = payload.get("incident", {}) or {}
    labels = (inc.get("resource", {}) or {}).get("labels", {}) or {}

    svc_hint = labels.get("service_name")
    region_hint = labels.get("location")

    # Fallback: parse from resource_name like
    # projects/.../locations/us-west1/services/weather-db/revisions/...
    rn = inc.get("resource_name") or ""
    m = re.search(r"/locations/([^/]+)/services/([^/]+)/", rn)
    if m:
        region_hint = region_hint or m.group(1)
        svc_hint = svc_hint or m.group(2)

    return svc_hint, region_hint

def _challenge():
    r = Response(status=401)
    r.headers['WWW-Authenticate'] = 'Basic realm="gcm-webhook"'
    return r

def check_basic_auth(req):
    # If no creds configured, allow through
    if not BASIC_USER or not BASIC_PASS:
        return True

    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return _challenge()

    try:
        user, pwd = base64.b64decode(auth.split()[1]).decode("utf-8").split(":", 1)
    except Exception:
        return _challenge()

    if not (hmac.compare_digest(user, BASIC_USER) and hmac.compare_digest(pwd, BASIC_PASS)):
        return _challenge()

    return True

def svc_clause_for(names):
    names = [s.strip() for s in (names or []) if s and s.strip()]
    if not names:
        return None
    return " OR ".join([f'resource.labels.service_name="{s}"' for s in names])

def filter_requests_weird(region=None, services=None):
    f = [
        'resource.type="cloud_run_revision"',
        'logName:"run.googleapis.com%2Frequests"',
        'NOT httpRequest.userAgent:"GoogleHC"',
        'NOT httpRequest.requestUrl:"/health"',
    ]
    if region:
        f.append(f'resource.labels.location="{region}"')
    clause = svc_clause_for(services)
    if clause:
        f.append(f'({clause})')
    f.append(
        '('
        'httpRequest.status < 200 OR '
        '(httpRequest.status > 206 AND httpRequest.status < 300) OR '
        '(httpRequest.status >= 300 AND httpRequest.status != 301 AND '
        ' httpRequest.status != 302 AND httpRequest.status != 303 AND '
        ' httpRequest.status != 304 AND httpRequest.status != 307 AND httpRequest.status != 308) OR '
        'httpRequest.status >= 400'
        ') AND httpRequest.status != 404'
    )
    return "\n".join(f)

def filter_container_errors(trace=None, region=None, services=None):
    f = ['resource.type="cloud_run_revision"']
    if region:
        f.append(f'resource.labels.location="{region}"')
    clause = svc_clause_for(services)
    if clause:
        f.append(f'({clause})')
    f.append('(severity>=ERROR OR textPayload:("Traceback" OR "Exception" OR "CRITICAL" OR "panic:") '
             'OR jsonPayload.message:("error" OR "exception"))')
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


def _summarize_log_exception(exc, max_len=500):
    message = getattr(exc, "message", None) or str(exc) or exc.__class__.__name__
    message = " ".join(message.split())
    if isinstance(exc, gcloud_exceptions.PermissionDenied):
        message = f"{message} (check that the Cloud Run runtime service account has Logging Viewer access)"
    elif isinstance(exc, google_auth_exceptions.DefaultCredentialsError):
        message = f"{message} (application default credentials were not found)"
    if len(message) > max_len:
        message = message[: max_len - 1] + "…"
    return message
    
def _ok(**kwargs):
    # Always acknowledge to Monitoring; include context for debugging
    return {"ok": True, **kwargs}, 200

def try_fetch_logs(filter_text, start, end, page_size=100):
    try:
        return fetch_logs(filter_text, start, end, page_size=page_size), None
    except (
        gcloud_exceptions.GoogleAPICallError,
        gcloud_exceptions.RetryError,
        google_auth_exceptions.GoogleAuthError,
        OSError,        # was EnvironmentError; OSError is the canonical alias
        ValueError,
    ) as exc:
        app.logger.error("Cloud Logging query failed: %s", _summarize_log_exception(exc))
        app.logger.error(
            "Filter used:\n%s\n",
            f'{filter_text}\n'
            f'timestamp>="{start.isoformat()}" AND timestamp<="{end.isoformat()}"'
        )
        return [], _summarize_log_exception(exc)
    except Exception as exc:  # last-resort safety net
        app.logger.exception("Unexpected error while querying Cloud Logging")
        return [], _summarize_log_exception(exc)


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
        return ("", 401)

    payload = request.get_json(silent=True) or {}
    inc = payload.get("incident", {}) or {}
    svc_hint, region_hint = extract_hints(payload)

    started_at = inc.get("started_at") or int(time.time())
    t0 = datetime.fromtimestamp(int(started_at), tz=timezone.utc) - timedelta(minutes=WINDOW_MIN)
    t1 = datetime.fromtimestamp(int(started_at), tz=timezone.utc) + timedelta(minutes=WINDOW_MIN)

    # Query logs using the hints (don’t rely solely on env REGION/SERVICES)
    req_logs, req_error = try_fetch_logs(
        filter_requests_weird(region=region_hint or REGION,
                              services=[svc_hint] if svc_hint else SERVICES),
        t0, t1
    )
    trace = next((e["trace"] for e in req_logs if e.get("trace")), None)
    err_logs, err_error = try_fetch_logs(
        filter_container_errors(trace, region=region_hint or REGION,
                                services=[svc_hint] if svc_hint else SERVICES),
        t0, t1
    )

    # Build the set of candidate services
    services_seen = sorted({e.get("svc") for e in (req_logs + err_logs) if e.get("svc")})
    if svc_hint:
        services_seen = sorted(set(services_seen + [svc_hint]))

    # Now map to repo
    repo_slug = choose_repo(services_seen)
    if not repo_slug or "/" not in repo_slug or repo_slug.lower() in {"owner/repo", "org/repo"}:
        app.logger.error("Invalid/missing repo mapping. services_seen=%s REPO_MAP=%s DEFAULT_REPO=%r",
                         services_seen, list(REPO_MAP.keys()), DEFAULT_REPO)
        return {"ok": True, "note": "bad_repo_slug", "services_seen": services_seen}, 200
    
    owner, repo = repo_slug.split("/", 1)
    
    try:
        pr = latest_pr_number(owner, repo)
    except requests.HTTPError as e:
        body = e.response.text[:2000] if getattr(e, "response", None) else ""
        app.logger.error("GitHub latest_pr_number failed: %s body=%s", e, body)
        return _ok(note="github_latest_pr_error", status=getattr(e.response, "status_code", None))
    
    if not pr:
        app.logger.warning("No PRs found in %s", repo_slug)
        return _ok(note="no_prs_found", repo=repo_slug)

    # Build comment
    header = f"Paging @{CODEX_HANDLE} — unusual HTTP statuses or errors detected"
    req_block = (
        format_lines(req_logs, max_lines=MAX_LINES//2, max_chars=MAX_CHARS//2)
        if not req_error
        else f"_⚠️ Failed to load logs: {req_error}_"
    )
    err_block = (
        format_lines(err_logs, max_lines=MAX_LINES//2, max_chars=MAX_CHARS//2)
        if not err_error
        else f"_⚠️ Failed to load logs: {err_error}_"
    )

    body = (
        f"{header}\n\n"
        f"**Window:** `{t0.isoformat()} – {t1.isoformat()}` (±{WINDOW_MIN}m)\n"
        f"**Services seen:** `{', '.join(sorted(set(s for s in services_seen if s)) or ['unknown'])}`\n\n"
        f"**Request anomalies:**\n{req_block}\n\n"
        f"**Container errors (same trace if available):**\n{err_block}\n\n"
        f"<details><summary>Raw webhook payload</summary>\n\n```json\n{json.dumps(payload)[:6000]}\n```\n</details>"
    )

    try:
        link = post_pr_comment(owner, repo, pr, body)
    except requests.HTTPError as e:
        body = e.response.text[:2000] if getattr(e, "response", None) else ""
        app.logger.error("GitHub comment failed: %s body=%s", e, body)
        return _ok(note="github_comment_error",
                   status=getattr(e.response, "status_code", None), repo=repo_slug, pr=pr)

    response = {"repo": repo_slug, "pr": pr, "comment_url": link}
    log_errors = {}
    if req_error:
        log_errors["requests"] = req_error
    if err_error:
        log_errors["container"] = err_error
    if log_errors:
        response["log_errors"] = log_errors
    return response, 200
