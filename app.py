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
PRE_MIN = int(os.environ.get("PRE_MIN", "3"))  # minutes to include *before* trigger


# ---- Helpers ----
def svc_clause_for(names):
    names = [s.strip() for s in (names or []) if s and s.strip()]
    if not names:
        return None
    return " OR ".join([f'resource.labels.service_name="{s}"' for s in names])

def region_clause_for(regions):
    regs = [r for r in (regions or []) if r]
    if not regs:
        return None
    return "(" + " OR ".join([f'resource.labels.location="{r}"' for r in regs]) + ")"

def _get(obj, name, default=None):
    """Attr-or-dict get."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)

def _get_nested(obj, *names, default=None):
    cur = obj
    for n in names:
        cur = _get(cur, n)
        if cur is None:
            return default
    return cur

def _payload_to_str(entry):
    """Normalize payload (text/json/proto) to a short string."""
    if isinstance(entry, dict):
        if "textPayload" in entry:
            return str(entry["textPayload"])[:2000]
        if "jsonPayload" in entry:
            try:
                return json.dumps(entry["jsonPayload"])[:2000]
            except Exception:
                return str(entry["jsonPayload"])[:2000]
        if "protoPayload" in entry:
            try:
                return json.dumps(entry["protoPayload"])[:2000]
            except Exception:
                return str(entry["protoPayload"])[:2000]
        # Some dict-shaped entries put the merged content under 'payload'
        if "payload" in entry:
            p = entry["payload"]
            if isinstance(p, str):
                return p[:2000]
            try:
                return json.dumps(p)[:2000]
            except Exception:
                return str(p)[:2000]
        return ""
    # Object-shaped entries (google.cloud.logging_v2.entries.LogEntry)
    payload = getattr(entry, "payload", None)
    if isinstance(payload, str):
        return payload[:2000]
    if isinstance(payload, dict):
        return (payload.get("message") or payload.get("msg")
                or json.dumps(payload))[:2000]
    return (str(payload)[:2000]) if payload is not None else ""

# ---  fetch_logs ------------------------------------------------------
def fetch_logs(filter_text, start, end, page_size=100):
    client = logging_v2.Client(project=PROJECT_ID)
    time_filter = f'timestamp>="{start.isoformat()}" AND timestamp<="{end.isoformat()}"'
    final = f"{filter_text}\n{time_filter}"

    entries = client.list_entries(
        filter_=final,
        order_by=logging_v2.DESCENDING,
        page_size=page_size
    )

    out = []
    for e in entries:
        # timestamp
        ts = getattr(e, "timestamp", None)
        ts_str = ts.isoformat() if isinstance(ts, datetime) else (str(ts) if ts else "")

        # severity
        sev = getattr(e, "severity", None)
        # http request (object or dict with snake/camel)
        http = getattr(e, "http_request", None)
        if isinstance(http, dict):
            status = http.get("status")
            url    = http.get("request_url") or http.get("requestUrl") or http.get("url")
            method = http.get("request_method") or http.get("requestMethod") or http.get("method")
        else:
            status = getattr(http, "status", None) if http else None
            url    = getattr(http, "request_url", None) if http else None
            method = getattr(http, "request_method", None) if http else None

        # resource.labels.service_name (object or dict)
        res = getattr(e, "resource", None)
        labels = {}
        if isinstance(res, dict):
            labels = res.get("labels", {}) or {}
        else:
            labels = getattr(res, "labels", {}) or {}
        svc = labels.get("service_name")

        # trace
        trace = getattr(e, "trace", None)

        # payload normalization
        text = _payload_to_str(e)

        out.append({
            "ts": ts_str,
            "sev": sev,
            "svc": svc,
            "trace": trace,
            "status": status,
            "method": method,
            "url": url,
            "text": text,
        })
    return out


def format_lines(lines, max_lines=30, max_chars=8000, chronological=False):
    entries = list(lines or [])
    entries = list(reversed(entries))[-max_lines:] if chronological else entries[:max_lines]
    blob = "\n\n".join(
        f'{i+1:02d} {e.get("ts","")} {e.get("sev","")} '
        f'svc={e.get("svc") or "-"} status={e.get("status") or "-"} '
        f'method={e.get("method") or "-"} url={e.get("url") or "-"}\n'
        f'{e.get("text","")}'
        for i, e in enumerate(entries)
    )
    if len(blob) > max_chars:
        blob = blob[:max_chars] + "\n…(truncated)…"
    return f"```\n{blob}\n```" if blob else "_No logs in window._"


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


def filter_container_errors(region=None, services=None):
    f = ['resource.type="cloud_run_revision"']
    if region:
        f.append(f'resource.labels.location="{region}"')
    clause = svc_clause_for(services)
    if clause:
        f.append(f'({clause})')
    # Exclude request logs; match stderr/stdout “error-looking” lines
    f.append('NOT logName:"run.googleapis.com%2Frequests"')
    f.append('(logName:"run.googleapis.com%2Fstderr" OR logName:"run.googleapis.com%2Fstdout")')
    f.append('(severity>=ERROR OR textPayload:("Traceback" OR "Exception" OR "CRITICAL" OR "panic:") '
             'OR jsonPayload.message:("error" OR "exception") OR jsonPayload.error:*)')
    return "\n".join(f)


def filter_stderr_tail(regions=None, services=None, streams=("stderr", "stdout")):
    f = ['resource.type="cloud_run_revision"']
    if regions:
        reg = "(" + " OR ".join([f'resource.labels.location="{r}"' for r in regions if r]) + ")"
        if reg != "()": f.append(reg)
    if services:
        sc = svc_clause_for(services)
        if sc: f.append(f"({sc})")
    # streams
    parts = []
    if "stderr" in streams: parts.append('logName:"run.googleapis.com%2Fstderr"')
    if "stdout" in streams: parts.append('logName:"run.googleapis.com%2Fstdout"')
    if parts: f.append("(" + " OR ".join(parts) + ")")
    # error-ish lines
    f.append('(severity>=ERROR OR textPayload:("Traceback" OR "Exception" OR "CRITICAL" OR "panic:") '
             'OR jsonPayload.message:("error" OR "exception") OR jsonPayload.error:*)')
    return "\n".join(f)


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


@app.post("/alert")
def alert():
    if not check_basic_auth(request):
        return ("", 401)

    payload = request.get_json(silent=True) or {}
    inc = payload.get("incident", {}) or {}

    started_at = int(inc.get("started_at") or time.time())
    t1 = datetime.fromtimestamp(started_at, tz=timezone.utc)
    t0 = t1 - timedelta(minutes=WINDOW_MIN)

    svc_hint, region_hint = extract_hints(payload)

    # --- ensure the name exists BEFORE any use ---
    services_seen: list[str] = []

    # main log pulls
    req_logs, req_error = try_fetch_logs(
        filter_requests_weird(region=region_hint or REGION,
                              services=[svc_hint] if svc_hint else SERVICES),
        t0, t1
    )
    trace = next((e.get("trace") for e in req_logs if e.get("trace")), None)
    err_logs, err_error = try_fetch_logs(
        filter_container_errors(region=region_hint or REGION,
                                services=[svc_hint] if svc_hint else SERVICES),
        t0, t1, page_size=200
    )
    

    services_seen = sorted({e.get("svc") for e in (req_logs + err_logs) if e.get("svc")})

    # union services (origin + watchlist + bridge itself)
    svc_union = set(services_seen or [])
    if svc_hint: svc_union.add(svc_hint)
    if SERVICES: svc_union.update(SERVICES)
    svc_union.add(os.environ.get("K_SERVICE") or "")
    svc_union.add("log2pr-bridge")
    svc_union = sorted(s for s in svc_union if s)
    
    # regions: origin and bridge region
    regions = [region_hint or None, REGION or None]
    
    pre_t1 = datetime.fromtimestamp(started_at, tz=timezone.utc)
    pre_t0 = pre_t1 - timedelta(minutes=PRE_MIN)
    
    # 1) stderr only
    stderr_tail, stderr_err = try_fetch_logs(
        filter_stderr_tail(regions=regions, services=svc_union, streams=("stderr",)),
        pre_t0, pre_t1, page_size=100
    )
    
    # 2) if empty, add stdout too
    if not stderr_tail and not stderr_err:
        stderr_tail, stderr_err = try_fetch_logs(
            filter_stderr_tail(regions=regions, services=svc_union, streams=("stderr", "stdout")),
            pre_t0, pre_t1, page_size=150
        )
    
    # 3) if still empty, widen window by +2 min
    if not stderr_tail and not stderr_err:
        wider_t0 = pre_t1 - timedelta(minutes=PRE_MIN + 2)
        stderr_tail, stderr_err = try_fetch_logs(
            filter_stderr_tail(regions=regions, services=svc_union, streams=("stderr", "stdout")),
            wider_t0, pre_t1, page_size=200
        )
    
    stderr_block = (
        format_lines(stderr_tail, max_lines=min(40, MAX_LINES // 2),
                     max_chars=min(6000, MAX_CHARS // 2), chronological=True)
        if not stderr_err else f"_⚠️ Failed to load stderr/stdout tail: {stderr_err}_"
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
        format_lines(err_logs, max_lines=MAX_LINES, max_chars=MAX_CHARS)
        if not err_error
        else f"_⚠️ Failed to load logs: {err_error}_"
    )

    body = (
        f"{header}\n\n"
        f"**Window:** `{t0.isoformat()} – {t1.isoformat()}` (±{WINDOW_MIN}m)\n"
        f"**Services seen:** `{', '.join(services_seen) or 'unknown'}`\n\n"
        # f"**Right before trigger (stderr tail, {PRE_MIN}m):**\n{stderr_block}\n\n"
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
