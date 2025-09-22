# Cloud Run log-to-PR bridge

This repository contains a tiny Cloud Run service that turns a single Google Cloud Monitoring alert into a GitHub pull request mention. When the alert fires, the bridge

1. receives the webhook payload, optionally guarded by HTTP Basic authentication,
2. queries Cloud Logging for "weird" HTTP statuses and obvious application errors around the incident timestamp,
3. maps the Cloud Run service to the owning GitHub repository,
4. finds the most recently updated pull request (open or closed), and
5. posts a compact log extract that pings `@codex` (configurable).

The result is a reusable incident-notification pattern that needs only one Monitoring policy per project and works even when no PR is currently open.

## How it fits together

```
Cloud Monitoring alert  ──▶  Cloud Run bridge  ──▶  GitHub PR comment (@codex)
                   │                   │
                   └── queries Cloud Logging for the surrounding errors ─┘
```

## Prerequisites

* A Google Cloud project with Cloud Run, Cloud Logging, and Cloud Monitoring enabled.
* A service account with **Cloud Run Admin**, **Service Account User**, and **Logging Viewer** roles for deployment.
* A GitHub personal access token (classic or fine-grained) with `repo` scope so the bridge can comment on pull requests.
* A GitHub repository where you will host this code and run the CI/CD workflow.

> ℹ️  The sample app reads Basic Auth credentials from environment variables `WEBHOOK_USER` / `WEBHOOK_PASS`. If you skip them the webhook is wide open, so it is best to set them.

## 1. Configure GitHub secrets and variables

Create the following repository **secrets** (`Settings → Secrets and variables → Actions → New repository secret`). The deploy workflow forwards each secret to Cloud Run as shown below.

| Secret | Used for | Cloud Run env var | Example |
| --- | --- | --- | --- |
| `PROJECT_ID` | gcloud deploy project | _n/a (deploy flag)_ | `my-gcp-project` |
| `REGION` | Cloud Run region + log filters | `REGION` | `europe-north1` |
| `SERVICES` | Comma-separated Cloud Run service names to inspect | `CLOUD_RUN_SERVICES` | `svc-a,svc-b` |
| `REPO_MAP` | JSON object mapping service → GitHub repo | `REPO_MAP_JSON` | `{ "svc-a": "OWNER/REPO_A" }` |
| `DEFAULT_REPO` | (Recommended) fallback repo if mapping misses | `DEFAULT_REPO` | `OWNER/REPO_FALLBACK` |
| `BASIC_USER` | Webhook Basic Auth username | `WEBHOOK_USER` | `henrik` |
| `BASIC_PASS` | Webhook Basic Auth password | `WEBHOOK_PASS` | `strong-generated-value` |
| `GH_PR_TOKEN` | Long-lived PAT used by the bridge to comment | `GITHUB_TOKEN` | _GitHub PAT string_ |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` **or** `GCP_SA_KEY` | GitHub → GCP authentication | _n/a (deploy step)_ | Workload Identity provider resource name or JSON key |
| `GCP_SERVICE_ACCOUNT` (if using WIF) | Service account email for deployment | _n/a (deploy step)_ | `deploy-bot@my-gcp-project.iam.gserviceaccount.com` |

Then add these repository **variables** (`Settings → Secrets and variables → Actions → New repository variable`). They control comment formatting and log selection and can be tuned without touching secrets:

| Variable | Purpose | Default idea |
| --- | --- | --- |
| `CODEX_HANDLE` | Handle to mention in PR comments | `codex` |
| `WINDOW_MIN` | Minutes before/after incident to query logs | `5` |
| `MAX_LINES` | Maximum total log lines captured | `40` |
| `MAX_CHARS` | Maximum characters included in the comment | `20000` |

### Notes on values

* `REPO_MAP` **must** be a valid JSON string. If you need multiple mappings, include them all: `{ "svc-a": "OWNER/REPO_A", "svc-b": "OWNER/REPO_B" }`.
* Ensure every service in the alert is represented in `REPO_MAP`; otherwise also set `DEFAULT_REPO` so incidents never fail.
* Store the GitHub PAT in `GH_PR_TOKEN`. It is long-lived and will be baked into the Cloud Run environment, so treat it with care.

## 2. Build the log-based alert filter

Create a logs-based alerting policy in Cloud Monitoring that captures unusual HTTP statuses or obvious application errors. You can paste the filter below and adjust the service names and region as needed.

```text
(
  resource.type="cloud_run_revision"
  logName=~"projects/.*/logs/run.googleapis.com%2Frequests"
  (resource.labels.service_name="SVC_A" OR resource.labels.service_name="SVC_B")
  NOT httpRequest.userAgent:"GoogleHC"
  NOT httpRequest.requestUrl:"/health"
  (
    httpRequest.status<200 OR
    (httpRequest.status>=300 AND httpRequest.status!=301 AND httpRequest.status!=302 AND httpRequest.status!=303
                               AND httpRequest.status!=304 AND httpRequest.status!=307 AND httpRequest.status!=308) OR
    (httpRequest.status=404 ? false : false)
  )
)
OR
(
  resource.type="cloud_run_revision"
  (resource.labels.service_name="SVC_A" OR resource.labels.service_name="SVC_B")
  (
    severity>=ERROR OR
    textPayload:("Traceback" OR "Exception" OR "CRITICAL" OR "panic:") OR
    jsonPayload.message:("error" OR "exception")
  )
)
```

Attach a **webhook notification channel**. You will point it at the Cloud Run URL once the bridge is deployed. Enable Basic Auth on the channel and use the same username/password you stored in GitHub secrets.

## 3. Deploy the bridge service

### Manual deployment (one-off)

If you want to verify locally before wiring up CI, deploy with gcloud from this repo root:

```bash
gcloud run deploy log2pr-bridge \
  --source . \
  --region "${REGION}" \
  --project "${PROJECT_ID}" \
  --allow-unauthenticated \
  --set-env-vars REGION="${REGION}",WINDOW_MIN="${WINDOW_MIN}",MAX_LINES="${MAX_LINES}",MAX_CHARS="${MAX_CHARS}",CODEX_HANDLE="${CODEX_HANDLE}" \
  --set-env-vars CLOUD_RUN_SERVICES="svc-a,svc-b",REPO_MAP_JSON='{"svc-a":"OWNER/REPO_A","svc-b":"OWNER/REPO_B"}',DEFAULT_REPO="OWNER/REPO_FALLBACK" \
  --set-env-vars WEBHOOK_USER="${BASIC_USER}",WEBHOOK_PASS="${BASIC_PASS}",GITHUB_TOKEN="${GH_PR_TOKEN}"
```

The service account running the container must have **Logging Viewer** access to read log entries.

### Automated deployment (GitHub Actions)

This repository ships with a workflow at `.github/workflows/deploy.yml`. It:

1. authenticates to Google Cloud via Workload Identity Federation or a service account key,
2. builds and deploys the service to Cloud Run whenever you push to `main`, and
3. forwards the secrets and variables above into Cloud Run environment variables.

You can also trigger it manually from the **Actions** tab using "Run workflow".

Make sure the authentication inputs are configured (either `GCP_WORKLOAD_IDENTITY_PROVIDER` + `GCP_SERVICE_ACCOUNT`, or `GCP_SA_KEY`). The workflow assumes the Cloud Run service is named `log2pr-bridge`; adjust the `SERVICE_NAME` env at the top of the file if you prefer a different name.

## 4. Hook Monitoring to the bridge

After deployment grab the Cloud Run HTTPS URL and configure your Monitoring policy to send notifications to it:

1. Monitoring → Alerting → Notification channels → Webhooks → **Add new**.
2. Paste the Cloud Run URL.
3. Enable Basic authentication and fill the username/password from `BASIC_USER`/`BASIC_PASS`.
4. Save and test — you should receive a 200 OK from the bridge.

Once the policy fires, the bridge will look up surrounding logs, map the affected service to a repo using `REPO_MAP_JSON`, and post a comment mentioning `@${CODEX_HANDLE}` on the latest updated pull request (open or closed).

## 5. Tuning and extensions

* **Status whitelist:** modify the log filter to allow expected statuses (e.g., 401, 403, 409) or add latency constraints (e.g., `httpRequest.latency>="3s"`).
* **Service → repo mapping:** keep `REPO_MAP` JSON updated whenever you add new Cloud Run services. Use `DEFAULT_REPO` as a safety net.
* **Secrets vs environment variables:** for higher security you can mirror the GitHub secrets into Secret Manager (`gcloud secrets versions add ...`) and swap `--set-env-vars` for `--set-secrets` in the deploy command.
* **No PR history:** GitHub's API cannot add comments if the repository has never had a pull request. Ensure at least one PR exists (even if closed) or extend the service to open a dedicated "codex inbox" PR.

## Local development

You can run the bridge locally with Flask for quick iteration:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export GOOGLE_CLOUD_PROJECT="${PROJECT_ID}" GITHUB_TOKEN="${GH_PR_TOKEN}" WEBHOOK_USER="${BASIC_USER}" WEBHOOK_PASS="${BASIC_PASS}" \
       REGION="${REGION}" CLOUD_RUN_SERVICES="svc-a,svc-b" REPO_MAP_JSON='{"svc-a":"OWNER/REPO_A"}' DEFAULT_REPO="OWNER/REPO_FALLBACK"
flask --app app run --debug
```

Send a sample request to `http://localhost:5000/alert` with the Monitoring webhook payload to test parsing.

---

With the alert, Cloud Run bridge, and GitHub workflow in place, any suspicious behavior in Cloud Run will immediately page `@codex` on the most recent pull request, backed by the log snippets you need for triage.
