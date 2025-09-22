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

* A Google Cloud project with Cloud Run, Cloud Logging, Cloud Monitoring, and Secret Manager enabled.
* A service account used by CI with **Cloud Run Admin**, **Service Account User**, **Logging Viewer**, and **Secret Manager Secret Accessor** roles so the workflow can deploy and mount secrets.
* Ensure the Cloud Run runtime service account (default compute or custom) also has **Logging Viewer** and **Secret Manager Secret Accessor** so the running container can query logs and resolve secrets.
* A GitHub personal access token with permission to comment on pull requests in the target repository (store it in the Secret Manager secret `github-token`, described below).
* A GitHub repository where you will host this code and run the CI/CD workflow.

> ℹ️  The sample app reads Basic Auth credentials from environment variables `WEBHOOK_USER` / `WEBHOOK_PASS`. If you skip them the webhook is wide open, so it is best to set them.

## 1. Configure GitHub repository secrets and variables

### Repository secrets

Create the following repository **secrets** (`Settings → Secrets and variables → Actions → New repository secret`). The deploy workflow forwards each secret to Cloud Run or to the deployment tooling as noted.

| Secret | Used for | Cloud Run env var | Example |
| --- | --- | --- | --- |
| `PROJECT_ID` | gcloud deploy project | _n/a (deploy flag)_ | `my-gcp-project` |
| `REGION` | Cloud Run region + log filters | `REGION` | `europe-north1` |
| `GCP_SA_KEY` | Service account key (JSON) used by CI to authenticate | _n/a (auth step)_ | *(contents of the key file)* |

These are the only GitHub secrets required; runtime credentials now live in Google Secret Manager and are described below.

### Google Secret Manager secrets

Create the following secrets in Secret Manager (`Security → Secret Manager → Create Secret` or via `gcloud`). The CI/CD workflow references them by name and always deploys the latest version.

| Secret | Purpose | Example value |
| --- | --- | --- |
| `services` | Comma-separated Cloud Run service names to inspect | `svc-a,svc-b` |
| `repo-map` | JSON mapping service → GitHub repo | `{"svc-a":"OWNER/REPO_A"}` |
| `webhook-user` | Webhook Basic Auth username | `henrik` |
| `webhook-pass` | Webhook Basic Auth password | `strong-generated-value` |
| `github-token` | GitHub PAT used for PR comments | `ghp_xxx` |

Keep the `repo-map` JSON compact (no spaces or newlines) so the resulting environment variable is valid JSON.

Example creation commands (run once per secret; skip the `create` step if the secret already exists):

```bash
gcloud secrets create services --replication-policy=automatic
printf 'svc-a,svc-b' | gcloud secrets versions add services --data-file=-

gcloud secrets create repo-map --replication-policy=automatic
printf '{"svc-a":"OWNER/REPO_A"}' | gcloud secrets versions add repo-map --data-file=-

gcloud secrets create webhook-user --replication-policy=automatic
printf 'henrik' | gcloud secrets versions add webhook-user --data-file=-

gcloud secrets create webhook-pass --replication-policy=automatic
printf 'strong-generated-value' | gcloud secrets versions add webhook-pass --data-file=-

gcloud secrets create github-token --replication-policy=automatic
printf 'ghp_xxx' | gcloud secrets versions add github-token --data-file=-
```

Grant both the GitHub Actions deployer service account (the one whose key is stored in `GCP_SA_KEY`) and the Cloud Run runtime service account access to each secret:

```bash
for sa in "ci-deployer@PROJECT_ID.iam.gserviceaccount.com" "PROJECT_NUMBER-compute@developer.gserviceaccount.com"; do
  for secret in services repo-map webhook-user webhook-pass github-token; do
    gcloud secrets add-iam-policy-binding "$secret" \
      --member="serviceAccount:${sa}" \
      --role="roles/secretmanager.secretAccessor"
  done
done
```

Replace `ci-deployer@…` with your GitHub Actions service account email and update the runtime identity if you use a custom one. Granting `roles/secretmanager.secretAccessor` ensures both accounts can read the secret data during deployment and at runtime.

### Repository variables

Add the following repository **variables** (`Settings → Secrets and variables → Actions → New repository variable`). They control comment formatting and log selection and can be tuned without touching secrets:
| Variable | Purpose | Default idea |
| --- | --- | --- |
| `CODEX_HANDLE` | Handle to mention in PR comments | `codex` 
| `WINDOW_MIN` | Minutes before/after an incident to query logs | `5` |
| `MAX_LINES` | Maximum total log lines captured | `40` |
| `MAX_CHARS` | Maximum characters included in the comment | `20000` |

### GitHub token for PR comments

The bridge reads the GitHub PAT from the `GITHUB_TOKEN` environment variable. Populate the Secret Manager secret `github-token`; the CI/CD workflow mounts it and exposes the value as `GITHUB_TOKEN` inside Cloud Run on every deploy.

> Tip: For local debugging you can export the token with `export GITHUB_TOKEN="$(gcloud secrets versions access latest --secret=github-token)"` before running the app.

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

Attach a **webhook notification channel**. You will point it at the Cloud Run URL once the bridge is deployed. Enable Basic Auth on the channel and use the same username/password you stored in Secret Manager (`webhook-user` / `webhook-pass`).

## 3. Deploy the bridge service

### Manual deployment (optional)

To verify the setup before wiring up CI, deploy once with `gcloud` from this repo root. Ensure the Secret Manager entries described above exist, then provide the non-secret parameters as environment variables:

```bash
export PROJECT_ID="my-gcp-project"
export REGION="europe-north1"
export CODEX_HANDLE="codex"
export WINDOW_MIN="5"
export MAX_LINES="40"
export MAX_CHARS="20000"
```

When you run `gcloud run deploy`, reference the Secret Manager secrets so Cloud Run receives them as environment variables:

```bash
gcloud run deploy log2pr-bridge \
  --source . \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --allow-unauthenticated \
  --set-env-vars REGION="${REGION}",WINDOW_MIN="${WINDOW_MIN}",MAX_LINES="${MAX_LINES}",MAX_CHARS="${MAX_CHARS}",CODEX_HANDLE="${CODEX_HANDLE}" \
  --set-secrets CLOUD_RUN_SERVICES=services:latest,REPO_MAP_JSON=repo-map:latest,WEBHOOK_USER=webhook-user:latest,WEBHOOK_PASS=webhook-pass:latest,GITHUB_TOKEN=github-token:latest
```

If you use a custom runtime service account, append `--service-account` and make sure that account has both **Logging Viewer** and **Secret Manager Secret Accessor** roles. The identity running `gcloud` must also have `roles/secretmanager.secretAccessor` on each secret so it can attach them during deployment.

### Automated deployment (GitHub Actions)

This repository ships with a workflow at `.github/workflows/deploy.yml`. It:

1. authenticates to Google Cloud using the `GCP_SA_KEY` repository secret,
2. builds and deploys the service to Cloud Run whenever you push to `main`, and
3. wires the repository variables into standard environment variables and mounts the Secret Manager secrets (`services`, `repo-map`, `webhook-user`, `webhook-pass`, `github-token`) as Cloud Run environment variables.

You can also trigger it manually from the **Actions** tab using **Run workflow**. Ensure the service account JSON stored in `GCP_SA_KEY` belongs to the account that has the roles listed in the prerequisites.

## 4. Hook Monitoring to the bridge

After deployment grab the Cloud Run HTTPS URL and configure your Monitoring policy to send notifications to it:

1. Monitoring → Alerting → Notification channels → Webhooks → **Add new**.
2. Paste the Cloud Run URL.
3. Enable Basic authentication and fill the username/password you stored in the `webhook-user` / `webhook-pass` secrets.
4. Save and test — you should receive a 200 OK from the bridge.

Once the policy fires, the bridge will look up surrounding logs, map the affected service to a repo using `REPO_MAP_JSON`, and post a comment mentioning `@${CODEX_HANDLE}` on the latest updated pull request (open or closed).

## 5. Tuning and extensions

* **Status whitelist:** modify the log filter to allow expected statuses (e.g., 401, 403, 409) or add latency constraints (e.g., `httpRequest.latency>="3s"`).
* **Service → repo mapping:** keep the `repo-map` secret updated whenever you add new Cloud Run services so incidents always resolve to a repository.
* **Secret rotation:** because the workflow deploys the `:latest` version of each secret, rotate credentials by adding a new secret version and re-running the deploy (or pushing to `main`).
* **No PR history:** GitHub's API cannot add comments if the repository has never had a pull request. Ensure at least one PR exists (even if closed) or extend the service to open a dedicated "codex inbox" PR.

## Local development

You can run the bridge locally with Flask for quick iteration:

```bash
# Provide values that mirror your deployment (pull secrets from Secret Manager when possible)
export PROJECT_ID="my-gcp-project"
export REGION="europe-north1"
export SERVICES="$(gcloud secrets versions access latest --secret=services)"
export REPO_MAP_JSON="$(gcloud secrets versions access latest --secret=repo-map)"
export WEBHOOK_USER="$(gcloud secrets versions access latest --secret=webhook-user)"
export WEBHOOK_PASS="$(gcloud secrets versions access latest --secret=webhook-pass)"
export GITHUB_TOKEN="$(gcloud secrets versions access latest --secret=github-token)"

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export GOOGLE_CLOUD_PROJECT="${PROJECT_ID}" GITHUB_TOKEN="${GITHUB_TOKEN}" WEBHOOK_USER="${WEBHOOK_USER}" WEBHOOK_PASS="${WEBHOOK_PASS}" \
       REGION="${REGION}" CLOUD_RUN_SERVICES="${SERVICES}" REPO_MAP_JSON="${REPO_MAP_JSON}"
flask --app app run --debug
```

Send a sample request to `http://localhost:5000/alert` with the Monitoring webhook payload to test parsing.

---

With the alert, Cloud Run bridge, and GitHub workflow in place, any suspicious behavior in Cloud Run will immediately page `@codex` on the most recent pull request, backed by the log snippets you need for triage.
