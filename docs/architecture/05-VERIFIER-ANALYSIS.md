# Leakwatch - Secret Verifier Analysis

> **Document Version:** 1.0
> **Date:** 2026-03-25
> **Status:** Approved

## 1. Current State

Leakwatch currently has **63 built-in detectors** and **3 verifiers** (AWS, GitHub, Slack).

| Metric | Value |
|--------|-------|
| Total Detectors | 63 |
| Verifiers Implemented | 3 |
| Verification Coverage | 3/63 (4.8%) |
| Verifier Architecture | `init()` + compile-time registration via `verifier.Register()` |
| Verification Interface | `Verifier.Verify(ctx, RawFinding) VerificationResult` |

### Existing Verifier Patterns

All current verifiers follow a consistent pattern:

- **AWS** (`aws-access-key-id`): Uses STS `GetCallerIdentity` with the key pair (requires both Access Key ID in `Raw` and Secret Access Key in `RawV2`). Returns account/ARN metadata on success.
- **GitHub** (`github-token`): HTTP GET to `https://api.github.com/user` with `Bearer` token. Returns login username on success.
- **Slack** (`slack-token`): HTTP POST to `https://slack.com/api/auth.test` with `Bearer` token. Returns team/user metadata on success.

## 2. Verifier Classification

All 63 detectors are classified into four tiers based on verification feasibility.

### Tier 1 --- Easy (Simple API call, single credential, no extra context)

These detectors can be verified with a single HTTP request using only the detected secret as authentication. This is the highest-value, lowest-effort category.

| # | Detector ID | API Endpoint | Method | Auth Header | Complexity | Priority | Notes |
|---|-------------|-------------|--------|-------------|------------|----------|-------|
| 1 | `github-token` | `https://api.github.com/user` | GET | `Bearer {token}` | Easy | P0 | **Already implemented** |
| 2 | `slack-token` | `https://slack.com/api/auth.test` | POST | `Bearer {token}` | Easy | P0 | **Already implemented** |
| 3 | `openai-api-key` | `https://api.openai.com/v1/models` | GET | `Bearer {token}` | Easy | P0 | Returns model list; 401 if invalid |
| 4 | `anthropic-api-key` | `https://api.anthropic.com/v1/models` | GET | `x-api-key: {token}` | Easy | P0 | Requires `anthropic-version` header |
| 5 | `gitlab-pat` | `https://gitlab.com/api/v4/user` | GET | `PRIVATE-TOKEN: {token}` | Easy | P0 | Returns user info; 401 if invalid |
| 6 | `sendgrid-api-key` | `https://api.sendgrid.com/v3/user/profile` | GET | `Bearer {token}` | Easy | P0 | Returns user profile; 401/403 if invalid |
| 7 | `digitalocean-token` | `https://api.digitalocean.com/v2/account` | GET | `Bearer {token}` | Easy | P0 | Returns account info |
| 8 | `cloudflare-api-token` | `https://api.cloudflare.com/client/v4/user/tokens/verify` | GET | `Bearer {token}` | Easy | P0 | Dedicated verify endpoint |
| 9 | `newrelic-api-key` | `https://api.newrelic.com/v2/users.json` | GET | `Api-Key: {token}` | Easy | P0 | Returns user list; 401 if invalid |
| 10 | `heroku-api-key` | `https://api.heroku.com/account` | GET | `Bearer {token}` | Easy | P0 | Requires `Accept: application/vnd.heroku+json; version=3` |
| 11 | `notion-token` | `https://api.notion.com/v1/users/me` | GET | `Bearer {token}` | Easy | P0 | Requires `Notion-Version` header |
| 12 | `telegram-bot-token` | `https://api.telegram.org/bot{token}/getMe` | GET | Token in URL path | Easy | P0 | Token is part of URL, not header |
| 13 | `discord-bot-token` | `https://discord.com/api/v10/users/@me` | GET | `Bot {token}` | Easy | P0 | Returns bot user info |
| 14 | `sentry-token` | `https://sentry.io/api/0/` | GET | `Bearer {token}` | Easy | P1 | Returns auth info |
| 15 | `pagerduty-api-key` | `https://api.pagerduty.com/users/me` | GET | `Authorization: Token token={key}` | Easy | P1 | Custom auth format |
| 16 | `vercel-token` | `https://api.vercel.com/v2/user` | GET | `Bearer {token}` | Easy | P1 | Returns user info |
| 17 | `linear-api-key` | `https://api.linear.app/graphql` | POST | `Bearer {token}` | Easy | P1 | GraphQL query `{ viewer { id } }` |
| 18 | `circleci-token` | `https://circleci.com/api/v2/me` | GET | `Circle-Token: {token}` | Easy | P1 | Returns user info |
| 19 | `npm-token` | `https://registry.npmjs.org/-/npm/v1/user` | GET | `Bearer {token}` | Easy | P1 | Returns user profile |
| 20 | `huggingface-token` | `https://huggingface.co/api/whoami-v2` | GET | `Bearer {token}` | Easy | P1 | Returns user/org info |
| 21 | `airtable-pat` | `https://api.airtable.com/v0/meta/whoami` | GET | `Bearer {token}` | Easy | P1 | Dedicated whoami endpoint |
| 22 | `snyk-api-key` | `https://api.snyk.io/rest/self?version=2024-04-22` | GET | `Authorization: token {key}` | Easy | P1 | Returns user info |
| 23 | `figma-pat` | `https://api.figma.com/v1/me` | GET | `X-FIGMA-TOKEN: {token}` | Easy | P1 | Returns user info |
| 24 | `postmark-server-token` | `https://api.postmarkapp.com/server` | GET | `X-Postmark-Server-Token: {token}` | Easy | P1 | Returns server info |
| 25 | `grafana-api-key` | `https://grafana.com/api/user` | GET | `Bearer {token}` | Easy | P1 | Note: instance URL needed for self-hosted |
| 26 | `doppler-token` | `https://api.doppler.com/v3/me` | GET | `Bearer {token}` | Easy | P1 | Returns user/workplace info |
| 27 | `sonarcloud-token` | `https://sonarcloud.io/api/authentication/validate` | GET | Basic `{token}:` | Easy | P2 | Dedicated validate endpoint; Basic auth with token as username |
| 28 | `pypi-api-token` | `https://upload.pypi.org/legacy/` | POST | Basic `__token__:{token}` | Easy | P2 | Check via upload endpoint returns 400 (active) vs 403 (invalid) |
| 29 | `deepseek-api-key` | `https://api.deepseek.com/models` | GET | `Bearer {token}` | Easy | P2 | Returns model list; 401 if invalid |
| 30 | `launchdarkly-sdk-key` | `https://app.launchdarkly.com/api/v2/caller-identity` | GET | `Authorization: {key}` | Easy | P2 | Returns caller identity |

**Total Tier 1: 30 detectors (28 new + 2 already implemented)**

### Tier 2 --- Medium (Needs extra context, specific auth flow, or domain extraction)

These require either extracting additional information from the finding context (e.g., a domain name, workspace slug), using a non-standard authentication flow, or making multiple API calls.

| # | Detector ID | API Endpoint | Method | Auth | Complexity | Priority | Notes |
|---|-------------|-------------|--------|------|------------|----------|-------|
| 1 | `aws-access-key-id` | AWS STS `GetCallerIdentity` | SDK | HMAC-signed | Medium | P0 | **Already implemented**. Needs both Access Key ID + Secret Access Key |
| 2 | `stripe-api-key-live` | `https://api.stripe.com/v1/charges?limit=1` | GET | Basic `{key}:` | Medium | P0 | Live key -- verification must be read-only; use minimal-scope endpoint |
| 3 | `stripe-api-key-test` | `https://api.stripe.com/v1/charges?limit=1` | GET | Basic `{key}:` | Medium | P1 | Test key -- lower risk but same flow as live |
| 4 | `twilio-api-key` | `https://api.twilio.com/2010-04-01/Accounts.json` | GET | Basic `{sid}:{token}` | Medium | P1 | Needs Account SID + Auth Token pair |
| 5 | `mailgun-api-key` | `https://api.mailgun.net/v3/domains` | GET | Basic `api:{key}` | Medium | P1 | Uses Basic auth with `api` as username |
| 6 | `shopify-access-token` | `https://{shop}.myshopify.com/admin/api/2024-01/shop.json` | GET | `X-Shopify-Access-Token: {token}` | Medium | P1 | Requires shop domain from context |
| 7 | `okta-api-token` | `https://{domain}/api/v1/users/me` | GET | `SSWS {token}` | Medium | P1 | Requires Okta domain from context |
| 8 | `databricks-token` | `https://{workspace}.cloud.databricks.com/api/2.0/clusters/list` | GET | `Bearer {token}` | Medium | P1 | Requires workspace URL from context |
| 9 | `github-oauth-token` | `https://api.github.com/user` | GET | `Bearer {token}` | Medium | P1 | Same endpoint as github-token but OAuth tokens may have limited scopes |
| 10 | `auth0-management-token` | `https://{domain}/api/v2/users?per_page=1` | GET | `Bearer {token}` | Medium | P2 | JWT-format; needs Auth0 domain extracted from token `iss` claim |
| 11 | `coinbase-api-key` | `https://api.coinbase.com/v2/user` | GET | HMAC signature | Medium | P2 | Requires API key + secret + timestamp-based HMAC signing |
| 12 | `datadog-api-key` | `https://api.datadoghq.com/api/v1/validate` | GET | `DD-API-KEY: {key}` | Medium | P2 | Dedicated validate endpoint; may also need Application Key for full validation |
| 13 | `hashicorp-vault-token` | `https://{vault-addr}/v1/auth/token/lookup-self` | GET | `X-Vault-Token: {token}` | Medium | P2 | Requires Vault server address from context |
| 14 | `terraform-cloud-token` | `https://app.terraform.io/api/v2/account/details` | GET | `Bearer {token}` | Medium | P2 | Standard Bearer auth; some tokens may be for Terraform Enterprise (custom URL) |
| 15 | `supabase-service-key` | `https://{project-ref}.supabase.co/rest/v1/` | GET | `apikey: {key}` + `Authorization: Bearer {key}` | Medium | P2 | Needs project ref from context; JWT format may contain project ref |
| 16 | `rubygems-api-key` | `https://rubygems.org/api/v1/api_key.json` | GET | `Authorization: {key}` | Medium | P2 | Returns key metadata |
| 17 | `bitbucket-app-password` | `https://api.bitbucket.org/2.0/user` | GET | Basic `{username}:{app-password}` | Medium | P2 | Requires username from context |
| 18 | `dockerhub-pat` | `https://hub.docker.com/v2/user/login` | POST | Token exchange | Medium | P2 | Need to exchange PAT for JWT via login endpoint |

**Total Tier 2: 18 detectors (17 new + 1 already implemented)**

### Tier 3 --- Hard (Complex auth flow, needs second credential, or high risk)

These detectors require complex authentication flows, secondary credentials that are typically not available in the finding context, or carry significant risk if verified incorrectly.

| # | Detector ID | Potential Approach | Complexity | Priority | Challenges |
|---|-------------|-------------------|------------|----------|------------|
| 1 | `azure-storage-key` | Azure Storage REST API with HMAC-SHA256 signed request | Hard | P2 | Requires storage account name + constructing HMAC-signed `Authorization` header per Azure REST API spec |
| 2 | `azure-entra-secret` | Microsoft Graph `https://graph.microsoft.com/v1.0/me` | Hard | P2 | Client secret requires OAuth2 client_credentials flow with tenant ID + client ID + secret to get access token first |
| 3 | `gcp-service-account` | Google OAuth2 token endpoint via JWT assertion | Hard | P2 | JSON key file contains private key; must construct signed JWT, exchange for access token, then call `https://www.googleapis.com/oauth2/v1/tokeninfo` |
| 4 | `snowflake-credentials` | Snowflake SQL REST API | Hard | P3 | Requires account identifier + username + password; connection string format varies significantly |
| 5 | `jwt` | Decode and check `exp` claim | Hard | P3 | Cannot verify signature without knowing the signing key; can only check expiry and structural validity |

**Total Tier 3: 5 detectors**

### Tier 4 --- Not Verifiable (No public API, format-only, or infrastructure-dependent)

These detectors identify secrets that cannot be verified through a public API call, either because the service has no verification endpoint, the secret requires infrastructure access, or the detection is format-based only.

| # | Detector ID | Reason Not Verifiable |
|---|-------------|----------------------|
| 1 | `private-key` | Private keys (RSA, SSH, DSA, EC, PGP) have no remote verification endpoint. Validity depends on the system they are deployed to. Could theoretically parse and validate structure, but not liveness. |
| 2 | `generic-api-key` | Catches generic patterns like `api_key=`, `apikey:`, etc. No way to determine which service the key belongs to, so no API to call. |
| 3 | `database-connection-string` | PostgreSQL, MySQL, MSSQL, MongoDB connection strings. Verification would require direct database connection, which is intrusive and may trigger security alerts. Not safe for automated verification. |
| 4 | `redis-connection-string` | Redis connection URIs (`redis://`). Verification requires direct network connection to the Redis instance, which is typically not internet-accessible. |
| 5 | `rabbitmq-connection-string` | AMQP connection URIs (`amqp://`). Same as Redis -- requires direct network connection to the broker. |
| 6 | `ftp-credentials` | FTP/SFTP URIs with embedded credentials. Verification requires direct connection to potentially internal FTP servers. |
| 7 | `ldap-credentials` | LDAP bind credentials (`ldap://`). Verification requires direct connection to LDAP directory server, typically internal. |
| 8 | `slack-webhook` | Webhook URLs (`https://hooks.slack.com/services/...`). Could POST a message, but that would be a **side effect** (sends actual message to a channel). Read-only verification is not possible. |
| 9 | `teams-webhook` | Microsoft Teams webhook URLs. Same as Slack webhook -- verification would send a message, causing a side effect. |
| 10 | `infura-api-key` | Infura project IDs/keys are embedded in Ethereum RPC URLs. Could make an `eth_blockNumber` call, but this uses the API quota and the key format has high false-positive overlap with generic hex strings. |

**Total Tier 4: 10 detectors**

### Summary

| Tier | Count | Description | Verification Coverage |
|------|-------|-------------|----------------------|
| Tier 1 (Easy) | 30 | Simple Bearer/API-key auth, single request | High confidence |
| Tier 2 (Medium) | 18 | Needs context extraction or multi-step auth | Medium confidence |
| Tier 3 (Hard) | 5 | Complex auth flows or second credential | Low confidence |
| Tier 4 (Not Verifiable) | 10 | No public API or side-effect-only | Not possible |
| **Total** | **63** | | |

**Maximum achievable verification coverage: 53/63 (84.1%)**

## 3. Implementation Roadmap

### Sprint 1 --- High-Value Easy Wins (P0, Tier 1)

**Goal:** Increase coverage from 4.8% to 17.5% (11/63)

| Verifier | Detector ID | Estimated Effort |
|----------|-------------|-----------------|
| OpenAI | `openai-api-key` | 0.5 day |
| Anthropic | `anthropic-api-key` | 0.5 day |
| GitLab | `gitlab-pat` | 0.5 day |
| SendGrid | `sendgrid-api-key` | 0.5 day |
| DigitalOcean | `digitalocean-token` | 0.5 day |
| Cloudflare | `cloudflare-api-token` | 0.5 day |
| Telegram | `telegram-bot-token` | 0.5 day |
| Discord | `discord-bot-token` | 0.5 day |

**Estimated total: 4 days**

### Sprint 2 --- Tier 1 Continued (P1)

**Goal:** Increase coverage to 34.9% (22/63)

| Verifier | Detector ID | Estimated Effort |
|----------|-------------|-----------------|
| New Relic | `newrelic-api-key` | 0.5 day |
| Heroku | `heroku-api-key` | 0.5 day |
| Notion | `notion-token` | 0.5 day |
| Sentry | `sentry-token` | 0.5 day |
| PagerDuty | `pagerduty-api-key` | 0.5 day |
| Vercel | `vercel-token` | 0.5 day |
| Linear | `linear-api-key` | 0.5 day |
| CircleCI | `circleci-token` | 0.5 day |
| NPM | `npm-token` | 0.5 day |
| Hugging Face | `huggingface-token` | 0.5 day |
| Airtable | `airtable-pat` | 0.5 day |

**Estimated total: 5.5 days**

### Sprint 3 --- Remaining Tier 1 + Key Tier 2 (P1-P2)

**Goal:** Increase coverage to 52.4% (33/63)

| Verifier | Detector ID | Estimated Effort |
|----------|-------------|-----------------|
| Snyk | `snyk-api-key` | 0.5 day |
| Figma | `figma-pat` | 0.5 day |
| Postmark | `postmark-server-token` | 0.5 day |
| Grafana | `grafana-api-key` | 0.5 day |
| Doppler | `doppler-token` | 0.5 day |
| SonarCloud | `sonarcloud-token` | 0.5 day |
| DeepSeek | `deepseek-api-key` | 0.5 day |
| LaunchDarkly | `launchdarkly-sdk-key` | 0.5 day |
| Stripe Live | `stripe-api-key-live` | 1 day |
| Stripe Test | `stripe-api-key-test` | 0.5 day |
| Twilio | `twilio-api-key` | 1 day |

**Estimated total: 6 days**

### Sprint 4 --- Tier 2 Medium-Priority

**Goal:** Increase coverage to 69.8% (44/63)

| Verifier | Detector ID | Estimated Effort |
|----------|-------------|-----------------|
| Mailgun | `mailgun-api-key` | 0.5 day |
| Shopify | `shopify-access-token` | 1 day |
| Okta | `okta-api-token` | 1 day |
| Databricks | `databricks-token` | 1 day |
| GitHub OAuth | `github-oauth-token` | 0.5 day |
| PyPI | `pypi-api-token` | 1 day |
| Auth0 | `auth0-management-token` | 1.5 days |
| Coinbase | `coinbase-api-key` | 1.5 days |
| Datadog | `datadog-api-key` | 1 day |
| Terraform | `terraform-cloud-token` | 0.5 day |
| Vault | `hashicorp-vault-token` | 1 day |

**Estimated total: 10 days**

### Sprint 5 --- Remaining Tier 2 + Tier 3

**Goal:** Increase coverage to 84.1% (53/63)

| Verifier | Detector ID | Estimated Effort |
|----------|-------------|-----------------|
| Supabase | `supabase-service-key` | 1 day |
| RubyGems | `rubygems-api-key` | 0.5 day |
| Bitbucket | `bitbucket-app-password` | 1 day |
| Docker Hub | `dockerhub-pat` | 1 day |
| Azure Storage | `azure-storage-key` | 2 days |
| Azure Entra | `azure-entra-secret` | 2 days |
| GCP | `gcp-service-account` | 2 days |
| Snowflake | `snowflake-credentials` | 1.5 days |
| JWT | `jwt` | 1 day |

**Estimated total: 12 days**

### Total Roadmap Summary

| Sprint | New Verifiers | Cumulative Coverage | Effort |
|--------|--------------|---------------------|--------|
| Sprint 1 | 8 | 11/63 (17.5%) | 4 days |
| Sprint 2 | 11 | 22/63 (34.9%) | 5.5 days |
| Sprint 3 | 11 | 33/63 (52.4%) | 6 days |
| Sprint 4 | 11 | 44/63 (69.8%) | 10 days |
| Sprint 5 | 9 | 53/63 (84.1%) | 12 days |
| **Total** | **50** | **53/63 (84.1%)** | **37.5 days** |

## 4. Security Considerations

### Rate Limiting

Every verifier MUST implement per-provider rate limiting to avoid triggering abuse detection or account lockouts.

| Provider Category | Recommended Rate Limit | Rationale |
|-------------------|----------------------|-----------|
| AI Providers (OpenAI, Anthropic, DeepSeek) | 5 req/min | API usage may incur costs to the key owner |
| Source Control (GitHub, GitLab, Bitbucket) | 10 req/min | GitHub allows 5000/hr authenticated, but be conservative |
| Communication (Slack, Discord, Telegram) | 5 req/min | Avoid triggering spam detection |
| Cloud Providers (AWS, GCP, Azure) | 5 req/min | STS/IAM calls have low limits |
| CI/CD (CircleCI, Vercel, Terraform) | 5 req/min | Typically lower rate limits |
| All Others | 5 req/min | Default conservative limit |

Implementation: Use `golang.org/x/time/rate` (already a dependency) with a per-verifier `rate.Limiter` instance.

### Credential Safety

- **NEVER** log, print, or persist raw secret values during verification. This is enforced by the `Verifier` interface contract.
- Redact secrets in all error messages. Use `slog` structured logging with only metadata fields.
- HTTP client must not follow redirects that could leak the `Authorization` header to third-party domains.
- Set a custom `User-Agent: leakwatch-verifier` on all requests for transparency.

### Timeout Handling

- All verifier HTTP requests MUST respect the `context.Context` deadline.
- Default per-request timeout: **10 seconds**.
- If the verification API is unreachable or times out, return `StatusVerifyError` (not `StatusVerifiedInactive`). A network failure does not mean the secret is invalid.
- Implement exponential backoff for transient failures (429, 503) with a maximum of 2 retries.

### Verification API Downtime

When a provider's API is unavailable:

1. Return `finding.StatusVerifyError` with a descriptive message.
2. The finding is reported with `unverified` status -- it is NOT suppressed.
3. Log the error at `slog.Warn` level for operational visibility.
4. Do **not** cache negative results from API errors. Only cache definitive `active` or `inactive` results.

### Network Security

- All verification requests MUST use HTTPS. HTTP endpoints MUST be rejected.
- TLS certificate validation MUST NOT be disabled.
- Consider implementing a configurable HTTP proxy for environments where direct internet access is not available.
- DNS resolution should use the system resolver; do not hardcode IP addresses.

### Minimal-Privilege Verification

- Always use the **least-privilege** API endpoint for verification. Prefer read-only endpoints that return minimal data.
- Never call endpoints that modify state (create, update, delete).
- For Stripe: use `GET /v1/charges?limit=1`, not `POST /v1/charges`.
- For webhook URLs (Slack, Teams): do **not** verify, as any call would post a message.

## 5. Implementation Guidelines

### Verifier Template

Each new verifier should follow this structure:

```go
package <provider>

import (
    "context"
    "fmt"
    "log/slog"
    "net/http"

    "github.com/cemililik/leakwatch/internal/detector"
    "github.com/cemililik/leakwatch/internal/verifier"
    "github.com/cemililik/leakwatch/pkg/finding"
)

const detectorID = "<detector-id>"

type Verifier struct {
    apiURL     string
    httpClient *http.Client
}

func init() {
    verifier.Register(&Verifier{})
}

func (v *Verifier) Type() string { return detectorID }

func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
    // 1. Extract and validate the secret from raw.Raw
    // 2. Build the HTTP request with proper auth header
    // 3. Execute with context-aware HTTP client
    // 4. Interpret response: 200 = active, 401/403 = inactive, other = error
    // 5. Return VerificationResult with metadata in ExtraData
}
```

### Testing Requirements

- Each verifier MUST have a corresponding `*_test.go` with table-driven tests.
- Use `httptest.NewServer` to mock provider APIs.
- Test cases must cover: active token, inactive/revoked token, network error, timeout, malformed response, empty input.
- Target: **95% code coverage** for all verifier packages (consistent with detector coverage requirement).

### Verifier Registration

New verifiers are registered at compile time. After creating the verifier package, add the blank import to `cmd/imports.go`:

```go
import (
    _ "github.com/cemililik/leakwatch/internal/verifier/<provider>"
)
```
