---
title: "Verification Coverage"
description: "Which of the 63 built-in detectors are live-verified, format-validated only, or not verifiable — and what that means for triage."
---

# Verification Coverage

Leakwatch ships 63 built-in detectors and 54 verifiers, giving a coverage rate of **85.7%** (54 of 63 detector types have some form of verification). This page maps every detector to its verification status so you know what to expect in your output.

## Live-verified (49 detector types)

For these types, Leakwatch makes a controlled, read-only API call to the provider and returns `verified_active` or `verified_inactive`. No data is created or modified; the call uses the minimum endpoint needed to confirm identity.

| Detector type | Provider |
|--------------|---------|
| `aws-access-key-id` | AWS STS (`GetCallerIdentity`) |
| `github-token` | GitHub REST API |
| `github-oauth-token` | GitHub REST API |
| `gitlab-pat` | GitLab REST API |
| `slack-token` | Slack Web API |
| `openai-api-key` | OpenAI API |
| `anthropic-api-key` | Anthropic API |
| `deepseek-api-key` | DeepSeek API |
| `huggingface-token` | Hugging Face API |
| `sendgrid-api-key` | SendGrid Web API |
| `mailgun-api-key` | Mailgun API |
| `postmark-server-token` | Postmark API |
| `stripe-api-key-live` | Stripe API |
| `stripe-api-key-test` | Stripe API |
| `digitalocean-token` | DigitalOcean API |
| `cloudflare-api-token` | Cloudflare API |
| `heroku-api-key` | Heroku Platform API |
| `vercel-token` | Vercel REST API |
| `npm-token` | npm Registry API |
| `pypi-api-token` | PyPI API |
| `rubygems-api-key` | RubyGems API |
| `dockerhub-pat` | Docker Hub API |
| `circleci-token` | CircleCI API |
| `terraform-cloud-token` | Terraform Cloud API |
| `discord-bot-token` | Discord API |
| `telegram-bot-token` | Telegram Bot API |
| `sentry-token` | Sentry API |
| `pagerduty-api-key` | PagerDuty API |
| `newrelic-api-key` | New Relic API |
| `grafana-api-key` | Grafana API |
| `datadog-api-key` | Datadog API |
| `snyk-api-key` | Snyk API |
| `twilio-api-key` | Twilio API |
| `doppler-token` | Doppler API |
| `launchdarkly-sdk-key` | LaunchDarkly API |
| `sonarcloud-token` | SonarCloud API |
| `shopify-access-token` | Shopify Admin API |
| `notion-token` | Notion API |
| `linear-api-key` | Linear API |
| `figma-pat` | Figma REST API |
| `airtable-pat` | Airtable API |
| `okta-api-token` | Okta API |
| `auth0-management-token` | Auth0 Management API |
| `databricks-token` | Databricks REST API |
| `bitbucket-app-password` | Bitbucket REST API |
| `coinbase-api-key` | Coinbase API |
| `supabase-service-key` | Supabase API |
| `infura-api-key` | Infura API |
| `teams-webhook` | Microsoft Teams |

## Format-validated only (5 detector types)

These verifiers run entirely offline. No network request is made. Because a valid format does not prove a credential is active, all five always return `unverified` regardless of whether the format check passes or fails.

| Detector ID | What is validated | Why no live check |
|-------------|------------------|------------------|
| `gcp-service-account` | JSON structure (`type`, `project_id`, `private_key_id`, `client_email`) | Live check requires a GCP OAuth2 token exchange, which has side effects |
| `rabbitmq-connection-string` | AMQP URL parsed successfully | No public unauthenticated health endpoint |
| `snowflake-credentials` | Password length and host substring check | Live check requires a JDBC/ODBC database connection |
| `azure-storage-key` | Format check | Requires per-account HMAC signing; no generic identity endpoint |
| `azure-entra-secret` | Format check | Client credential flow would create sessions |

## Not verifiable (9 detector types)

These detector types have no verifier at all. Findings from them are always `unverified`. This is **not** because they are unimportant — they are detected and reported in full — but because no public verification API exists, or because any verification attempt would have side effects.

| Detector ID | Reason |
|-------------|--------|
| `jwt` | A JWT can be issued by any party; there is no universal validation endpoint |
| `private-key` | No provider to call; active use cannot be detected remotely |
| `generic-api-key` | Unknown provider by definition |
| `database-connection-string` | Connecting would create sessions on the target database |
| `redis-connection-string` | Connecting would open a live connection to the Redis instance |
| `ftp-credentials` | No safe read-only FTP probe |
| `ldap-credentials` | LDAP bind would create an authenticated session |
| `slack-webhook` | Confirming a webhook is active requires sending a message |
| `hashicorp-vault-token` | Vault token validation requires knowing the Vault endpoint |

:::note
"Not verifiable" does not mean "not found". All 9 of these types are still detected and appear in your output. They require manual triage to determine whether the credential is live and whether it needs rotation.
:::

## Coverage summary

| Category | Count |
|----------|-------|
| Live-verified | 49 |
| Format-validated only | 5 |
| Not verifiable | 9 |
| **Total detectors** | **63** |
| **Verifiers (any coverage)** | **54 (85.7%)** |

## See also

- [How Verification Works](#/verification/how-verification-works) — the two verification modes, statuses, and the verification engine.
- [Detector Catalog](#/detectors/detector-catalog) — the full list of built-in detectors with severities.
