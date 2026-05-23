---
title: "Doğrulama Kapsamı"
description: "63 yerleşik dedektörün hangilerinin canlı doğrulandığı, yalnızca format doğrulandığı veya doğrulanamaz olduğu ve bunun önceliklendirme açısından ne anlama geldiği."
---

# Doğrulama Kapsamı

Leakwatch 63 yerleşik dedektör ve 54 doğrulayıcı ile gelir; bu, **%85,7** kapsama oranı sağlar (63 dedektör türünün 54'ünün bir tür doğrulaması mevcuttur). Bu sayfa, çıktınızda ne beklemeniz gerektiğini bilmeniz için her dedektörü doğrulama durumuna göre eşler.

## Canlı doğrulanan (49 dedektör türü)

Bu türler için Leakwatch, sağlayıcıya kontrollü, salt-okunur bir API çağrısı yapar ve `verified_active` ya da `verified_inactive` döndürür. Hiçbir veri oluşturulmaz veya değiştirilmez; çağrı, kimliği doğrulamak için gereken minimum uç noktayı kullanır.

| Dedektör türü | Sağlayıcı |
|--------------|----------|
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

## Yalnızca format doğrulaması (5 dedektör türü)

Bu doğrulayıcılar tamamen çevrimdışı çalışır. Hiçbir ağ isteği yapılmaz. Geçerli bir format kimlik bilgisinin aktif olduğunu kanıtlamadığından, beşi de format kontrolünün geçip geçmediğinden bağımsız olarak her zaman `unverified` döndürür.

| Dedektör ID | Doğrulanan özellik | Neden canlı kontrol yok |
|-------------|-------------------|------------------------|
| `gcp-service-account` | JSON yapısı (`type`, `project_id`, `private_key_id`, `client_email`) | Canlı kontrol, yan etkileri olan GCP OAuth2 token değişimi gerektirir |
| `rabbitmq-connection-string` | AMQP URL'nin başarıyla ayrıştırılması | Herkese açık kimlik doğrulamasız sağlık uç noktası yok |
| `snowflake-credentials` | Parola uzunluğu ve host alt dize kontrolü | Canlı kontrol bir JDBC/ODBC veritabanı bağlantısı gerektirir |
| `azure-storage-key` | Format kontrolü | Hesap başına HMAC imzalama gerektirir; genel kimlik uç noktası yok |
| `azure-entra-secret` | Format kontrolü | İstemci kimlik bilgisi akışı oturum oluşturur |

## Doğrulanamaz (9 dedektör türü)

Bu dedektör türlerinin hiç doğrulayıcısı yoktur. Bunlardan gelen bulgular her zaman `unverified` olur. Bu durum önemsiz oldukları anlamına **gelmez** — tam olarak tespit edilip raporlanırlar — ancak herkese açık bir doğrulama API'si bulunmamakta ya da herhangi bir doğrulama girişimi yan etkiye yol açmaktadır.

| Dedektör ID | Neden |
|-------------|-------|
| `jwt` | JWT herhangi bir tarafça yayınlanabilir; evrensel bir doğrulama uç noktası yoktur |
| `private-key` | Çağrılacak sağlayıcı yok; aktif kullanım uzaktan tespit edilemez |
| `generic-api-key` | Tanım gereği bilinmeyen sağlayıcı |
| `database-connection-string` | Bağlanmak hedef veritabanında oturum oluşturur |
| `redis-connection-string` | Bağlanmak Redis örneğinde canlı bağlantı açar |
| `ftp-credentials` | Güvenli, salt-okunur FTP yoklama yöntemi yok |
| `ldap-credentials` | LDAP bind kimliği doğrulanmış bir oturum oluşturur |
| `slack-webhook` | Webhook'un aktif olduğunu doğrulamak mesaj göndermeyi gerektirir |
| `hashicorp-vault-token` | Vault token doğrulaması, Vault uç noktasının bilinmesini gerektirir |

:::note
"Doğrulanamaz" "bulunamaz" anlamına gelmez. Bu 9 türün tamamı yine de tespit edilir ve çıktınızda görünür. Kimlik bilgisinin canlı olup olmadığını ve döndürülmesi gerekip gerekmediğini belirlemek için manuel inceleme gerektirir.
:::

## Kapsam özeti

| Kategori | Sayı |
|----------|------|
| Canlı doğrulanan | 49 |
| Yalnızca format doğrulaması | 5 |
| Doğrulanamaz | 9 |
| **Toplam dedektör** | **63** |
| **Doğrulayıcı (herhangi bir kapsam)** | **54 (%85,7)** |

## Ayrıca bakın

- [Doğrulama Nasıl Çalışır](#/verification/how-verification-works) — iki doğrulama modu, durumlar ve doğrulama motoru.
- [Dedektör Kataloğu](#/detectors/detector-catalog) — yerleşik dedektörlerin tam listesi ve şiddet seviyeleri.
