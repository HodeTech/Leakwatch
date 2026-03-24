package remediation

import "github.com/cemililik/leakwatch/pkg/finding"

func init() {
	Register("aws-access-key-id", finding.Remediation{
		Title: "Rotate AWS Access Key",
		Steps: []string{
			"Sign in to the AWS IAM console and locate the compromised access key.",
			"Create a new access key for the same IAM user.",
			"Update all services, applications, and CI/CD pipelines that use the old key.",
			"Deactivate the old access key and monitor CloudTrail for any usage.",
			"Delete the old access key after confirming no remaining usage.",
		},
		DocURL:     "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#rotating_access_keys_console",
		ConsoleURL: "https://console.aws.amazon.com/iam/home#/security_credentials",
		Urgency:    "immediate",
		Checklist: []string{
			"Review CloudTrail logs for unauthorized usage of the compromised key.",
			"Check for any resources created or modified by the compromised key.",
			"Notify the security team about the exposure.",
			"Scan the codebase for other occurrences of the same key.",
		},
	})

	Register("github-token", finding.Remediation{
		Title: "Revoke GitHub Token",
		Steps: []string{
			"Go to GitHub Settings > Developer settings > Personal access tokens.",
			"Revoke the compromised token immediately.",
			"Create a new token with the minimum required scopes.",
			"Update all integrations and CI/CD pipelines with the new token.",
		},
		DocURL:     "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
		ConsoleURL: "https://github.com/settings/tokens",
		Urgency:    "immediate",
		Checklist: []string{
			"Review the GitHub audit log for unauthorized actions performed with the token.",
			"Check repository and organization settings for unexpected changes.",
			"Notify the security team about the exposure.",
			"Scan for other repositories that may contain the same token.",
		},
	})

	Register("slack-token", finding.Remediation{
		Title: "Revoke Slack Token",
		Steps: []string{
			"Go to Slack App Management at api.slack.com/apps.",
			"Select the affected application and navigate to OAuth & Permissions.",
			"Revoke the compromised bot or user token.",
			"Reinstall the app to generate a new token.",
			"Update all services using the old token.",
		},
		DocURL:     "https://api.slack.com/authentication/rotation",
		ConsoleURL: "https://api.slack.com/apps",
		Urgency:    "high",
		Checklist: []string{
			"Review Slack access logs for unauthorized message reads or posts.",
			"Check for any data exfiltration from private channels.",
			"Notify the workspace administrators about the exposure.",
			"Scan for other locations where the token may be stored.",
		},
	})

	Register("slack-webhook", finding.Remediation{
		Title: "Regenerate Slack Webhook URL",
		Steps: []string{
			"Go to Slack App Management at api.slack.com/apps.",
			"Select the affected application and navigate to Incoming Webhooks.",
			"Remove the compromised webhook URL.",
			"Create a new webhook URL for the target channel.",
			"Update all services that post via the old webhook URL.",
		},
		DocURL:     "https://api.slack.com/messaging/webhooks",
		ConsoleURL: "https://api.slack.com/apps",
		Urgency:    "high",
		Checklist: []string{
			"Review the target channel for unexpected or malicious messages.",
			"Notify the channel members about potential spam from the compromised webhook.",
			"Scan for other locations where the webhook URL may be stored.",
		},
	})

	Register("stripe-api-key-live", finding.Remediation{
		Title: "Roll Stripe Live API Key",
		Steps: []string{
			"Sign in to the Stripe Dashboard and go to Developers > API keys.",
			"Roll the compromised live secret key to generate a new one.",
			"Update all backend services and payment integrations with the new key.",
			"Monitor the Stripe Dashboard for any unauthorized transactions.",
		},
		DocURL:     "https://docs.stripe.com/keys#rolling-keys",
		ConsoleURL: "https://dashboard.stripe.com/apikeys",
		Urgency:    "immediate",
		Checklist: []string{
			"Review recent Stripe events and logs for unauthorized charges or refunds.",
			"Check for any new connected accounts or transfers.",
			"Notify the security and finance teams about the exposure.",
			"Scan the codebase for other occurrences of the same key.",
		},
	})

	Register("stripe-api-key-test", finding.Remediation{
		Title: "Roll Stripe Test API Key",
		Steps: []string{
			"Sign in to the Stripe Dashboard and go to Developers > API keys.",
			"Roll the compromised test secret key to generate a new one.",
			"Update development and staging environments with the new key.",
		},
		DocURL:     "https://docs.stripe.com/keys#rolling-keys",
		ConsoleURL: "https://dashboard.stripe.com/test/apikeys",
		Urgency:    "medium",
		Checklist: []string{
			"Verify no live data was accessible through the test key.",
			"Update CI/CD pipelines that reference the old test key.",
			"Scan for other locations where the test key may be stored.",
		},
	})

	Register("jwt", finding.Remediation{
		Title: "Rotate JWT Signing Key",
		Steps: []string{
			"Generate a new signing key (symmetric secret or asymmetric key pair).",
			"Deploy the new key to all services that issue or validate tokens.",
			"Invalidate all existing tokens by revoking sessions or using a deny list.",
			"Monitor authentication logs for tokens signed with the old key.",
		},
		DocURL:     "https://datatracker.ietf.org/doc/html/rfc7519",
		ConsoleURL: "",
		Urgency:    "high",
		Checklist: []string{
			"Identify all services and clients that consume the JWT.",
			"Check authentication logs for unauthorized access using the leaked token.",
			"Notify the security team about the exposure.",
			"Verify that token expiration and refresh mechanisms are properly configured.",
		},
	})

	Register("database-connection-string", finding.Remediation{
		Title: "Rotate Database Credentials",
		Steps: []string{
			"Change the database user password immediately via your database management tool.",
			"Update all application connection configurations with the new password.",
			"Restart services that use pooled connections to pick up the new credentials.",
			"Review database access logs for unauthorized connections.",
			"Consider restricting the database user's permissions to the minimum required.",
		},
		DocURL:     "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
		ConsoleURL: "",
		Urgency:    "immediate",
		Checklist: []string{
			"Check database audit logs for unauthorized queries or data exports.",
			"Verify that network-level access controls (firewall, security groups) are in place.",
			"Notify the security team and database administrators about the exposure.",
			"Scan for other locations where the connection string may be stored.",
		},
	})

	Register("private-key", finding.Remediation{
		Title: "Regenerate Private Key",
		Steps: []string{
			"Generate a new key pair using a strong algorithm (e.g., Ed25519 or RSA 4096).",
			"Revoke any certificates signed by the compromised key.",
			"Remove the compromised public key from all authorized_keys and trust stores.",
			"Deploy the new public key to all systems and services.",
			"Securely delete the compromised private key from all storage locations.",
		},
		DocURL:     "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html",
		ConsoleURL: "",
		Urgency:    "immediate",
		Checklist: []string{
			"Review SSH and TLS access logs for unauthorized connections using the compromised key.",
			"Check certificate transparency logs if the key was used for TLS.",
			"Notify the security team about the exposure.",
			"Audit all systems where the key had access.",
		},
	})

	Register("generic-api-key", finding.Remediation{
		Title: "Rotate API Key",
		Steps: []string{
			"Identify the service provider associated with the API key.",
			"Sign in to the provider's dashboard and locate the API key management section.",
			"Revoke or regenerate the compromised key.",
			"Update all services and integrations with the new key.",
		},
		DocURL:     "",
		ConsoleURL: "",
		Urgency:    "high",
		Checklist: []string{
			"Review the provider's usage and audit logs for unauthorized API calls.",
			"Notify the security team about the exposure.",
			"Scan the codebase for other occurrences of the same key.",
			"Consider using a secrets manager to avoid embedding keys in source code.",
		},
	})

	Register("openai-api-key", finding.Remediation{
		Title: "Rotate OpenAI API Key",
		Steps: []string{
			"Go to platform.openai.com/api-keys.",
			"Create a new API key.",
			"Update all integrations with the new key.",
			"Delete the old API key.",
			"Check usage logs for unauthorized activity.",
		},
		DocURL:     "https://platform.openai.com/docs/guides/safety-best-practices",
		ConsoleURL: "https://platform.openai.com/api-keys",
		Urgency:    "immediate",
		Checklist: []string{
			"Check billing for unauthorized usage.",
			"Review API logs for suspicious activity.",
			"Notify the team about the exposure.",
		},
	})

	Register("anthropic-api-key", finding.Remediation{
		Title: "Rotate Anthropic API Key",
		Steps: []string{
			"Go to console.anthropic.com/settings/keys.",
			"Create a new API key.",
			"Update all integrations with the new key.",
			"Delete the old API key.",
		},
		DocURL:     "https://docs.anthropic.com/en/docs/initial-setup",
		ConsoleURL: "https://console.anthropic.com/settings/keys",
		Urgency:    "immediate",
		Checklist: []string{
			"Check usage logs for unauthorized activity.",
			"Review billing for unexpected charges.",
			"Notify the team about the exposure.",
		},
	})

	Register("gitlab-pat", finding.Remediation{
		Title: "Revoke GitLab Personal Access Token",
		Steps: []string{
			"Go to GitLab Settings > Access Tokens.",
			"Revoke the compromised token.",
			"Create a new token with minimal scopes.",
			"Update CI/CD pipelines with the new token.",
		},
		DocURL:     "https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html",
		ConsoleURL: "https://gitlab.com/-/user_settings/personal_access_tokens",
		Urgency:    "immediate",
		Checklist: []string{
			"Check repository activity for unauthorized changes.",
			"Review CI/CD jobs for suspicious runs.",
			"Audit access logs for unauthorized access.",
		},
	})

	Register("sendgrid-api-key", finding.Remediation{
		Title: "Rotate SendGrid API Key",
		Steps: []string{
			"Go to SendGrid Settings > API Keys.",
			"Create a new key with minimal permissions.",
			"Update email service configuration with the new key.",
			"Delete the old API key.",
		},
		DocURL:     "https://docs.sendgrid.com/ui/account-and-settings/api-keys",
		ConsoleURL: "https://app.sendgrid.com/settings/api_keys",
		Urgency:    "immediate",
		Checklist: []string{
			"Check sent email logs for abuse.",
			"Monitor bounce and spam rates for anomalies.",
			"Notify the team about the exposure.",
		},
	})

	Register("npm-token", finding.Remediation{
		Title: "Revoke NPM Access Token",
		Steps: []string{
			"Run `npm token revoke <token>` or go to npmjs.com > Access Tokens.",
			"Create a new token.",
			"Update CI/CD pipelines with the new token.",
			"Check for unauthorized package publishes.",
		},
		DocURL:     "https://docs.npmjs.com/about-access-tokens",
		ConsoleURL: "https://www.npmjs.com/settings/~/tokens",
		Urgency:    "immediate",
		Checklist: []string{
			"Check for unauthorized package publishes.",
			"Review download stats for anomalies.",
			"Run npm audit on affected packages.",
		},
	})
}
