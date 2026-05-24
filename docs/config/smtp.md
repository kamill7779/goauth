# SMTP Configuration

GoAuth sends verification, reset, and invite emails through the configured mailer provider.

## Providers

```env
MAILER_PROVIDER=console
```

Supported values:

| Provider | Use |
| --- | --- |
| `console` | Local development. Writes mail bodies to temporary mailbox files and logs the path. |
| `smtp` | Real delivery through SMTP. Required for production. |
| `noop` | Drops messages. Useful only for special tests. |

Production should use `MAILER_PROVIDER=smtp` and verify real delivery before public traffic.

## SMTP Variables

```env
MAILER_PROVIDER=smtp
SMTP_HOST=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM=
SMTP_SSL=false
SMTP_AUTH_LOGIN=false
```

| Variable | Meaning |
| --- | --- |
| `SMTP_HOST` | SMTP server hostname. |
| `SMTP_PORT` | SMTP server port. |
| `SMTP_USERNAME` | Login account. |
| `SMTP_PASSWORD` | SMTP password or provider-specific authorization code. |
| `SMTP_FROM` | Header and envelope sender, for example `GoAuth <no-reply@example.com>`. |
| `SMTP_SSL` | `true` for implicit TLS, usually port `465`. |
| `SMTP_AUTH_LOGIN` | `true` for providers that require AUTH LOGIN instead of AUTH PLAIN. |

## 126 Mail Verified Recipe

126 Mail works through implicit TLS on port `465`.

```env
MAILER_PROVIDER=smtp
SMTP_HOST=smtp.126.com
SMTP_PORT=465
SMTP_USERNAME=<your-user>@126.com
SMTP_PASSWORD=<126 smtp authorization code>
SMTP_FROM=GoAuth <your-user@126.com>
SMTP_SSL=true
SMTP_AUTH_LOGIN=true
```

Notes:

- Use a 126 SMTP authorization code, not the normal web login password.
- Keep `SMTP_FROM` aligned with the authenticated mailbox unless your provider explicitly allows aliases.
- This path is compatible with the current GoAuth SMTP sender because it uses implicit TLS.

## Outlook And Microsoft 365

Outlook.com and Microsoft 365 typically use port `587` with STARTTLS:

```env
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_SSL=false
SMTP_AUTH_LOGIN=true
```

Current limitation: GoAuth's SMTP sender supports implicit TLS (`SMTP_SSL=true`) and plain SMTP auth, but does not yet upgrade a port `587` connection with STARTTLS. Add STARTTLS support before recommending Microsoft 365 as a production SMTP provider.

Microsoft 365 also requires SMTP AUTH to be enabled for the mailbox or tenant, and may require modern authentication depending on tenant policy.

## Local Console Mail

For local development:

```env
MAILER_PROVIDER=console
```

Watch logs:

```powershell
cd services/identity-service
docker compose logs -f identity-service
```

Find `mailbox_path`, then open that file to read the verification code.

## Troubleshooting

| Error | What to check |
| --- | --- |
| `smtp host is required` | `MAILER_PROVIDER=smtp` but `SMTP_HOST` is empty. |
| `smtp from is required` | Set `SMTP_FROM`. |
| Authentication failure | Use provider-specific SMTP authorization code, not the normal password. |
| Sender rejected | Set `SMTP_FROM` to the authenticated mailbox or an allowed alias. |
| Timeout or connection refused | Check outbound firewall, host, port, and provider SMTP access switch. |
| Works on 465 but not 587 | 587 usually needs STARTTLS; current sender needs STARTTLS support first. |
| Mail accepted but not received | Check spam folder, provider rate limits, SPF/DKIM/DMARC, and mailbox sending restrictions. |

## Production Checklist

- Use `MAILER_PROVIDER=smtp`.
- Verify a real registration email and password reset email.
- Store `SMTP_PASSWORD` as a secret, not in committed files.
- Use a stable sender domain with SPF/DKIM/DMARC configured.
- Monitor SMTP failures in service logs.
