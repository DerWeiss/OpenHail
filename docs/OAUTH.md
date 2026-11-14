# OAuth2 / XOAUTH2

Gmail and Microsoft 365 no longer accept password authentication for IMAP or
SMTP. OpenHail has supported password auth since 0.1.0; this document covers
the OAuth2 path, which is the only one that works against those two providers.

## Why XOAUTH2 and not "app passwords"

Google removed app passwords for accounts without 2-Step Verification, and
Microsoft retired basic auth for Exchange Online entirely. An app password is a
long-lived bearer credential sitting in a keyring. XOAUTH2 hands the server a
short-lived signed token instead, scoped to specific capabilities, revocable
from the provider's own console without touching this machine. That is simply a
better credential, not just a supported one.

## What OpenHail implements

| Piece | Status | Notes |
|---|---|---|
| IMAP `AUTHENTICATE XOAUTH2` | done | `ImapClient.authenticate_xoauth2` |
| SMTP `AUTH XOAUTH2` | done | `SmtpSender.send_xoauth2` |
| Device code flow (headless) | done | `openhail oauth login` — no browser redirect needed |
| Authorization code + PKCE | done | `oauth.authorization_url` / `exchange_code` |
| Refresh-token rotation | done | rotates silently and persists the new token |
| Token storage | done | OS keyring only, namespaced `openhail:<account>:oauth` |
| Google Workspace domain delegation | not implemented | needs RS256 service-account JWT signing |

## Registering a client

Both providers require you to create your own OAuth client. OpenHail does not
ship one, and should not: a shared client ID in a public repo is a leak of a
rate-limit quota and an attribution problem.

### Google

1. <https://console.cloud.google.com/apis/credentials>
2. Create Credentials → OAuth client ID → **Desktop app**
3. Enable the Gmail API for the project
4. Copy the client ID

Scope requested is `https://mail.google.com/`, which is full IMAP+SMTP access.
This is a **restricted scope** — while your client is in "Testing" mode it works
only for accounts you add as test users (max 100). Publishing it to production
requires Google's verification review. For personal use, stay in Testing mode;
refresh tokens from Testing clients expire every 7 days, which is the tradeoff.

### Microsoft

1. <https://entra.microsoft.com> → App registrations → New registration
2. Supported account types: *Accounts in any organizational directory and
   personal Microsoft accounts*
3. Authentication → **Allow public client flows: Yes** (required for device code)
4. API permissions → Microsoft Graph → Delegated → add
   `IMAP.AccessAsUser.All` and `SMTP.Send`, then Grant admin consent

Microsoft requires the app to have IMAP/SMTP enabled on the tenant. Many
corporate tenants disable this deliberately; if the flow succeeds but IMAP
returns an error, that is why.

## Usage

```bash
# 1. Add the account. Hosts come from the provider registry.
openhail account add-oauth --name gmail --provider google --user you@gmail.com

# 2. Sign in. Prints a URL and a code; visit the URL on any device.
export OPENHAIL_OAUTH_CLIENT_ID="....apps.googleusercontent.com"
openhail oauth login --account gmail --provider google \
    --client-id "$OPENHAIL_OAUTH_CLIENT_ID"

# 3. Sync and read as usual. Auth is chosen per-account.
openhail sync --account gmail
openhail list --account gmail
```

Check token state without touching the network:

```bash
openhail oauth status --account gmail
```

Everything after step 2 is identical to password accounts. `mail.sync` and
`mail.send` inspect `auth_kind` and pick the right SASL mechanism.

## Token lifetime

Access tokens last about an hour. `get_valid_token` refreshes automatically
when a token is within 120 seconds of expiry, and persists the rotated refresh
token. You should never need to call `oauth refresh` manually; it exists for
debugging.

If the provider revokes the grant (password change, admin revoke, 7-day Testing
expiry), the refresh returns `invalid_grant`. OpenHail surfaces that as an error
rather than silently retrying, because retrying a revoked grant can lock the
client out.

## Threat model

**What this protects against**

- A stolen `mail.db`: no credentials in it at all, only message bodies.
- A stolen token: bounded to ~1 hour, and revocable provider-side.
- Credential theft via `ps` or shell history: no password or token ever appears
  in argv.
- Refresh-token loss during rotation: the old token is retained when the server
  omits a new one, so rotating does not log the user out.

**What it does not protect against**

- **Root on the box.** The keyring is only as strong as the OS account. An
  attacker running as you can read the token. This is true of every mail client.
- **A malicious consent screen.** If you are tricked into authorising the wrong
  app, OpenHail is not involved. Read the app name on the consent page.
- **Provider-side compromise.** Out of scope.

## Implementation notes for reviewers

- **Zero third-party dependencies.** The OAuth2 flows here are HTTP form posts
  and base64. PKCE needs only `hashlib`. No `requests`, no `authlib`.
- **Form encoding, not URL interpolation.** `_post_form` uses
  `urllib.parse.urlencode`, so a client secret containing `&` cannot smuggle an
  extra parameter. There is a test for exactly this.
- **The `\x01` separator in the SASL string is validated.** A token containing
  `\x01` would let a caller inject an extra `auth=` field; `xoauth2_string`
  rejects control characters.
- **Tokens live under `openhail:<account>:oauth`**, and account names are
  validated to exclude `:`, so one account cannot read another's token.
