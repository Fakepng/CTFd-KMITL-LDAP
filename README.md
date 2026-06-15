# CTFd-LDAP Plugin

A clean, zero-dependency-bloat LDAP / Active Directory authentication plugin for [CTFd](https://github.com/CTFd/CTFd).

---

## Features

| Feature                  | Details                                                              |
| ------------------------ | -------------------------------------------------------------------- |
| **Two auth modes**       | `search_bind` (recommended) or `direct_bind`                         |
| **Group restriction**    | Restrict login to members of a specific LDAP group                   |
| **Auto-provisioning**    | Creates CTFd accounts on first successful LDAP login                 |
| **Local admin fallback** | CTFd admins can still log in with their local password               |
| **Admin test panel**     | `/admin/plugins/ldap` — test connectivity and user lookup in-browser |
| **TLS / SSL**            | Full support via `ldap3`                                             |
| **Env-var driven**       | Every setting can be overridden with an environment variable         |

---

## Installation

```bash
# 1. Copy plugin into CTFd's plugins directory
cp -r CTFd-LDAP-Plugin  /path/to/CTFd/CTFd/plugins/CTFd-LDAP

# 2. Install the dependency
pip install ldap3

# 3. Configure (see below), then restart CTFd
```

For Docker, add to your `Dockerfile` or `docker-compose.yml`:

```dockerfile
RUN pip install ldap3
```

---

## Configuration

You can configure the plugin in **two ways** (environment variables take priority):

### A) Environment variables (recommended for production)

```bash
LDAP_SERVER_HOST=ldap.corp.example.com
LDAP_SERVER_PORT=389
LDAP_USE_SSL=false
LDAP_USE_TLS=false

LDAP_BIND_DN=cn=svc-ctfd,ou=service,dc=corp,dc=example,dc=com
LDAP_BIND_PASSWORD=SuperSecretPassword

LDAP_BASE_DN=dc=corp,dc=example,dc=com
LDAP_USER_SEARCH_DN=ou=users,dc=corp,dc=example,dc=com
LDAP_USER_FILTER=(uid={username})
LDAP_USERNAME_ATTR=uid
LDAP_DISPLAYNAME_ATTR=cn
LDAP_EMAIL_ATTR=mail

LDAP_AUTH_MODE=search_bind

# Optional: restrict to group members
LDAP_REQUIRED_GROUP_DN=cn=ctf-players,ou=groups,dc=corp,dc=example,dc=com
LDAP_GROUP_MEMBER_ATTR=member
LDAP_GROUP_MEMBER_IS_DN=true

LDAP_AUTO_PROVISION=true
LDAP_ALLOW_LOCAL_ADMIN=true
```

### B) Edit `__init__.py` directly

Find the `LDAP_CONFIG` block near the top and set your values there:

```python
LDAP_CONFIG = {
    "SERVER_HOST": "ldap.corp.example.com",
    "SERVER_PORT": 389,
    ...
}
```

---

## Auth modes

### `search_bind` (default, recommended)

1. Plugin connects with a **service account** (read-only LDAP user).
2. Searches for the login DN matching `USER_FILTER`.
3. Verifies group membership (if configured).
4. Binds as the **user** with their password to verify credentials.

Best for: standard corporate LDAP / Active Directory deployments.

```
LDAP_AUTH_MODE=search_bind
LDAP_BIND_DN=cn=readonly,dc=example,dc=com
LDAP_BIND_PASSWORD=secret
```

### `direct_bind`

1. Constructs the user's DN from a template.
2. Binds directly as the user — no service account needed.

Best for: simple OpenLDAP setups where DNs follow a predictable pattern.

```
LDAP_AUTH_MODE=direct_bind
LDAP_DIRECT_BIND_TEMPLATE=uid={username},ou=users,dc=example,dc=com
```

---

## Active Directory example

```bash
LDAP_SERVER_HOST=ad.corp.example.com
LDAP_SERVER_PORT=389
LDAP_BIND_DN=CORP\svc-ctfd
LDAP_BIND_PASSWORD=Password123!
LDAP_BASE_DN=DC=corp,DC=example,DC=com
LDAP_USER_SEARCH_DN=CN=Users,DC=corp,DC=example,DC=com
LDAP_USER_FILTER=(sAMAccountName={username})
LDAP_USERNAME_ATTR=sAMAccountName
LDAP_DISPLAYNAME_ATTR=displayName
LDAP_EMAIL_ATTR=mail
LDAP_AUTH_MODE=search_bind
```

---

## Admin test panel

After installing, visit `/admin/plugins/ldap` as a CTFd admin to:

- View the current configuration (passwords masked)
- Test server connectivity and service-account bind
- Test a specific user's credentials and see their LDAP attributes

---

## How auto-provisioning works

On the first successful LDAP login for a username:

1. Plugin checks for an existing CTFd user with that name or email.
2. If none found and `LDAP_AUTO_PROVISION=true`, a new CTFd user is created with:
   - `name` = LDAP username
   - `email` = value of `LDAP_EMAIL_ATTR` (falls back to `username@ldap.local`)
   - `password` = `__ldap__` (never usable for local login)
   - `verified = True`
3. On subsequent logins, the existing CTFd account is reused.

Set `LDAP_AUTO_PROVISION=false` if you want to pre-create CTFd accounts manually.

---

## Local admin fallback

If `LDAP_ALLOW_LOCAL_ADMIN=true` (default), any CTFd user with `is_admin=True` can log in with their local CTFd password. This ensures you always have a recovery path if LDAP is unreachable.

---

## Security notes

- Service account should be **read-only** in your directory.
- Use `LDAP_USE_SSL=true` (port 636) or `LDAP_USE_TLS=true` (STARTTLS on port 389) in production.
- The plugin sets `password = "__ldap__"` for auto-provisioned users, which is an impossible-to-match bcrypt hash — those accounts cannot be used to log in locally.

---

## Troubleshooting

| Symptom                                      | Check                                                         |
| -------------------------------------------- | ------------------------------------------------------------- |
| `Could not connect to authentication server` | Firewall, wrong host/port, LDAP server down                   |
| `User not found in directory`                | `USER_SEARCH_DN`, `USER_FILTER`, and `USERNAME_ATTR` settings |
| `Invalid credentials`                        | Wrong password, or account locked in directory                |
| `Access denied: not a member`                | `REQUIRED_GROUP_DN` and `GROUP_MEMBER_ATTR` settings          |
| Import error on startup                      | `pip install ldap3` not run, or wrong Python env in Docker    |

Check CTFd logs for detailed `LDAP:` prefixed messages.

---

## License

MIT
