# CTFd KMITL LDAP Plugin

A small CTFd plugin for KMITL student authentication via the university LDAP server.

This plugin uses direct bind to authenticate students using `uid={student_id},ou=Student,ou={faculty},ou=bkk,dc=kmitl,dc=ac,dc=th`.

---

## Features

- KMITL student login with `69010001` or `69010001@kmitl.ac.th`
- Direct LDAP bind using student DN template
- Auto-provision CTFd accounts on first successful login
- Local admin fallback for password recovery
- Optional curriculum lookup from KMITL Developer API
- TLS / SSL support via `ldap3`
- Admin test panel at `/admin/plugins/ldap`

---

## Installation

1. Copy this plugin folder into `CTFd/plugins/CTFd-LDAP`
2. Install the dependency:

```bash
pip install ldap3
```

3. Restart CTFd.

For Docker, add:

```dockerfile
RUN pip install ldap3
```

---

## Configuration

The plugin reads settings from environment variables. Defaults are declared in the `LDAP_CONFIG` block at the top of `__init__.py`.

### Supported environment variables

```bash
LDAP_SERVER_HOST=10.252.92.100
LDAP_SERVER_PORT=389
LDAP_USE_SSL=false
LDAP_USE_TLS=false
LDAP_TIMEOUT=5
LDAP_BASE_DN=dc=kmitl,dc=ac,dc=th
LDAP_ALLOW_LOCAL_ADMIN=true
LDAP_AUTO_PROVISION=true
KMITL_DEVELOPER_KEY=
KMITL_DEVELOPER_API=https://api.kmitl.ac.th/student-catalog/v1
```

If you want to customize the plugin without environment variables, edit `LDAP_CONFIG` directly in `__init__.py`.

### Notes

- `LDAP_USE_SSL=true` enables LDAPS on the configured port.
- `LDAP_USE_TLS=true` enables STARTTLS before binding.
- `LDAP_ALLOW_LOCAL_ADMIN=true` allows existing local CTFd admins to log in with their local password.
- `LDAP_AUTO_PROVISION=true` creates a CTFd user after successful LDAP authentication.
- `KMITL_DEVELOPER_KEY` enables optional curriculum lookup from the KMITL student catalog API.

---

## Login behavior

The plugin accepts both raw student IDs and KMITL email addresses.

Accepted formats:

- `69010001`
- `69010001@kmitl.ac.th`

It constructs the LDAP DN from the student ID using the faculty code from digits 3–4:

- `01` → eng
- `02` → arch
- `03` → ietech
- `04` → agri
- `05` → sci
- `07` → it
- `08` → agro
- `11` → fam
- `12` → la
- `13` → iaai
- `14` → md
- `15` → ami
- `16` → nano

If the faculty code is not recognized, authentication fails with a clear error.

---

## Auto-provisioning

On first successful LDAP login:

1. The plugin checks for an existing CTFd user by student ID or email.
2. If none exists and `LDAP_AUTO_PROVISION=true`, it creates a new user with:
   - `name` = LDAP display name or student ID
   - `email` = LDAP email or `{student_id}@kmitl.ac.th`
   - `password` = `__ldap__` (sentinel value; not usable locally)
   - `verified = True`
   - `affiliation` = formatted curriculum name when available

---

## Local admin fallback

If `LDAP_ALLOW_LOCAL_ADMIN=true`, local CTFd admins can log in with their local password first.
This ensures you retain admin access if LDAP is unreachable.

---

## Admin test panel

Visit `/admin/plugins/ldap` as a CTFd admin to:

- view plugin configuration
- test LDAP server connectivity
- test a student's credentials
- see the DN and LDAP attributes used during authentication

---

## Troubleshooting

| Symptom                                        | Check                                           |
| ---------------------------------------------- | ----------------------------------------------- |
| `Invalid credentials`                          | Incorrect student ID/email or password          |
| `Unknown faculty code`                         | Verify digits 3–4 of the student ID             |
| `Cannot reach the KMITL authentication server` | LDAP host/port or network connectivity          |
| Auto-provisioning failed                       | Ensure `LDAP_AUTO_PROVISION=true`               |
| Curriculum not fetched                         | Set `KMITL_DEVELOPER_KEY` and verify API access |

Check CTFd logs for `KMITL LDAP:` messages.

---

## License

MIT
