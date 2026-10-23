# Roles, DENY, authentication and TLS in detail

Part of the [project README](../README.md); the README has the overview, schema, results and limitations.


## Roles and permissions

A **role** is a named bundle of privileges: privileges go to the role once and the role is granted to
users. A new professor needs one statement, `GRANT professor_role TO new_professor`. Without roles the
privileges get copied per person and drift apart.

What each role may do ([sql/03_roles.sql](../sql/03_roles.sql); every cell is checked by `make roles` and
`tests/integration/test_permissions.py::test_role_matrix`, 24 combinations):

| Role | `courses` | `students` | `grades` | `my_grades` view | `financial_records` |
|---|---|---|---|---|---|
| `student_role` | Read | No | No | Read (own rows only) | No |
| `professor_role` | Read | Read | Read + update the **`grade` column only** | Read | **DENIED** |
| `finance_role` | No | Read | No | No | Read / insert / update |
| `admin_role` | All | All | All | All | All - but only inside `university.*` |

```sql
CREATE ROLE professor_role;
GRANT professor_role TO 'smith_professor'@'%';             -- give the role to a user
SET DEFAULT ROLE professor_role FOR 'smith_professor'@'%'; -- activate it at every login
```
Without `SET DEFAULT ROLE` the user *holds* the role but it is *inactive* until they run `SET ROLE ...`
(a classic misconfiguration, reproduced in experiment 7).

`GRANT` adds a positive privilege on the server (`*.*`), a database, a table or a single column.
MariaDB's base rule: **anything not granted is forbidden** (shown in [example 1](../examples/01_roles_and_grants.sql)).

## DENY explained

**The problem:** the professor should read "everything except financial records". With `GRANT` alone you
list `students`, `courses` and `grades` separately and must remember every future table. Granting
`university.*` would expose the bank details.

**The MariaDB 13.1 solution:** grant broadly, then subtract.

```sql
GRANT SELECT ON university.* TO professor_role;                  -- "read everything..."
DENY  SELECT ON university.financial_records TO professor_role;  -- "...except this table"
```

Rules, from the [official reference](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/deny)
and **each one reproduced on 13.1.2** by an experiment or test:

| Rule | Verified by |
|---|---|
| A DENY beats every GRANT at every level, whatever the order of the statements | experiment 1 (cases A-E), `test_deny_semantics.py` |
| A deny propagates downward: database ▸ table ▸ column | experiment 1 (C, D) |
| A DENY removes only the privilege it names | experiment 1 (E) |
| Only `REVOKE DENY` at the **exact** level removes it (errors 1141 / 1147 otherwise) | experiment 4 |
| Plain `REVOKE` removes grants, not denies | experiment 4 |
| DENY works on roles, accounts and `PUBLIC` (even against the administrator) | experiments 1, 7, 8 |
| A denied table disappears from `SHOW TABLES` / `information_schema` | [example 2](../examples/02_deny.sql), experiment 10 |
| DENY lines are shown in `SHOW GRANTS` only to accounts that can read `mysql.*` | experiment 10, `test_permissions.py` |
| Stored in the `denies` key of `mysql.global_priv` | `test_deny_is_stored_in_global_priv_as_json` |
| Routine denies need the type (`ON PROCEDURE` / `ON FUNCTION`; without it: error 1144), block `CALL`/function calls with 1370, hide the routine from `INFORMATION_SCHEMA.ROUTINES`, and disappear when the routine is dropped | experiment 13, `test_routine_deny_*` |

Real `SHOW GRANTS` as an administrator (`make shell`):
```
MariaDB> SHOW GRANTS FOR professor_role;
GRANT USAGE ON *.* TO `professor_role`
GRANT SELECT ON `university`.* TO `professor_role`
GRANT UPDATE (`grade`) ON `university`.`grades` TO `professor_role`
DENY SELECT ON `university`.`financial_records` TO `professor_role`
```

Try it yourself - choose a password for the professor, then log in with it:
```bash
make set-password USER=smith_professor   # asks for the new password twice
make sql USER=smith_professor            # = docker exec -it $MARIADB_CONTAINER mariadb -u smith_professor -p university
```
```sql
SELECT code, title FROM courses;       -- works
SELECT * FROM financial_records;
-- ERROR 1142 (42000): SELECT command denied to user 'smith_professor'@'localhost' for table `university`.`financial_records`
```

The official documentation, and the MariaDB article announcing the feature, also warn that DENY is *not a
substitute for least-privilege design*: use it for clear exceptions, as here. [Findings](experiments-and-findings.md#findings-limits-and-surprises-of-mariadb-access-control) shows where the
exception mechanism itself has sharp edges.

## Authentication: no password in any file

Authentication answers **"who are you?"**; roles and grants answer **"what may you do?"**. The area brief asks
for "one of the authentication methods in place of a password in a configuration file". This project stores
**no account password anywhere** - not in Git, not in `.env`, not in the container environment, not in the
data directory - and every account still has a real authentication method:

| Account | Authentication | Where its secret lives |
|---|---|---|
| `root@localhost` (no `root@'%'` exists) | **`unix_socket`** (the OS user `root` inside the container) `OR` an ed25519 key nobody can use - see finding 12 for why the second method exists | nowhere - there is no password. Use `make shell` / `docker exec … mariadb`. |
| `alice_student`, `smith_professor`, `jones_finance`, `uni_admin` | **ED25519** | created `ACCOUNT LOCK` with an unusable key; a person sets a password with `make set-password` (getpass) and types it at login, or an automated run sets a random one that exists only in that process's memory |
| `harness_<hex>` - the administrator of one test/demo run | **ED25519 + `REQUIRE X509`** | random password in process memory only, plus `certs/client-key.pem` (issued by the project CA); dropped at the end of the run |
| `my_grades_owner@localhost` (view definer) | none - `ACCOUNT LOCK`, cannot log in | - |

| Method named in the brief | Used for |
|---|---|
| **Unix socket** ✅ | root. No password at all; only usable inside the container. Not suitable for the application, which connects over the network (TLS would be pointless over a local socket). |
| **ED25519** ✅ | every network account. Ships with MariaDB, works with `pip install pymysql[ed25519]`, works over TLS. |
| **PARSEC** | not used: the pure-Python PyMySQL cannot speak it (it needs a locally compiled C connector). |

**How it is built** ([sql/04_users.sql](../sql/04_users.sql), [sql/06_lockdown.sh](../sql/06_lockdown.sh),
[app/admin.py](../app/admin.py)):

1. The container starts with `MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1` and `MARIADB_ROOT_HOST=localhost`: the
   image creates only `root@localhost`, reachable only through the socket of the temporary init server
   (`--skip-networking`). We chose this over `MARIADB_RANDOM_ROOT_PASSWORD`, which would print a password into
   the container log.
2. `04_users.sql` creates the demo accounts with `IDENTIFIED VIA ed25519 USING '<public key>' ACCOUNT LOCK`.
   The public key belongs to 32 random bytes that were discarded after computing it, so no password matches.
3. The last init script switches root to `IDENTIFIED VIA unix_socket OR ed25519 USING '<unusable key>'` and
   removes the image's `healthcheck` accounts together with the file holding their password
   (`/var/lib/mysql/.my-healthcheck.cnf`);
   `healthcheck.sh` then connects as the OS user root through the socket. We checked the container still
   becomes healthy, also after a restart that keeps the data.
4. Each automated run creates `harness_<hex>` through `docker exec` (socket root) with a random password and
   `REQUIRE X509`, grants it only data, account and grant privileges (no `FILE`, `SUPER`, `SHUTDOWN`,
   `PROCESS`, replication or connection admin), sets random passwords for the demo accounts and unlocks them,
   and drops itself at the end.

*How passwords reach SQL.* MariaDB accepts only a string **literal** inside `PASSWORD(...)`: we checked that a
server-side placeholder (`PASSWORD(?)`) and a variable (`PASSWORD(@pw)`) are both syntax errors (1064). So a
password always travels as an escaped literal. Over a driver connection that is PyMySQL's `%s` parameter;
through `docker exec` (where there is no driver connection) `app/admin.py` uses the same escaping function as
the driver, `pymysql.converters.escape_item`, and sends the SQL on stdin, never on a command line.

Real output (`make set-password`, then logging in through the container socket):
```
$ make set-password USER=smith_professor
New password for smith_professor:
Repeat it:
Password set and account unlocked. Log in with: make sql USER=smith_professor

$ docker compose exec mariadb mariadb -u smith_professor -p… university -e "SELECT CURRENT_USER(); SELECT * FROM financial_records;"
CURRENT_USER()
smith_professor@%
--------------
SELECT * FROM financial_records
--------------

ERROR 1142 (42000) at line 1: SELECT command denied to user 'smith_professor'@'localhost' for table `university`.`financial_records`
```

### Password policy: validation and reuse plugins

[sql/05_password_policy.sql](../sql/05_password_policy.sql) installs **`simple_password_check`** (configured in
[docker-compose.yml](../docker-compose.yml): at least 12 characters, upper and lower case, a digit, a special
character) and **`password_reuse_check`** (`password_reuse_check_interval=365` days). `cracklib_password_check`
is not shipped in the image (we listed `/usr/lib/mysql/plugin`). We checked on the live server that validation
applies to `IDENTIFIED VIA ed25519 USING PASSWORD(...)` and to `SET PASSWORD` for ed25519 accounts, and that
`strict_password_validation` (ON by default) matters: it refuses credentials given as a ready-made public key
(error 1290), which the plugins could not check. The random passwords of the harness and the demo runs always
contain all character classes (`strong_password()` in [app/database.py](../app/database.py)).
[experiments/12_password_policy.sql](../experiments/12_password_policy.sql) and
[tests/integration/test_password_policy.py](../tests/integration/test_password_policy.py) show it; real excerpt:

```
Step 10  user: dba (harness_fcbbec84)  (active role: none)
    SQL      ALTER USER exp_pw_{{run}}@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
    Expected error 1396
    Actual   error 1396: Operation ALTER USER failed for 'exp_pw_0e6664'@'%'
    Result   PASS
Step 11  user: dba (harness_fcbbec84)  (active role: none)
    SQL      SHOW WARNINGS;
    Actual   ok (3 rows)
             | Warning  1819  password_reuse_check: The password was already used
             | Error    1819  Your password does not satisfy the current policy requirements (password_reuse_check)
             | Error    1396  Operation ALTER USER failed for 'exp_pw_0e6664'@'%'
```

| Attempt (as the administrator) | Result |
|---|---|
| `abc`, `password12345`, `PASSWORD-12345`, `Password-short` | refused, **1819** (`simple_password_check`) |
| `IDENTIFIED VIA ed25519` without a password (= empty password) | refused, **1819** |
| a pre-computed ed25519 public key (`USING '<key>'`) | refused, **1290** (`strict_password_validation`) |
| the same password again with `SET PASSWORD` | refused, **1819** (`password_reuse_check`) |
| a weak or reused password with `ALTER USER` | refused, but as **1396**; the reason is only in `SHOW WARNINGS` (finding 10) |
| the same password for a *different* account; a password containing the account name | **accepted** (finding 11) |

**ED25519 login:** the client says who it is; the server sends a random challenge; the client recomputes the
private key from the typed password and *signs* the challenge; the server verifies with the stored public key.
A failure returns `ERROR 1045 Access denied` before any query can run - the same error for a wrong password and
for a non-existent user, so accounts cannot be enumerated.

Attacks and results ([tests/integration/test_authentication.py](../tests/integration/test_authentication.py),
[tests/integration/test_account_model.py](../tests/integration/test_account_model.py), [example 5](../examples/05_ed25519_authentication.sql)):

| Attack / check | Expected | Actual |
|---|---|---|
| All 4 demo accounts use `ed25519` | yes | ✅ |
| Correct password | login, correct user and role | ✅ |
| Wrong password, empty password, another user's password | error **1045** | ✅ |
| Unknown user vs wrong password | identical error (no enumeration) | ✅ |
| Stored `authentication_string` (public key) used as the password | error **1045** | ✅ |
| Password appears in `mysql.user` / `mysql.global_priv` | never | ✅ |
| Locked account (`ACCOUNT LOCK`) with the correct password | error **4151** | ✅ |
| Expired password | login ok, every statement fails with **1820** | ✅ |
| root over the network (TLS), with an empty, guessed or any password | error **1045** - `root@'%'` does not exist | ✅ |
| root through `docker exec` | `root@localhost` via the `unix_socket` method, no password | ✅ |
| 200 logins with unknown user names | all **1045**, like a real account (no enumeration, finding 12) | ✅ |
| Harness account with the right password but **without** its client certificate | error **1045** | ✅ |
| Any live password (harness + 4 demo accounts) in any file of the project directory, `.env` included | none | ✅ |
| Password variables in the container environment / healthcheck password file in the data directory | only `MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1` / file absent | ✅ |
| Harness password in the server log | absent | ✅ |

## TLS that is verified, not assumed

TLS does two separate jobs: **encryption** (nobody on the network reads queries and results) and **server
authentication** (the client checks it reached *our* server). A client that encrypts but does not verify
ends up with an encrypted connection *to the attacker*. **PyMySQL 1.2's default is exactly that**: with no TLS options it
switches to "preferred" mode - TLS, but `verify_mode=CERT_NONE` and `check_hostname=False`
(`test_pymysql_default_encrypts_but_does_not_verify` asserts this on the live connection).

[scripts/generate_certs.sh](../scripts/generate_certs.sh) creates our own CA, a server certificate for the name
`localhost` signed by it, and a second *unrelated* CA used only to simulate a client that trusts the wrong
authority. Server side ([docker-compose.yml](../docker-compose.yml)):
`--ssl-cert/--ssl-key/--ssl-ca`, `--tls-version=TLSv1.2,TLSv1.3`, `--require-secure-transport=ON`.
Client side ([app/database.py](../app/database.py)): `ssl_ca=certs/ca.pem`, `ssl_verify_cert=True`, `ssl_verify_identity=True`.

| Attempt ([tests/integration/test_tls.py](../tests/integration/test_tls.py)) | Who refuses | Real result |
|---|---|---|
| Correct CA, full verification | - | ✅ connected, `TLSv1.3`, `TLS_AES_256_GCM_SHA384` |
| Client trusts a different CA | client | ❌ `[SSL: CERTIFICATE_VERIFY_FAILED] ... self-signed certificate in certificate chain` |
| Connect to `127.0.0.1` (certificate says `localhost`) | client | ❌ `CERTIFICATE_VERIFY_FAILED ... IP address mismatch` |
| No TLS at all (demo user *and* the administrator) | **server** | ❌ `3159 Connections using insecure transport are prohibited while --require_secure_transport=ON` |
| Server offers only TLS 1.2/1.3; refuses plaintext | server config | ✅ `tls_version=TLSv1.2,TLSv1.3`, `require_secure_transport=ON` |
| Encryption with verification turned **off** (explicitly, or PyMySQL's default) | - | ⚠️ connects. This is "assumed, not verified" - the lesson |

**The private key is not world-readable.** `scripts/generate_certs.sh` writes every key with mode `600`
(`umask 077`, checked after creation). The MariaDB process runs as the unprivileged `mysql` user, so the
container's entrypoint wrapper copies the key into the container with owner `mysql`, mode `600`:
```
$ docker compose exec mariadb ls -l /etc/mysql/tls
-rw-r--r-- 1 mysql mysql 1139 ca.pem
-rw-r--r-- 1 mysql mysql 1131 server-cert.pem
-rw------- 1 mysql mysql 1704 server-key.pem
```
`tests/unit/test_repository_security.py` fails if any `certs/*-key.pem` is group/other-accessible.
