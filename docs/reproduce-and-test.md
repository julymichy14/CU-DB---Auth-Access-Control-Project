# Reproducing, testing and troubleshooting

Part of the [project README](../README.md); the README has the overview, schema, results and limitations.


## Commands by hand, without `make`

On Windows the simplest route is **WSL** (Ubuntu) with Docker Desktop's WSL
integration turned on: clone the repository inside WSL and use the `make` commands from the README unchanged. Without
`make` (any system), the same steps by hand - run the first line in WSL or Git Bash, because it is a bash
script that needs `openssl`:

```bash
bash scripts/generate_certs.sh                       # once: CA, server and client certificates
docker compose up -d --wait                          # start MariaDB 13.1 (first start: creates everything)
python -m venv .venv                                 # python3 on macOS/Linux
.venv/bin/python -m pip install -r requirements-dev.txt     # PowerShell: .venv\Scripts\python -m pip ...
.venv/bin/python app/demo.py                         # role demo
.venv/bin/python app/sqlrunner.py examples experiments      # tutorial + experiments
.venv/bin/python -m pytest                           # all tests
.venv/bin/python app/admin.py set-password smith_professor  # then:
docker compose exec mariadb mariadb -u smith_professor -p university
```

We ran exactly this sequence (with `python3`) in a fresh clone on macOS: role demo 24/24, every SQL step
passed, all tests passed. We had no Windows machine, so the WSL / PowerShell variants are untested.

Check the server version (`docker compose exec mariadb ...` works whatever the container is called):
```bash
docker compose exec mariadb mariadbd --version
# mariadbd  Ver 13.1.2-MariaDB-ubu2604 for debian-linux-gnu on aarch64 (mariadb.org binary distribution)
```

## Test files, and do the tests test?

| File | Covers |
|---|---|
| [unit/test_sqlrunner.py](../tests/unit/test_sqlrunner.py) | `parse()` on valid and malformed files, every `judge()` expectation kind, output rendering |
| [unit/test_security_helpers.py](../tests/unit/test_security_helpers.py) | `socket_sql` escaping (a hostile value stays one literal, on stdin, never on argv, never echoed), generated passwords vs the policy, input validation |
| [unit/test_repository_security.py](../tests/unit/test_repository_security.py) | key files owner-only, no secrets/keys tracked, `.env` and keys ignored, no interpolated password in SQL/shell, no string-built SQL in `app/`, TLS verification on, port on loopback |
| [integration/test_permissions.py](../tests/integration/test_permissions.py) | the 4×6 role matrix with exact error codes, view isolation, column privilege, DENY beats later GRANT, SHOW GRANTS/SHOW TABLES visibility, JSON storage, injection payloads |
| [integration/test_deny_semantics.py](../tests/integration/test_deny_semantics.py) | GRANT/DENY conflicts, nested roles, column-level DENY, `REVOKE DENY`, SET ROLE NONE, definer views, wildcard names, stale denies, PUBLIC lockout, routine-level DENY |
| [integration/test_account_model.py](../tests/integration/test_account_model.py) | no live password in any file or in the container, root only via the socket, harness refused without its certificate, the enumeration oracle (finding 12) |
| [integration/test_authentication.py](../tests/integration/test_authentication.py) | ED25519 for all demo accounts, wrong/empty/foreign passwords, no enumeration, stolen public key, lock and expiry |
| [integration/test_password_policy.py](../tests/integration/test_password_policy.py) | the validation and reuse plugins and findings 9-11 |
| [integration/test_tls.py](../tests/integration/test_tls.py) | verified connection and protocol version, wrong CA, host-name mismatch, plaintext refused, verification-off lesson, PyMySQL's unverified default |
| [integration/test_experiments.py](../tests/integration/test_experiments.py) | runs all 18 `.sql` tutorial and experiment files; any mismatching step fails with the step-by-step output |
| [integration/test_tools.py](../tests/integration/test_tools.py) | the role demo, the runner's command line, the interactive menu and `set-password`, driven with typed input |
| [unit/test_lab_api.py](../tests/unit/test_lab_api.py) | the lab's statement check (allowed kinds, DDL/GRANT/SET/multi-statement/executable comments refused), value conversion, statistics and honest headlines, the example catalogue, the HTTP layer (status codes, JSON-only POST, foreign `Host` refused, static files, no path traversal), start-up and shutdown with Docker or MariaDB unavailable |
| [integration/test_lab.py](../tests/integration/test_lab.py) | every one of the 21 playground examples gets exactly its documented answer; writes are rolled back; timeout (1969) and row limit; the same statement per role; statistics and auth chains; all four benchmark scenarios; the lab's own TLS context refuses a foreign CA; the HTTP API end to end; no password ever appears in an API answer |
| [frontend/src/*.test.ts](../frontend/src/) | result formatting, expectation matching, API error handling, the router (Vitest) |

Tests use random throw-away names (`t_lab_<hex>`, `t_pw_<hex>`) and clean up; after a run the server is as
`sql/` left it.

**Do the tests actually test?** Mutation checks on the final suite, run for real: with the professor's DENY
revoked (`REVOKE DENY SELECT ON university.financial_records FROM professor_role`) **18 of 353 tests failed** -
the professor/financial cell of the role matrix, the later-GRANT test, the JOIN test, the `SHOW TABLES` test,
the SHOW GRANTS visibility test, the `mysql.global_priv` JSON test, experiments 6 and 10, the professor's role
demo (twice), the interactive-menu test, and seven lab tests (three playground examples, the per-role comparison,
the statistics, the access matrix and the HTTP API); restoring the DENY gave 353 passed again. With
`certs/server-key.pem` set to mode 644 the key-permission unit test failed; `make certs` set it back to 600.

## Reproducing everything

| To reproduce | Command | Look for |
|---|---|---|
| The whole project from nothing | `make clean && make demo` | exit 0; `TOTAL: 108 steps passed, 0 failed` (examples) and `TOTAL: 373 steps passed, 0 failed` (experiments 1-13) |
| Role matrix ([Roles and permissions](access-control-guide.md#roles-and-permissions)) | `make roles` | `Role demo: 24/24 actions behaved as expected.` |
| Tutorial ([Experiments](experiments-and-findings.md#security-experiments-advanced)) | `make examples` | `TOTAL: 108 steps passed, 0 failed` |
| All experiments / one experiment | `make experiments` / `.venv/bin/python app/sqlrunner.py experiments/08_deny_scope_role_vs_user.sql` | `... N passed, 0 failed` |
| PUBLIC hard lockout (finding 8) | `make lockout` | `-> 14_public_lockout.sh: 13 passed, 0 failed` |
| Password policy (findings 9-11) | `.venv/bin/python -m pytest tests/integration/test_password_policy.py -v` | all PASSED |
| ED25519 attacks ([Authentication](access-control-guide.md#authentication-no-password-in-any-file)) | `.venv/bin/python -m pytest tests/integration/test_authentication.py -v` | all PASSED |
| TLS attacks ([TLS](access-control-guide.md#tls-that-is-verified-not-assumed)) | `.venv/bin/python -m pytest tests/integration/test_tls.py -v` | all PASSED |
| DENY semantics ([DENY explained](access-control-guide.md#deny-explained)) | `.venv/bin/python -m pytest tests/integration/test_deny_semantics.py -v` | all PASSED |
| Everything, verbosely | `.venv/bin/python -m pytest -v` | 353 passed |
| Server-free part | `make unit` | 157 passed |
| The Interactive Lab | `make lab`, open <http://127.0.0.1:8000> | Playground: each example shows "matches"; Analytics: access matrix 24/24, failed logins all 1045 |
| The lab's API against the server | `.venv/bin/python -m pytest tests/integration/test_lab.py -v` | all PASSED |
| Frontend checks | `make frontend-test frontend` | 10 passed, build succeeded |
| Lint | `make lint` | `lint: no findings` |
| Password-free account model ([Authentication](access-control-guide.md#authentication-no-password-in-any-file)) | `.venv/bin/python -m pytest tests/integration/test_account_model.py -v` | all PASSED |
| By hand, as a role | `make set-password USER=smith_professor`, then `make sql USER=smith_professor` | [DENY explained](access-control-guide.md#deny-explained) |
| Interactively | `make set-password USER=…`, then `.venv/bin/python app/menu.py` | pick a role, type its password, try all actions |

## Troubleshooting

| Problem | Fix |
|---|---|
| `make: docker: command not found` / daemon not running | Start Docker Desktop; verify with `docker info`. |
| `The container name "/university-db" is already in use` | Another copy of this project is running. Stop it (`make down` there), or give this copy its own name and port in `.env`: `MARIADB_CONTAINER=university-db-2` and `MARIADB_PORT=3307` (we ran two copies side by side this way; both passed `make test`). |
| `port is already allocated` | Another MariaDB/MySQL uses 3306. Set `MARIADB_PORT=3307` in `.env`. |
| `ERROR 1045` / `4151 account is locked` when you log in by hand | The demo accounts start locked and every `make demo`/`make test` gives them new random passwords: run `make set-password USER=…` again. |
| Container exits at start, log mentions `server-key.pem` | Certificates are missing/unreadable: `make reset`, `rm -rf certs`, `make up`. |
| `no password known for …` | Automated tools set passwords themselves; for interactive tools run `make set-password USER=…` first and use a terminal (the password is asked for with getpass). |
| `CERTIFICATE_VERIFY_FAILED` when you connect with your own client | Pass `--ssl-ca=certs/ca.pem --ssl-verify-server-cert` and connect to `localhost` (the certificate name). |
| `ModuleNotFoundError: nacl` / auth plugin error | Use the project venv: `make venv`; ED25519 needs `pymysql[ed25519]`. |
| A test says `DENY on an inherited role is now enforced immediately` | The server's behaviour changed (finding 1): update [Findings](experiments-and-findings.md#findings-limits-and-surprises-of-mariadb-access-control) and experiment 2. |
| An experiment was interrupted and left objects | Re-run it; every file starts by dropping its own leftovers. `make reset` always restores a pristine server. |
| `06_lockdown.sh: Permission denied` in `docker compose logs mariadb` | `chmod +x sql/06_lockdown.sh`, then `make reset && make demo`. |
| `npm not found` during `make lab` | Install Node.js 20 or newer (it includes npm); the rest of the project does not need it. |
| The lab shows a red "MariaDB unreachable" banner | Start Docker Desktop and run `make up`; the lab retries on every request, no restart needed. |
| The lab page says "Cannot reach the lab backend" | The Python server is not running: start `make lab` (or `make lab-api` while developing). |
| `Address already in use` on port 8000 | Set another port in `.env`: `LAB_PORT=8001`. |

## Repository layout

```
├── README.md                    the main document: overview, schema, results, limitations
├── Makefile                     make demo | test | unit | lint | roles | examples | experiments | lockout |
│                                     lab | lab-api | frontend-test | set-password | sql | shell | down | reset | clean
├── docker-compose.yml           MariaDB 13.1 (pinned build) with TLS; no passwords; key copied in owner-only
├── .env.example                 optional non-secret settings (port, container name, image) - no passwords
├── requirements.txt             pymysql[ed25519], python-dotenv
├── requirements-dev.txt         + pytest, pytest-cov, ruff
├── ruff.toml, pytest.ini        lint and test configuration
├── .github/workflows/ci.yml     CI: lint, frontend checks + build, MariaDB 13.1 container, tests + coverage, demo, lockout; canary job
├── sql/                         run by the image on first start, in this order:
│   ├── 01_schema.sql            tables
│   ├── 02_data.sql              fake data
│   ├── 03_roles.sql             roles, GRANT, DENY, the my_grades view and its definer
│   ├── 04_users.sql             ED25519 users, created LOCKED with an unusable key (no password)
│   ├── 05_password_policy.sql   simple_password_check + password_reuse_check
│   └── 06_lockdown.sh           root -> unix_socket OR unusable key; removes the image's healthcheck password file
├── scripts/
│   └── generate_certs.sh        CA, server and client certificates, keys mode 600
├── app/
│   ├── database.py              verified-TLS connections; passwords from memory or getpass. No security logic.
│   ├── admin.py                 socket-root helper, the short-lived harness account, set-password
│   ├── actions.py               the university SQL (fixed strings) + validated update_grade
│   ├── demo.py                  six actions x four roles, expected/actual/PASS-FAIL
│   ├── menu.py                  interactive version
│   ├── sqlrunner.py             runs annotated .sql files as different users
│   ├── lab_server.py            the Interactive Lab's HTTP API + static files (127.0.0.1, stdlib only)
│   ├── lab.py                   statement check, rolled-back execution as a demo account, stats, benchmarks
│   └── lab_examples.py          the playground's 21 examples with their documented answers
├── frontend/                    the Interactive Lab: React + TypeScript + Vite + Tailwind CSS + Recharts
│   ├── src/pages/               Home, Playground, Analytics, Docs
│   ├── src/components/          layout, SQL editor, result panel, UI pieces
│   └── src/api.ts               the only code that talks to the backend
├── examples/                    5 standalone SQL lessons + README with a 10-minute "Start here"
├── experiments/                 13 annotated SQL experiments + 14_public_lockout.sh (disposable server)
├── tests/
│   ├── unit/                    157 tests, no server needed
│   └── integration/             196 tests against the real server
└── docs/
    ├── access-control-guide.md       roles, DENY, authentication, TLS in detail
    ├── experiments-and-findings.md   the 14 experiments and the 12 findings
    ├── interactive-lab.md            the web frontend (make lab)
    ├── reproduce-and-test.md         this file
    ├── demo-output.txt               complete output of `make demo` from a fresh clone
    ├── test-output.txt               `pytest -v` with coverage, same run
    ├── lockout-output.txt            `make lockout`, same run
    ├── upstream-report-nested-role-deny.md   bug report for finding 1, prepared (not filed)
    └── screenshots/                  the Interactive Lab, taken from a fresh copy
```
