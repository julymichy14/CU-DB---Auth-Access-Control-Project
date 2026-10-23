# The MariaDB Interactive Lab

Part of the [project README](../README.md); the README has the overview, schema, results and limitations.



```bash
make lab
# MariaDB Interactive Lab: http://127.0.0.1:8000/   (Ctrl+C stops it)
# Connected to MariaDB 13.1.2-MariaDB-ubu2604 over verified TLS; demo accounts ready.
```

`make lab` does everything `make setup` does, plus `npm ci` and a production build of [frontend/](../frontend/), then
starts [app/lab_server.py](../app/lab_server.py) on `127.0.0.1` only. Open <http://127.0.0.1:8000>. It has four pages:

* **SQL Playground.** 21 preloaded statements in five groups (roles and GRANT, DENY, column privileges, where the
  limits are, authentication and TLS). Pick one and it loads its SQL, the account it runs as, and four short notes:
  what it does, which MariaDB feature it shows, why that matters, and what to observe. **Run query** sends it to
  MariaDB *as that account* (`alice_student`, `smith_professor`, `jones_finance` or `uni_admin`) over verified TLS
  with ED25519. The result shows the rows or MariaDB's error, the time measured by the backend, the account and its
  active role, and whether the answer matches the documented one. **Compare all roles** sends the same statement
  once per account. You can edit the SQL.
* **Analytics.** Live summary cards (server and TLS, dataset size, accounts) and four benchmark scenarios that run
  on your server when you press the button: the **access matrix** (4 roles x 6 actions against the documented
  policy), **failed logins** (the error code of N logins with unknown names vs. a real name: finding 12, live),
  **TLS 1.2 vs TLS 1.3** connection cost, and **one SELECT through four privilege paths**. Each result prints its
  method and number of runs, reports median, mean, stdev, min, p95 and max rather than single numbers, and says so
  when a difference is within the run-to-run spread. Every chart has a table view. Nothing is precomputed.
* **Documentation.** A summary of this README (overview, the MariaDB features, architecture, schema, setup, example
  queries, findings, limitations), with copyable commands. This README stays the complete reference.
* **Home.** What the project is, the area, and links.

**What the lab will and will not run.** The browser never sees a credential: the API holds the demo accounts' random
in-memory passwords (given by the harness, as in `make demo`). Each statement runs as the chosen demo account, so
MariaDB's privileges are the real limit (the playground's "admin" cannot read `mysql.user` either). In front of that,
[app/lab.py](../app/lab.py) accepts one statement per request, and only `SELECT`, `SHOW`, `WITH`, `DESCRIBE`,
`EXPLAIN` or a single `INSERT`/`UPDATE`/`DELETE`. It refuses DDL, `GRANT`/`DENY`, `SET`, `CALL`, executable
comments and multi-statement text before they reach the server. Every statement runs inside a transaction that is
**always rolled back**, so the data never changes, with a server-side `max_statement_time` of 5 s and at most 200
rows returned. The API accepts only JSON POSTs, refuses a `Host` header other than this machine (DNS rebinding),
sends no CORS headers, and has no debug mode.

**Development** (hot reload): `make lab-api` in one terminal (API on port 8000), and
`cd frontend && npm ci && npm run dev` in another (<http://127.0.0.1:5173>, which proxies `/api`). The frontend is
React 19, TypeScript, Vite, Tailwind CSS, Recharts and lucide icons; the API uses only the Python standard library
plus the project's existing connection code. Endpoints: `GET /api/health`, `GET /api/examples`, `POST /api/query`,
`GET /api/stats`, `GET /api/scenarios`, `POST /api/benchmark`. Set `LAB_PORT` in `.env` to use another port.

| SQL Playground: one statement, four accounts | Analytics: the access matrix, measured live |
|---|---|
| ![The same UPDATE sent as each role: student and finance get error 1142, the professor and the admin may change the grade (rolled back)](screenshots/playground-compare.png) | ![Allowed vs. denied per role, 24/24 answers match the documented policy](screenshots/analytics-access-matrix.png) |
| **Analytics: failed logins (finding 12)** | **Analytics: TLS 1.2 vs TLS 1.3, 30 runs each** |
| ![30 unknown user names and 30 wrong passwords: every attempt answered 1045](screenshots/analytics-failed-logins.png) | ![Median connection time per TLS version and every run in order; the difference is within the spread](screenshots/analytics-tls.png) |

More screenshots: [home](screenshots/home.png), [documentation page](screenshots/docs.png),
[phone width](screenshots/mobile.png). They were taken from a `make lab` started in a fresh copy of the
repository; the numbers in them are from that run and will differ slightly on your machine.
