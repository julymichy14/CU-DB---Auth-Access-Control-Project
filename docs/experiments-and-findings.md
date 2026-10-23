# Experiments and findings

Part of the [project README](../README.md); the README has the overview, schema, results and limitations.


## Security experiments (advanced)

Experiments 1-13 are annotated SQL files (14 is a shell script, because it needs its own throw-away server).
Each step is run **as the named user**, over verified TLS, and
printed with SQL, expected result, actual result and PASS/FAIL, plus a "Why" explanation and a security
takeaway. Initial configuration is the visible `[setup]` block at the top of each run. Each file removes
everything it created and touches only scratch objects (`exp_*`, `tut_*`), apart from the read-only
experiments 6 and 10 which attack the real university database.

Sample of the real output (experiment 9, trimmed):
```
Step 3  user: exp_viewer  (active role: none)
    SQL      SELECT * FROM exp_lab.v_definer;
    Expected rows 1
    Actual   ok (1 rows)
             | 1  base-row
    Result   PASS
    Why      FINDING: the DENY on the viewer does NOT block the DEFINER view. The view runs with its definer's privileges, so the same rows are reachable.
```

| # | File | Question | Result (13.1.2) |
|---|---|---|---|
| 1 | [grant_deny_conflicts](../experiments/01_grant_deny_conflicts.sql) | Who wins when GRANT and DENY disagree: same level, different levels, either order? | DENY always; db▸table▸column masking; only the named privilege is removed |
| 2 | [multi_role_inheritance](../experiments/02_multi_role_inheritance.sql) | GRANT in one branch, DENY three roles deep in another | DENY wins - **but only after `FLUSH PRIVILEGES`** (finding 1) |
| 3 | [column_level_deny](../experiments/03_column_level_deny.sql) | Every way to reach a denied column | Blocked in SELECT/WHERE/ORDER BY/aggregates/UPDATE; name still leaks (finding 4) |
| 4 | [revoke_deny](../experiments/04_revoke_deny.sql) | What really removes a DENY? | Exact level only; plain REVOKE does not; `REVOKE ALL` does; DENY outlives `DROP DATABASE` (finding 7) |
| 5 | [privilege_escalation](../experiments/05_privilege_escalation.sql) | 15 escalation attempts incl. a delegated admin with GRANT OPTION | All refused with specific codes (1959, 1142, 1227, 1044) |
| 6 | [unauthorized_access](../experiments/06_unauthorized_access.sql) | Joins, subqueries, other schemas, view widening - on the real DB | Every route to forbidden data blocked |
| 7 | [misconfiguration_recovery](../experiments/07_misconfiguration_recovery.sql) | Missing default role, over-broad GRANT, `DENY ... TO PUBLIC` | Symptoms, diagnosis and repair of each; PUBLIC DENY locks out the administrator until revoked |
| 8 | [deny_scope_role_vs_user](../experiments/08_deny_scope_role_vs_user.sql) | Can a user shed a role-attached DENY? | **Yes, with `SET ROLE NONE`**; account-level and PUBLIC denies cannot be shed (finding 2) |
| 9 | [views_and_deny](../experiments/09_views_and_deny.sql) | DENY vs `SQL SECURITY DEFINER` / `INVOKER` views | DENY on the viewer does not follow a definer view (finding 3) |
| 10 | [metadata_visibility](../experiments/10_metadata_visibility.sql) | What can a denied user still learn? | Listings hidden; error codes leak existence (finding 5) |
| 11 | [database_name_patterns](../experiments/11_database_name_patterns.sql) | `_`/`%` wildcards in GRANT and DENY | Unescaped `_` leaks a grant; pattern DENY ignored (finding 6) |
| 12 | [password_policy](../experiments/12_password_policy.sql) | Do the validation and reuse plugins guard ED25519 accounts? What gets through? | Weak and reused passwords refused (1819/1396/1290); refused passwords recorded, history outlives `DROP USER`, shared passwords allowed (findings 9-11) |
| 13 | [routine_deny](../experiments/13_routine_deny.sql) | `DENY EXECUTE ON PROCEDURE/FUNCTION` inside a schema-wide `GRANT EXECUTE` | Calls refused (1370), routine hidden from `INFORMATION_SCHEMA.ROUTINES`, type required (1144), `DROP` removes the deny and re-creating does not restore it |
| 14 | [public_lockout](../experiments/14_public_lockout.sh) (shell, `make lockout`) | PUBLIC hard lockout on a disposable server, and every recovery path | Documented recovery works for `DENY UPDATE`; with `DENY UPDATE, DELETE` only `--skip-grant-tables` helps (finding 8) |

And five standalone tutorial lessons in [examples/](../examples/) (roles, DENY, inheritance, column privileges,
ED25519 failures) - see [examples/README.md](../examples/README.md) for how to follow them with any SQL client.

Run them:
```bash
make experiments                                       # experiments 1-13 (14: make lockout)
.venv/bin/python app/sqlrunner.py experiments/08_deny_scope_role_vs_user.sql   # one
.venv/bin/python app/sqlrunner.py --quiet experiments/ # only PASS/FAIL lines
```
Complete output of a clean run: [docs/demo-output.txt](demo-output.txt).

## Findings: limits and surprises of MariaDB access control

Everything here was observed on **13.1.2** (a preview release - behaviour may change; the CI "canary" job
re-runs the tests weekly against the floating `13.1` tag to notice). Each finding is reproduced by an
experiment or a test that asserts the observed behaviour (finding 8 by `make lockout`, which exits non-zero
if any step differs).

1. **A DENY on an inherited role is not enforced until the role graph is rebuilt (fail-open window).**
   After `DENY SELECT ON t TO role_c`, where `role_c` is granted to `role_b`, granted to the role the user
   has active, the user kept reading `t` - even in a brand-new session - until `FLUSH PRIVILEGES` (or any
   later role `GRANT` that rebuilds the graph). A DENY on the *active* role or on the *account* took effect
   at once, even in an open session; so did `REVOKE DENY`, `GRANT` and `REVOKE` on nested roles. This
   qualifies the documentation's statement that a deny on any held role beats a grant on any other role
   at any depth: that holds only once the role graph has been rebuilt. *Implication:* after denying a role that other roles
   inherit, run `FLUSH PRIVILEGES` and **test**. (experiment 2, `test_deny_in_a_nested_role_...`)
   A bug report with a minimal reproduction is prepared in
   [docs/upstream-report-nested-role-deny.md](upstream-report-nested-role-deny.md); it has not been filed
   in the MariaDB Jira yet.
2. **A DENY attached to a role vanishes when the user runs `SET ROLE NONE`** if some other privilege
   (a direct grant, another role) still allows the access. A DENY on the *account* or on `PUBLIC` cannot be
   shed. *Implication:* anchor DENYs to the account when privileges can arrive by several paths.
   `professor_role` is safe because it is the *only* source of the professor's privileges. (experiment 8)
3. **A DENY on a user does not follow a `SQL SECURITY DEFINER` view.** The viewer, denied the base table,
   still reads it through the view, because the view runs with the definer's rights. Conversely a DENY on
   the *definer* breaks the view for everybody (error 1356). `SQL SECURITY INVOKER` views obey the viewer's
   DENY. The reliable cut-off is to DENY (or not grant) the *view*. (experiment 9)
4. **Column DENY hides data, not existence.** `SHOW CREATE TABLE` still prints the denied column's name and
   type; `SHOW COLUMNS` keeps listing it while any other privilege on it (e.g. INSERT) remains; the user can
   still insert into it; `COUNT(*)` works. Reading it in `WHERE`/`ORDER BY`/aggregates *is* blocked.
   (experiment 3)
5. **Error codes reveal that a denied table exists.** `SELECT` on a denied table → `1142`, on a
   non-existent one → `1146`, although `SHOW TABLES` and `information_schema` hide the denied one.
   *Implication:* table names are not secrets. (experiment 10)
6. **Database names in GRANT/DENY are patterns.** `GRANT SELECT ON exp_lab_a.*` also grants `exp1lab1a`
   (each `_` is a wildcard); escape as `` `exp\_lab\_a` ``. A DENY written as a pattern is ignored when a
   more specific (exact) entry exists, so the broad DENY silently does nothing. (experiment 11)
7. **DENYs outlive what they point to.** `DROP DATABASE` leaves a database-level DENY; a re-created database
   with the same name is silently denied again. (experiment 4)
8. **`DENY ... TO PUBLIC` applies to every administrator, and can lock them all out.** Existing sessions keep
   working; new ones are denied. For a database-level PUBLIC deny the administrator recovers with
   `REVOKE DENY ... FROM PUBLIC` (experiment 7). The hard lockout is reproduced on a **disposable server**
   by `make lockout` ([experiments/14_public_lockout.sh](../experiments/14_public_lockout.sh); a separately named
   container and volume, removed afterwards - never the project's server):
   * `DENY UPDATE ON *.* TO PUBLIC`: in new sessions root gets 1142 on any UPDATE, `REVOKE DENY ... FROM
     PUBLIC` fails with **1045 "Access denied ... (using password: NO)"** - a misleading code that reads like
     a failed login - and `UPDATE mysql.global_priv` fails with 1142. The documented recovery works:
     `DELETE FROM mysql.global_priv WHERE User = 'PUBLIC'; FLUSH PRIVILEGES;` (DELETE was never denied).
   * `DENY UPDATE, DELETE ON *.* TO PUBLIC`: now the documented recovery fails too (1142 on the DELETE).
     Nothing over SQL lifts it; only a restart with `--skip-grant-tables` (access to the server process,
     not just SQL), deleting the row, and a normal restart. All 13 steps passed.

9. **The password reuse history keeps refused passwords and outlives the account.** A password that fails
   `simple_password_check` is still written to `mysql.password_reuse_check_history`: the second attempt with
   the same weak password is reported as *reused*. After `DROP USER`, re-creating the account with its old
   password is refused as reused. The history is never cleaned for dropped accounts. The plugin documentation
   does not mention either behaviour. (experiment 12, `test_a_refused_password_is_still_recorded_as_used`,
   `test_reuse_history_survives_drop_user`)
10. **The same policy violation has two error codes.** A weak or reused password set with `SET PASSWORD` is
    error 1819 naming the plugin; set with `ALTER USER ... IDENTIFIED VIA ed25519 USING PASSWORD(...)` it is
    the generic **1396** "Operation ALTER USER failed", with the 1819 only in `SHOW WARNINGS`. Code that looks
    for 1819 misses it; `make set-password` therefore uses `SET PASSWORD` (then unlocks with `ALTER USER`).
    (experiment 12)
11. **What the password policy does not catch:** two accounts sharing a password (reuse is per account), a
    password containing the account name, and credentials that existed before the plugins were installed
    (the policy never re-checks them: `my_grades_owner` and the image's `mariadb.sys` keep an empty password -
    both are locked, which is why locking matters). (experiment 12)

12. **A `unix_socket`-only account opens a user-enumeration oracle.** For a login with an *unknown* user name,
    MariaDB imitates the authentication plugin of a random existing account. When it picks a `unix_socket`
    account the attempt fails with **1698** ("Access denied for user ...", without "using password"),
    while every real network account fails with **1045**. So one 1698 proves the name does not exist. We hit
    this ourselves: our first design made root `unix_socket`-only, and the CI run for that commit failed
    `test_unknown_user_and_wrong_password_look_identical` once. Measured (real runs, wrong password):

    | Server state | 200 unknown names | real account (100×) |
    |---|---|---|
    | root `unix_socket` only (1 of 13 accounts) | 185 × 1045, **15 × 1698** | 100 × 1045 |
    | + 10 extra `unix_socket` accounts | 72 × 1045, **128 × 1698** | 100 × 1045 |
    | root `ed25519 … OR unix_socket` (disposable server, 300 names) | 213 × 1045, **87 × 1698** | 100 × 1045 |
    | root `unix_socket OR ed25519 USING '<unusable key>'` (disposable server, 300 names) | **300 × 1045** | 100 × 1045 |

    The account's *main* plugin (the `plugin` column, which is the **last** method of an `OR` chain) is what
    gets imitated. The project now uses the last row ([sql/06_lockdown.sh](../sql/06_lockdown.sh)):
    `test_unknown_users_are_indistinguishable_from_real_ones` checks 200 unknown names, and
    `test_a_unix_socket_only_account_opens_a_user_enumeration_oracle` re-creates the oracle with temporary
    accounts. *Implication:* never leave a `unix_socket`-only account on a server that is reachable over the
    network; put `unix_socket` first in an `OR` chain that ends with a method network accounts use.

Real excerpt of `make lockout` (finding 8):
```
Step 10  user: root@localhost (new session)
    SQL      DELETE FROM mysql.global_priv WHERE User = 'PUBLIC';
    Expected ERROR 1142
    Actual   ERROR 1142 (42000): DELETE command denied to user 'root'@'localhost' for table `mysql`.`global_priv`
    Result   PASS
    Why      The documented recovery is closed as well: root cannot delete PUBLIC's row.
...
-> 14_public_lockout.sh: 13 passed, 0 failed
```

Routine-level DENY (experiment 13) behaved exactly as documented. Real excerpt:
```
Step 7  user: exp_u  (active role: none)
    SQL      SELECT exp_lab.salary_of(1);
    Expected error 1370 salary_of
    Actual   error 1370: execute command denied to user 'exp_u'@'%' for routine 'exp_lab.salary_of'
    Result   PASS
```
Note the contrast with finding 7: a routine's DENY is removed by `DROP FUNCTION`/`DROP PROCEDURE` (so a
re-created routine is open again), while a database-level DENY survives `DROP DATABASE`.

Other results worth knowing: a delegated administrator with `GRANT OPTION` cannot hand out, or unlock for
themselves, a privilege they are DENIED (experiment 5); `SELECT *` with only some column grants fails at
table level (1142), referencing a denied column fails at column level (1143); `LOAD_FILE` without the FILE
privilege silently returns `NULL` instead of an error.
