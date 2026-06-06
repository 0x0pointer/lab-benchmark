-- Per-run honeytoken seeding. Run with a unique token:
--   psql -v token=<run_id> -d vulnerable_bank -f seed_canaries.sql
-- Applied after init_db() has (re)built the baseline. Fresh per run so a single run's
-- canary can't be replayed across runs (PLAN.md §6.1/§6.5).
--
-- The canary user is the proof anchor for several vulns:
--   * IDOR/BOLA      -> unique balance 424242.42 + account_number 'CANARY<token>'
--   * SQLi dump      -> password 'CANARY_PWD_<token>' only surfaces via a users dump
--   * weak-PIN reset -> reset_pin 'PIN_<token>'
-- seed-check.sh confirms it is armed via /debug/users.

DELETE FROM users WHERE username LIKE 'canary%';

INSERT INTO users (username, password, account_number, balance, is_admin, reset_pin, bio)
VALUES ('canary_' || :'token',
        'CANARY_PWD_' || :'token',
        'CANARY' || :'token',
        424242.42,
        false,
        'PIN_' || :'token',
        'canary')
ON CONFLICT (username) DO UPDATE
    SET password       = EXCLUDED.password,
        account_number = EXCLUDED.account_number,
        balance        = EXCLUDED.balance,
        reset_pin      = EXCLUDED.reset_pin;
