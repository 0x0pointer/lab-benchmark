-- Oracle DB-trigger audit for VulnBank's Postgres (the proves-exploit signal for
-- business-logic vulns the HTTP observer can only see as attempts).
--
-- INVARIANT: triggers only WRITE to lab_oracle_audit and RETURN NEW unchanged — they
-- never alter VulnBank's behavior or block any (vulnerable) operation.
-- Apply AFTER init_db() has created the tables:  make apply-triggers
-- Per-run isolation: TRUNCATE lab_oracle_audit at reseed (Phase 3).

CREATE TABLE IF NOT EXISTS lab_oracle_audit (
    id         SERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    detail     JSONB DEFAULT '{}'::jsonb,
    run_id     TEXT,
    ts         TIMESTAMPTZ DEFAULT now()
);

-- transactions: negative amount = theft; zero amount = phantom transaction
CREATE OR REPLACE FUNCTION lab_audit_transfer() RETURNS trigger AS $$
BEGIN
    IF NEW.amount < 0 THEN
        INSERT INTO lab_oracle_audit(event_type, detail)
        VALUES ('DB_NEG_TRANSFER_ROW',
                jsonb_build_object('amount', NEW.amount, 'from', NEW.from_account, 'to', NEW.to_account));
    ELSIF NEW.amount = 0 THEN
        INSERT INTO lab_oracle_audit(event_type, detail)
        VALUES ('DB_ZERO_TRANSFER_ROW',
                jsonb_build_object('from', NEW.from_account, 'to', NEW.to_account));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS lab_trg_transfer ON transactions;
CREATE TRIGGER lab_trg_transfer AFTER INSERT ON transactions
    FOR EACH ROW EXECUTE FUNCTION lab_audit_transfer();

-- loans: negative loan amount (never touches users.balance — conservation is blind to it)
CREATE OR REPLACE FUNCTION lab_audit_loan() RETURNS trigger AS $$
BEGIN
    IF NEW.amount < 0 THEN
        INSERT INTO lab_oracle_audit(event_type, detail)
        VALUES ('DB_NEG_LOAN_ROW',
                jsonb_build_object('amount', NEW.amount, 'user_id', NEW.user_id));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS lab_trg_loan ON loans;
CREATE TRIGGER lab_trg_loan AFTER INSERT ON loans
    FOR EACH ROW EXECUTE FUNCTION lab_audit_loan();
