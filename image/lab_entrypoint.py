"""Lab entrypoint — runs UNMODIFIED VulnBank with the observer middleware attached.

This replicates VulnBank's own ``if __name__ == '__main__'`` block (init_db + app.run
with debug=True) so the vulnerable behavior is byte-for-byte identical, and only ADDS
the read-only observer. No VulnBank source file is edited.

Import order matters: importing ``app`` runs VulnBank's module-level
``init_connection_pool()``, so the DB must already be reachable — lab_start.sh blocks
on pg_isready before exec'ing this.
"""
import os

import observer
from database import init_db
from app import app

observer.install(app)
init_db()  # idempotent reseed-on-boot, exactly as VulnBank's __main__ does

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    # debug=True is INTENTIONAL — it is part of the vuln set (VB-VERBOSE-ERRORS).
    app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False)
