"""Periodic housekeeping for the snmp app."""

import logging

from tacticalrmm.celery import app
from tacticalrmm.utils import redis_lock

from .models import SnmpReading

logger = logging.getLogger("trmm")

SNMP_PRUNE_LOCK = "snmp-prune-readings-lock"

# readings arrive every few minutes per device and metric, so the table grows
# without bound if nobody prunes it
PRUNE_DAYS = 90


@app.task(bind=True)
def prune_old_readings(self) -> str:
    with redis_lock(SNMP_PRUNE_LOCK, self.app.oid) as acquired:
        if not acquired:
            return f"{self.app.oid} still running"

        deleted = SnmpReading.prune(days=PRUNE_DAYS)
        logger.info(f"snmp: pruned {deleted} readings older than {PRUNE_DAYS} days")
        return f"pruned {deleted}"
