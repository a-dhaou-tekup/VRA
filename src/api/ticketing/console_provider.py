"""Console ticket provider — prints to stdout and returns a fake ticket ID."""

import logging
from api.ticketing.base import TicketProvider

logger = logging.getLogger(__name__)


class ConsoleProvider(TicketProvider):
    """Prints a human-readable ticket to the application log. No external calls."""

    def create_ticket(self, job: dict) -> dict:
        ticket_id = f"CON-{str(job.get('job_id', 'UNKNOWN'))[:8].upper()}"
        ticket_url = f"console://tickets/{ticket_id}"

        logger.info(
            "\n╔══════════════════════════════════════════════════════════\n"
            "║  [VRA TICKET] %s\n"
            "║  Product    : %s\n"
            "║  Risk Level : %s  (score: %s)\n"
            "║  CVEs       : %s\n"
            "║  SLA Due    : %s\n"
            "║  Business   : %s / %s\n"
            "║  Status     : %s\n"
            "╚══════════════════════════════════════════════════════════",
            ticket_id,
            job.get("main_product", "N/A"),
            job.get("max_risk_level", "N/A"),
            job.get("risk_score_max", "N/A"),
            job.get("cve_list", "[]"),
            job.get("due_date", "N/A"),
            job.get("business_unit", "N/A"),
            job.get("business_owner", "N/A"),
            job.get("status", "N/A"),
        )

        return {
            "ticket_id":  ticket_id,
            "ticket_url": ticket_url,
            "provider":   "console",
        }
