"""Abstract base class for ticket providers."""

import abc


class TicketProvider(abc.ABC):
    """All ticket providers must implement this interface."""

    @abc.abstractmethod
    def create_ticket(self, job: dict) -> dict:
        """Create a ticket for the given job.

        Returns:
            dict with keys: ticket_id (str), ticket_url (str), provider (str)
        """
