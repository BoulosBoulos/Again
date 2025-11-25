# users_service/circuit_breaker.py
from datetime import datetime, timedelta
from typing import Optional


class CircuitBreaker:
    """
    Simple in-memory circuit breaker for outbound HTTP calls.

    States:
    - closed: all requests pass, count failures
    - open: requests are blocked immediately
    - half_open: allow a trial request after reset timeout
    """

    def __init__(self, name: str, max_failures: int = 3, reset_timeout_seconds: int = 30):
        self.name = name
        self.max_failures = max_failures
        self.reset_timeout = timedelta(seconds=reset_timeout_seconds)
        self.failure_count = 0
        self.state = "closed"  # "closed" | "open" | "half_open"
        self.last_failure_time: Optional[datetime] = None

    def allow_request(self) -> bool:
        """
        Return True if a request is allowed to go through, False if the circuit is open.
        """
        if self.state == "open":
            # check if we can move to half-open
            if self.last_failure_time is None:
                return False
            elapsed = datetime.utcnow() - self.last_failure_time
            if elapsed >= self.reset_timeout:
                # allow a trial request
                self.state = "half_open"
                return True
            return False

        # closed or half_open → allow
        return True

    def record_success(self) -> None:
        """
        Reset the circuit on a successful call.
        """
        self.failure_count = 0
        self.state = "closed"
        self.last_failure_time = None

    def record_failure(self) -> None:
        """
        Increment the failure count and potentially open the circuit.
        """
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        if self.failure_count >= self.max_failures:
            self.state = "open"


# Circuit breaker instance for calling the Bookings service
bookings_circuit_breaker = CircuitBreaker(
    name="bookings_service",
    max_failures=3,
    reset_timeout_seconds=30,
)
