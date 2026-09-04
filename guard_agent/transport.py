import logging
import os

from guard_agent._transport_send import TransportSendMixin
from guard_agent.encryption import PayloadEncryptor
from guard_agent.install_id import resolve_install_id
from guard_agent.models import AgentConfig
from guard_agent.protocols import TransportProtocol
from guard_agent.utils import CircuitBreaker, RateLimiter


class HTTPTransport(TransportSendMixin, TransportProtocol):
    """
    HTTP transport layer for communicating with FastAPI Guard SaaS platform.
    Includes retry logic, circuit breaker, and rate limiting.
    """

    def __init__(self, config: AgentConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

        self._client = None
        self._pid = os.getpid()
        self._install_id = resolve_install_id(override=config.install_id)

        self._encryptor: PayloadEncryptor | None = None
        self._encryption_enabled = False
        self._init_encryption()

        self.circuit_breaker = CircuitBreaker(
            failure_threshold=5, recovery_timeout=60.0
        )
        self.rate_limiter = RateLimiter(
            max_calls=100,
            time_window=60.0,
        )

        self.requests_sent = 0
        self.requests_failed = 0
        self.bytes_sent = 0

        self._register_fork_hook()
