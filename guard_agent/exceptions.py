class GuardAgentError(Exception):
    """Base exception for all guard-agent errors."""


class BufferFullError(GuardAgentError):
    """Raised when an EventBuffer is full and the configured policy is 'raise'."""


class PermanentClientError(GuardAgentError):
    """Raised on a non-retryable 4xx (400/404/422).

    The batch must be dropped, not retried.
    """

    def __init__(self, status_code: int, detail: str = "") -> None:
        self.status_code = status_code
        self.detail = detail
        message = f"Permanent client error {status_code}"
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message)


class PayloadTooLargeError(PermanentClientError):
    """Raised on HTTP 413. The caller splits the batch or drops a singleton."""

    def __init__(self, detail: str = "") -> None:
        super().__init__(413, detail)
