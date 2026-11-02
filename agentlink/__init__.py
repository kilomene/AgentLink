"""AgentLink: a fixed-endpoint work line for AI agents."""

from .client import Agent, RegistrationFailed, RequestFailed, dial
from .config import DEFAULT_ENDPOINT

__version__ = "1.2.2"
__all__ = ["Agent", "RegistrationFailed", "RequestFailed", "dial",
           "DEFAULT_ENDPOINT", "__version__"]
