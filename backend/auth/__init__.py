"""Authorization and scope management"""

from .manager import AuthorizationManager
from .validator import TargetValidator

__all__ = ["AuthorizationManager", "TargetValidator"]

