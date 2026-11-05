"""
HAZARUS Security Module
Scope management, authorization, safety gates, and policy enforcement.
"""

from .scope import ScopeManager, ScopeConfig, ScopeError, TargetType
from .authorization import AuthorizationManager, AuthorizationRecord, AuthStatus
from .safety_gate import SafetyGate, SafetyError
from .audit_logger import AuditLogger, AuditEvent
from .policy_engine import PolicyEngine, PolicyDecision, PolicyResult

__all__ = [
    "ScopeManager",
    "ScopeConfig",
    "ScopeError",
    "TargetType",
    "AuthorizationManager",
    "AuthorizationRecord",
    "AuthStatus",
    "SafetyGate",
    "SafetyError",
    "AuditLogger",
    "AuditEvent",
    "PolicyEngine",
    "PolicyDecision",
    "PolicyResult",
]
