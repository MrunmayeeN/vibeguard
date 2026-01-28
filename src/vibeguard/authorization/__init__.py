"""
Agent Action Authorization System.

Provides human-in-the-loop controls for AI agent actions including:
- Action classification (risk levels)
- Approval workflows for high-risk actions
- Action logging and audit trails
- Rate limiting for actions
- Rollback capabilities

This module helps ensure AI agents don't take dangerous actions
without appropriate oversight.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable
from pathlib import Path
import threading


class ActionRisk(str, Enum):
    """Risk levels for agent actions."""
    
    LOW = "low"  # Safe actions, no approval needed
    MEDIUM = "medium"  # Potentially risky, may need approval
    HIGH = "high"  # Risky actions, approval recommended
    CRITICAL = "critical"  # Dangerous actions, approval required


class ActionCategory(str, Enum):
    """Categories of agent actions."""
    
    READ = "read"  # Reading data
    WRITE = "write"  # Writing/modifying data
    DELETE = "delete"  # Deleting data
    EXECUTE = "execute"  # Executing code/commands
    NETWORK = "network"  # Network requests
    FINANCIAL = "financial"  # Financial transactions
    COMMUNICATION = "communication"  # Sending messages/emails
    AUTHENTICATION = "authentication"  # Auth-related actions
    SYSTEM = "system"  # System-level operations


class ApprovalStatus(str, Enum):
    """Status of action approval."""
    
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    AUTO_APPROVED = "auto_approved"
    AUTO_DENIED = "auto_denied"


@dataclass
class Action:
    """Represents an agent action requiring authorization."""
    
    id: str
    name: str
    description: str
    category: ActionCategory
    risk: ActionRisk
    parameters: dict[str, Any] = field(default_factory=dict)
    tool_name: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "risk": self.risk.value,
            "parameters": self.parameters,
            "tool_name": self.tool_name,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class ApprovalRequest:
    """A request for human approval of an action."""
    
    action: Action
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None
    denial_reason: str | None = None
    
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at


@dataclass
class ActionResult:
    """Result of an action authorization check."""
    
    action: Action
    authorized: bool
    reason: str
    approval_status: ApprovalStatus
    requires_approval: bool = False
    approval_request: ApprovalRequest | None = None


class ActionClassifier:
    """
    Classifies actions by risk level and category.
    
    Uses rules and patterns to determine the risk level of agent actions.
    """
    
    # Default risk mappings for common action patterns
    DEFAULT_RISK_RULES: dict[str, tuple[ActionCategory, ActionRisk]] = {
        # File operations
        r"read_file|get_file|load_file": (ActionCategory.READ, ActionRisk.LOW),
        r"write_file|save_file|create_file": (ActionCategory.WRITE, ActionRisk.MEDIUM),
        r"delete_file|remove_file|unlink": (ActionCategory.DELETE, ActionRisk.HIGH),
        
        # Code execution
        r"execute|run_command|shell|bash|eval": (ActionCategory.EXECUTE, ActionRisk.CRITICAL),
        r"run_script|exec_code": (ActionCategory.EXECUTE, ActionRisk.HIGH),
        
        # Network
        r"http_request|fetch|curl|api_call": (ActionCategory.NETWORK, ActionRisk.MEDIUM),
        r"download|upload": (ActionCategory.NETWORK, ActionRisk.MEDIUM),
        
        # Database
        r"query|select|read_db": (ActionCategory.READ, ActionRisk.LOW),
        r"insert|update|write_db": (ActionCategory.WRITE, ActionRisk.MEDIUM),
        r"delete|drop|truncate": (ActionCategory.DELETE, ActionRisk.HIGH),
        
        # Communication
        r"send_email|send_message|notify": (ActionCategory.COMMUNICATION, ActionRisk.MEDIUM),
        r"post_social|tweet|publish": (ActionCategory.COMMUNICATION, ActionRisk.HIGH),
        
        # Financial
        r"transfer|payment|transaction": (ActionCategory.FINANCIAL, ActionRisk.CRITICAL),
        r"purchase|buy|order": (ActionCategory.FINANCIAL, ActionRisk.HIGH),
        
        # Authentication
        r"login|authenticate|oauth": (ActionCategory.AUTHENTICATION, ActionRisk.MEDIUM),
        r"change_password|reset_password": (ActionCategory.AUTHENTICATION, ActionRisk.HIGH),
        r"create_user|delete_user|grant|revoke": (ActionCategory.AUTHENTICATION, ActionRisk.CRITICAL),
        
        # System
        r"sudo|admin|root|privilege": (ActionCategory.SYSTEM, ActionRisk.CRITICAL),
        r"install|uninstall|update_system": (ActionCategory.SYSTEM, ActionRisk.HIGH),
        r"config|settings|preferences": (ActionCategory.SYSTEM, ActionRisk.MEDIUM),
    }
    
    def __init__(
        self,
        custom_rules: dict[str, tuple[ActionCategory, ActionRisk]] | None = None,
    ):
        """
        Initialize the classifier.
        
        Args:
            custom_rules: Additional classification rules
        """
        import re
        
        self.rules: dict[re.Pattern, tuple[ActionCategory, ActionRisk]] = {}
        
        # Add default rules
        for pattern, (category, risk) in self.DEFAULT_RISK_RULES.items():
            self.rules[re.compile(pattern, re.IGNORECASE)] = (category, risk)
        
        # Add custom rules
        if custom_rules:
            for pattern, (category, risk) in custom_rules.items():
                self.rules[re.compile(pattern, re.IGNORECASE)] = (category, risk)
    
    def classify(
        self,
        action_name: str,
        parameters: dict[str, Any] | None = None,
    ) -> tuple[ActionCategory, ActionRisk]:
        """
        Classify an action by name and parameters.
        
        Args:
            action_name: Name of the action/tool
            parameters: Action parameters (for context)
            
        Returns:
            Tuple of (category, risk_level)
        """
        # Check action name against rules
        for pattern, (category, risk) in self.rules.items():
            if pattern.search(action_name):
                # Potentially adjust risk based on parameters
                adjusted_risk = self._adjust_risk(risk, parameters)
                return category, adjusted_risk
        
        # Default classification
        return ActionCategory.READ, ActionRisk.LOW
    
    def _adjust_risk(
        self,
        base_risk: ActionRisk,
        parameters: dict[str, Any] | None,
    ) -> ActionRisk:
        """Adjust risk level based on parameters."""
        if not parameters:
            return base_risk
        
        risk_order = [ActionRisk.LOW, ActionRisk.MEDIUM, ActionRisk.HIGH, ActionRisk.CRITICAL]
        current_idx = risk_order.index(base_risk)
        
        # Check for high-risk parameter patterns
        params_str = json.dumps(parameters).lower()
        
        # Increase risk for sensitive paths
        if any(term in params_str for term in ['/etc/', '/root/', 'system32', 'registry']):
            current_idx = min(current_idx + 1, len(risk_order) - 1)
        
        # Increase risk for large amounts (financial)
        import re
        amounts = re.findall(r'\d+(?:\.\d+)?', params_str)
        for amount in amounts:
            try:
                if float(amount) > 1000:
                    current_idx = min(current_idx + 1, len(risk_order) - 1)
                    break
            except ValueError:
                pass
        
        return risk_order[current_idx]


class ActionAuthorizer:
    """
    Main authorization system for agent actions.
    
    Provides:
    - Risk-based action classification
    - Approval workflows for high-risk actions
    - Rate limiting
    - Audit logging
    
    Usage:
        authorizer = ActionAuthorizer()
        
        # Check if action is allowed
        result = authorizer.authorize(
            action_name="delete_file",
            parameters={"path": "/important/file.txt"},
        )
        
        if result.authorized:
            # Proceed with action
            pass
        elif result.requires_approval:
            # Wait for human approval
            approval = authorizer.wait_for_approval(result.approval_request)
    """
    
    def __init__(
        self,
        # Risk thresholds
        auto_approve_risk: ActionRisk = ActionRisk.LOW,
        require_approval_risk: ActionRisk = ActionRisk.HIGH,
        auto_deny_risk: ActionRisk | None = None,
        
        # Approval settings
        approval_timeout: timedelta = timedelta(minutes=5),
        approval_callback: Callable[[ApprovalRequest], None] | None = None,
        
        # Rate limiting
        rate_limits: dict[ActionCategory, tuple[int, timedelta]] | None = None,
        
        # Logging
        audit_log: str | Path | None = None,
        
        # Classifier
        classifier: ActionClassifier | None = None,
    ):
        """
        Initialize the authorizer.
        
        Args:
            auto_approve_risk: Risk level at or below which to auto-approve
            require_approval_risk: Risk level at or above which to require approval
            auto_deny_risk: Risk level at or above which to auto-deny (None = never)
            approval_timeout: How long approval requests last
            approval_callback: Callback when approval is requested
            rate_limits: Rate limits by category {category: (max_count, period)}
            audit_log: Path to audit log file
            classifier: Custom action classifier
        """
        self.auto_approve_risk = auto_approve_risk
        self.require_approval_risk = require_approval_risk
        self.auto_deny_risk = auto_deny_risk
        self.approval_timeout = approval_timeout
        self.approval_callback = approval_callback
        self.rate_limits = rate_limits or {}
        self.classifier = classifier or ActionClassifier()
        
        # State
        self._pending_approvals: dict[str, ApprovalRequest] = {}
        self._action_counts: dict[str, list[datetime]] = {}  # For rate limiting
        self._lock = threading.Lock()
        
        # Audit logging
        self._audit_file = None
        if audit_log:
            self._audit_file = open(audit_log, "a")
    
    def authorize(
        self,
        action_name: str,
        parameters: dict[str, Any] | None = None,
        description: str | None = None,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> ActionResult:
        """
        Authorize an action.
        
        Args:
            action_name: Name of the action/tool
            parameters: Action parameters
            description: Human-readable description
            agent_id: ID of the agent requesting the action
            session_id: Current session ID
            
        Returns:
            ActionResult with authorization decision
        """
        # Classify the action
        category, risk = self.classifier.classify(action_name, parameters)
        
        # Create action object
        action = Action(
            id=self._generate_action_id(action_name, parameters),
            name=action_name,
            description=description or f"Execute {action_name}",
            category=category,
            risk=risk,
            parameters=parameters or {},
            tool_name=action_name,
            agent_id=agent_id,
            session_id=session_id,
        )
        
        # Check rate limits
        if not self._check_rate_limit(category):
            self._log_action(action, "denied", "Rate limit exceeded")
            return ActionResult(
                action=action,
                authorized=False,
                reason=f"Rate limit exceeded for {category.value} actions",
                approval_status=ApprovalStatus.AUTO_DENIED,
            )
        
        # Determine authorization based on risk
        risk_order = [ActionRisk.LOW, ActionRisk.MEDIUM, ActionRisk.HIGH, ActionRisk.CRITICAL]
        risk_idx = risk_order.index(risk)
        auto_approve_idx = risk_order.index(self.auto_approve_risk)
        require_approval_idx = risk_order.index(self.require_approval_risk)
        
        # Auto-deny if configured
        if self.auto_deny_risk:
            auto_deny_idx = risk_order.index(self.auto_deny_risk)
            if risk_idx >= auto_deny_idx:
                self._log_action(action, "denied", f"Risk level {risk.value} exceeds threshold")
                return ActionResult(
                    action=action,
                    authorized=False,
                    reason=f"Action denied: {risk.value} risk exceeds allowed threshold",
                    approval_status=ApprovalStatus.AUTO_DENIED,
                )
        
        # Auto-approve low risk
        if risk_idx <= auto_approve_idx:
            self._log_action(action, "approved", "Auto-approved (low risk)")
            self._record_action(category)
            return ActionResult(
                action=action,
                authorized=True,
                reason="Auto-approved: low risk action",
                approval_status=ApprovalStatus.AUTO_APPROVED,
            )
        
        # Require approval for high risk
        if risk_idx >= require_approval_idx:
            approval_request = self._create_approval_request(action)
            self._log_action(action, "pending", "Awaiting approval")
            return ActionResult(
                action=action,
                authorized=False,
                reason=f"Action requires approval: {risk.value} risk",
                approval_status=ApprovalStatus.PENDING,
                requires_approval=True,
                approval_request=approval_request,
            )
        
        # Medium risk - approve but log
        self._log_action(action, "approved", f"Approved with {risk.value} risk")
        self._record_action(category)
        return ActionResult(
            action=action,
            authorized=True,
            reason=f"Approved: {risk.value} risk action",
            approval_status=ApprovalStatus.AUTO_APPROVED,
        )
    
    def approve(
        self,
        action_id: str,
        approved_by: str = "human",
    ) -> bool:
        """
        Approve a pending action.
        
        Args:
            action_id: ID of the action to approve
            approved_by: Who approved the action
            
        Returns:
            True if approved, False if not found or expired
        """
        with self._lock:
            if action_id not in self._pending_approvals:
                return False
            
            request = self._pending_approvals[action_id]
            
            if request.is_expired():
                request.status = ApprovalStatus.EXPIRED
                return False
            
            request.status = ApprovalStatus.APPROVED
            request.approved_by = approved_by
            request.approved_at = datetime.utcnow()
            
            self._log_action(request.action, "approved", f"Approved by {approved_by}")
            self._record_action(request.action.category)
            
            return True
    
    def deny(
        self,
        action_id: str,
        reason: str = "Denied by human",
        denied_by: str = "human",
    ) -> bool:
        """
        Deny a pending action.
        
        Args:
            action_id: ID of the action to deny
            reason: Reason for denial
            denied_by: Who denied the action
            
        Returns:
            True if denied, False if not found
        """
        with self._lock:
            if action_id not in self._pending_approvals:
                return False
            
            request = self._pending_approvals[action_id]
            request.status = ApprovalStatus.DENIED
            request.denial_reason = reason
            request.approved_by = denied_by
            request.approved_at = datetime.utcnow()
            
            self._log_action(request.action, "denied", f"Denied by {denied_by}: {reason}")
            
            return True
    
    def check_approval_status(self, action_id: str) -> ApprovalStatus | None:
        """
        Check the status of an approval request.
        
        Args:
            action_id: ID of the action
            
        Returns:
            Current approval status or None if not found
        """
        with self._lock:
            if action_id not in self._pending_approvals:
                return None
            
            request = self._pending_approvals[action_id]
            
            # Check expiration
            if request.status == ApprovalStatus.PENDING and request.is_expired():
                request.status = ApprovalStatus.EXPIRED
            
            return request.status
    
    def wait_for_approval(
        self,
        approval_request: ApprovalRequest,
        poll_interval: float = 0.5,
    ) -> ApprovalStatus:
        """
        Wait for an approval decision (blocking).
        
        Args:
            approval_request: The approval request to wait for
            poll_interval: How often to check status
            
        Returns:
            Final approval status
        """
        while True:
            status = self.check_approval_status(approval_request.action.id)
            
            if status is None:
                return ApprovalStatus.EXPIRED
            
            if status != ApprovalStatus.PENDING:
                return status
            
            time.sleep(poll_interval)
    
    def get_pending_approvals(self) -> list[ApprovalRequest]:
        """Get all pending approval requests."""
        with self._lock:
            pending = []
            for request in self._pending_approvals.values():
                if request.status == ApprovalStatus.PENDING:
                    if request.is_expired():
                        request.status = ApprovalStatus.EXPIRED
                    else:
                        pending.append(request)
            return pending
    
    def _generate_action_id(
        self,
        action_name: str,
        parameters: dict[str, Any] | None,
    ) -> str:
        """Generate a unique action ID."""
        content = f"{action_name}:{json.dumps(parameters or {})}:{time.time()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _create_approval_request(self, action: Action) -> ApprovalRequest:
        """Create an approval request for an action."""
        request = ApprovalRequest(
            action=action,
            expires_at=datetime.utcnow() + self.approval_timeout,
        )
        
        with self._lock:
            self._pending_approvals[action.id] = request
        
        # Notify via callback
        if self.approval_callback:
            try:
                self.approval_callback(request)
            except Exception:
                pass
        
        return request
    
    def _check_rate_limit(self, category: ActionCategory) -> bool:
        """Check if action is within rate limits."""
        if category not in self.rate_limits:
            return True
        
        max_count, period = self.rate_limits[category]
        key = category.value
        now = datetime.utcnow()
        cutoff = now - period
        
        with self._lock:
            if key not in self._action_counts:
                self._action_counts[key] = []
            
            # Remove old entries
            self._action_counts[key] = [
                ts for ts in self._action_counts[key]
                if ts > cutoff
            ]
            
            return len(self._action_counts[key]) < max_count
    
    def _record_action(self, category: ActionCategory) -> None:
        """Record an action for rate limiting."""
        key = category.value
        now = datetime.utcnow()
        
        with self._lock:
            if key not in self._action_counts:
                self._action_counts[key] = []
            self._action_counts[key].append(now)
    
    def _log_action(self, action: Action, decision: str, reason: str) -> None:
        """Log an action to the audit trail."""
        if not self._audit_file:
            return
        
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action.to_dict(),
            "decision": decision,
            "reason": reason,
        }
        
        self._audit_file.write(json.dumps(entry) + "\n")
        self._audit_file.flush()
    
    def close(self) -> None:
        """Close resources."""
        if self._audit_file:
            self._audit_file.close()
            self._audit_file = None


# Convenience functions

def require_approval(
    action_name: str,
    parameters: dict[str, Any] | None = None,
    authorizer: ActionAuthorizer | None = None,
) -> ActionResult:
    """
    Convenience function to check if an action requires approval.
    
    Args:
        action_name: Name of the action
        parameters: Action parameters
        authorizer: Authorizer to use (creates default if None)
        
    Returns:
        ActionResult with authorization decision
    """
    if authorizer is None:
        authorizer = ActionAuthorizer()
    
    return authorizer.authorize(action_name, parameters)
