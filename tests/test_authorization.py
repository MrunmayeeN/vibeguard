"""Tests for the agent action authorization system."""

import pytest
from datetime import timedelta

from vibeguard.authorization import (
    ActionAuthorizer,
    ActionClassifier,
    Action,
    ActionCategory,
    ActionRisk,
    ApprovalStatus,
)


class TestActionClassifier:
    """Tests for action classification."""
    
    def test_basic_classification(self):
        """Test basic action classification."""
        classifier = ActionClassifier()
        
        # Read operations should be low risk
        category, risk = classifier.classify("read_file")
        assert category == ActionCategory.READ
        assert risk == ActionRisk.LOW
        
        # Shell execution should be critical
        category, risk = classifier.classify("shell_execute")
        assert category == ActionCategory.EXECUTE
        assert risk == ActionRisk.CRITICAL
    
    def test_write_operations(self):
        """Test classification of write operations."""
        classifier = ActionClassifier()
        
        category, risk = classifier.classify("write_file")
        assert category == ActionCategory.WRITE
        assert risk == ActionRisk.MEDIUM
    
    def test_delete_operations(self):
        """Test classification of delete operations."""
        classifier = ActionClassifier()
        
        category, risk = classifier.classify("delete_file")
        assert category == ActionCategory.DELETE
        assert risk == ActionRisk.HIGH
    
    def test_financial_operations(self):
        """Test classification of financial operations."""
        classifier = ActionClassifier()
        
        category, risk = classifier.classify("transfer_funds")
        assert category == ActionCategory.FINANCIAL
        assert risk == ActionRisk.CRITICAL
    
    def test_communication_operations(self):
        """Test classification of communication operations."""
        classifier = ActionClassifier()
        
        category, risk = classifier.classify("send_email")
        assert category == ActionCategory.COMMUNICATION
        assert risk == ActionRisk.MEDIUM


class TestActionAuthorizer:
    """Tests for the action authorizer."""
    
    def test_auto_approve_low_risk(self):
        """Test that low-risk actions are auto-approved."""
        authorizer = ActionAuthorizer(auto_approve_risk=ActionRisk.LOW)
        
        result = authorizer.authorize("read_file", {"path": "/tmp/test.txt"})
        
        assert result.authorized
        assert result.approval_status == ApprovalStatus.AUTO_APPROVED
    
    def test_require_approval_high_risk(self):
        """Test that high-risk actions require approval."""
        authorizer = ActionAuthorizer(
            auto_approve_risk=ActionRisk.LOW,
            require_approval_risk=ActionRisk.HIGH,
        )
        
        result = authorizer.authorize("shell_execute", {"command": "ls"})
        
        assert not result.authorized
        assert result.requires_approval
        assert result.approval_status == ApprovalStatus.PENDING
    
    def test_auto_deny_critical(self):
        """Test that critical actions can be auto-denied."""
        authorizer = ActionAuthorizer(
            auto_deny_risk=ActionRisk.CRITICAL,
        )
        
        result = authorizer.authorize("transfer_funds", {"amount": 10000})
        
        assert not result.authorized
        assert result.approval_status == ApprovalStatus.AUTO_DENIED
    
    def test_approval_workflow(self):
        """Test the full approval workflow."""
        authorizer = ActionAuthorizer(
            require_approval_risk=ActionRisk.HIGH,
        )
        
        result = authorizer.authorize("delete_file", {"path": "/important.txt"})
        assert not result.authorized
        assert result.requires_approval
        
        action_id = result.action.id
        
        approved = authorizer.approve(action_id, approved_by="admin")
        assert approved
        
        status = authorizer.check_approval_status(action_id)
        assert status == ApprovalStatus.APPROVED
    
    def test_denial_workflow(self):
        """Test denying an action."""
        authorizer = ActionAuthorizer(
            require_approval_risk=ActionRisk.HIGH,
        )
        
        result = authorizer.authorize("delete_file", {"path": "/important.txt"})
        action_id = result.action.id
        
        denied = authorizer.deny(action_id, reason="Too risky")
        assert denied
        
        status = authorizer.check_approval_status(action_id)
        assert status == ApprovalStatus.DENIED


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
