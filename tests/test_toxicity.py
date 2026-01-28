"""Tests for toxicity detection scanner."""

import pytest

from vibeguard.scanners.toxicity import ToxicityScanner, ToxicityCategory
from vibeguard.models import IssueType, IssueSeverity, ScanDirection


class TestToxicityScanner:
    """Tests for toxicity detection."""
    
    def test_basic_initialization(self):
        """Test scanner initialization."""
        scanner = ToxicityScanner()
        assert scanner is not None
        assert scanner.check_hate is True
        assert scanner.check_harassment is True
    
    def test_clean_text(self):
        """Test that clean text passes."""
        scanner = ToxicityScanner()
        issues = scanner.scan("Hello, how are you today?", ScanDirection.INPUT)
        
        # Filter out low severity (profanity checks)
        significant_issues = [i for i in issues if i.severity != IssueSeverity.LOW]
        assert len(significant_issues) == 0
    
    def test_violence_detection(self):
        """Test detection of violent content."""
        scanner = ToxicityScanner()
        issues = scanner.scan(
            "I'm going to attack and hurt people",
            ScanDirection.INPUT
        )
        
        assert len(issues) > 0
        assert any(i.type == IssueType.TOXIC_CONTENT for i in issues)
    
    def test_harassment_detection(self):
        """Test detection of harassment."""
        scanner = ToxicityScanner()
        issues = scanner.scan(
            "You're worthless and pathetic",
            ScanDirection.INPUT
        )
        
        # Should detect harassment patterns
        assert len(issues) > 0
    
    def test_self_harm_detection(self):
        """Test detection of self-harm content."""
        scanner = ToxicityScanner()
        issues = scanner.scan(
            "best way to end it all",
            ScanDirection.INPUT
        )
        
        assert len(issues) > 0
        assert any(i.severity == IssueSeverity.CRITICAL for i in issues)
    
    def test_profanity_off_by_default(self):
        """Test that profanity checking is off by default."""
        scanner = ToxicityScanner()
        assert scanner.check_profanity is False
        
        issues = scanner.scan("This is bullshit", ScanDirection.INPUT)
        # Should not flag profanity by default
        profanity_issues = [
            i for i in issues 
            if "profanity" in i.detail.lower()
        ]
        assert len(profanity_issues) == 0
    
    def test_profanity_when_enabled(self):
        """Test profanity detection when enabled."""
        scanner = ToxicityScanner(check_profanity=True)
        issues = scanner.scan("This is bullshit", ScanDirection.INPUT)
        
        assert len(issues) > 0
    
    def test_min_severity_filter(self):
        """Test minimum severity filtering."""
        scanner = ToxicityScanner(
            check_profanity=True,
            min_severity=IssueSeverity.HIGH
        )
        
        # Low severity issues should be filtered
        issues = scanner.scan("damn it", ScanDirection.INPUT)
        low_issues = [i for i in issues if i.severity == IssueSeverity.LOW]
        assert len(low_issues) == 0
    
    def test_category_toggles(self):
        """Test enabling/disabling categories."""
        scanner = ToxicityScanner(
            check_hate=False,
            check_harassment=False,
            check_violence=True,
        )
        
        categories = scanner.get_categories()
        assert ToxicityCategory.VIOLENCE in categories
        assert ToxicityCategory.HATE_SPEECH not in categories
        assert ToxicityCategory.HARASSMENT not in categories
    
    def test_doxxing_threat(self):
        """Test detection of doxxing threats."""
        scanner = ToxicityScanner()
        issues = scanner.scan(
            "I'll dox your personal information and expose your address",
            ScanDirection.INPUT
        )
        
        assert len(issues) > 0
        assert any(i.severity == IssueSeverity.CRITICAL for i in issues)
    
    def test_weapon_creation(self):
        """Test detection of weapon creation requests."""
        scanner = ToxicityScanner()
        issues = scanner.scan(
            "how to make a bomb or explosive",
            ScanDirection.INPUT
        )
        
        assert len(issues) > 0
        assert any(i.severity == IssueSeverity.CRITICAL for i in issues)


class TestToxicityEdgeCases:
    """Edge case tests for toxicity scanner."""
    
    def test_empty_text(self):
        """Test handling of empty text."""
        scanner = ToxicityScanner()
        issues = scanner.scan("", ScanDirection.INPUT)
        assert issues == []
    
    def test_unicode_text(self):
        """Test handling of unicode text."""
        scanner = ToxicityScanner()
        issues = scanner.scan("Hello 世界 🌍", ScanDirection.INPUT)
        assert isinstance(issues, list)
    
    def test_very_long_text(self):
        """Test handling of very long text."""
        scanner = ToxicityScanner()
        long_text = "This is a normal sentence. " * 1000
        issues = scanner.scan(long_text, ScanDirection.INPUT)
        assert isinstance(issues, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
