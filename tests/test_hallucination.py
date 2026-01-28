"""Tests for hallucination detection scanner."""

import pytest

from vibeguard.scanners.hallucination import HallucinationScanner, HallucinationType
from vibeguard.models import ScanDirection


class TestHallucinationScanner:
    """Tests for hallucination detection."""
    
    def test_basic_initialization(self):
        """Test scanner initialization."""
        scanner = HallucinationScanner()
        assert scanner is not None
        assert scanner.check_citations is True
    
    def test_clean_output(self):
        """Test that reasonable output passes."""
        scanner = HallucinationScanner()
        issues = scanner.scan(
            "The weather is nice today.",
            ScanDirection.OUTPUT
        )
        # Simple statements shouldn't trigger many flags
        assert len(issues) < 3
    
    def test_input_direction_ignored(self):
        """Test that input direction is ignored."""
        scanner = HallucinationScanner()
        issues = scanner.scan(
            "According to a 2023 study by Harvard University...",
            ScanDirection.INPUT
        )
        # Should not scan inputs
        assert len(issues) == 0
    
    def test_fabricated_citation_detection(self):
        """Test detection of potentially fabricated citations."""
        scanner = HallucinationScanner()
        issues = scanner.scan(
            "According to a study by the Institute of Research, 95% of users prefer our product.",
            ScanDirection.OUTPUT
        )
        
        # Should flag potential fabricated citation
        assert len(issues) > 0
    
    def test_fabricated_statistic_detection(self):
        """Test detection of potentially fabricated statistics."""
        scanner = HallucinationScanner()
        issues = scanner.scan(
            "Studies show that 87.3% of people agree with this statement.",
            ScanDirection.OUTPUT
        )
        
        assert len(issues) > 0
    
    def test_future_date_detection(self):
        """Test detection of impossible future dates."""
        scanner = HallucinationScanner(current_year=2025)
        issues = scanner.scan(
            "In 2030, this technology was widely adopted.",
            ScanDirection.OUTPUT
        )
        
        assert len(issues) > 0
        assert any(
            HallucinationType.IMPOSSIBLE_DATE.value in str(i.metadata)
            for i in issues
        )
    
    def test_future_date_legitimate_context(self):
        """Test that future dates with legitimate context are less flagged."""
        scanner = HallucinationScanner(current_year=2025)
        # This mentions "predict" so should be less suspicious
        issues = scanner.scan(
            "Experts predict that by 2030, AI will be ubiquitous.",
            ScanDirection.OUTPUT
        )
        
        future_date_issues = [
            i for i in issues 
            if HallucinationType.IMPOSSIBLE_DATE.value in str(i.metadata)
        ]
        # Should not flag or flag with lower confidence
        assert len(future_date_issues) == 0 or all(
            i.metadata.get("confidence", 1) < 0.8 for i in future_date_issues
        )
    
    def test_overconfident_claim_detection(self):
        """Test detection of overconfident claims."""
        scanner = HallucinationScanner()
        issues = scanner.scan(
            "It is absolutely certain that this is the best approach. "
            "Everyone agrees that this is the only solution.",
            ScanDirection.OUTPUT
        )
        
        assert len(issues) > 0
    
    def test_hallucination_precursors(self):
        """Test detection of hallucination precursor phrases."""
        scanner = HallucinationScanner()
        issues = scanner.scan(
            "As we all know, the famous study proved this conclusively.",
            ScanDirection.OUTPUT
        )
        
        assert len(issues) > 0
    
    def test_context_grounding(self):
        """Test scanning with provided context."""
        scanner = HallucinationScanner()
        
        context = "Python was created by Guido van Rossum in 1991."
        output = "Python was created by Guido van Rossum in 1991. It is now used by millions."
        
        issues = scanner.scan_with_context(output, context)
        
        # First sentence is grounded, second may be flagged as unsupported
        # but overall should have few issues for well-grounded output
        unsupported = [
            i for i in issues 
            if HallucinationType.UNSUPPORTED_CLAIM.value in str(i.metadata)
        ]
        # Grounded claims should not be flagged
        assert all(
            "Guido van Rossum" not in i.detail for i in unsupported
        )
    
    def test_context_contradiction(self):
        """Test detection of claims contradicting context."""
        scanner = HallucinationScanner()
        
        context = "The company was founded in 2010."
        output = "The company was founded in 1995 and has been operating for decades."
        
        issues = scanner.scan_with_context(output, context, strict=True)
        
        # Should detect low overlap/potential contradiction
        assert len(issues) > 0
    
    def test_toggle_checks(self):
        """Test toggling individual checks."""
        scanner = HallucinationScanner(
            check_citations=False,
            check_statistics=False,
            check_dates=True,
            check_confidence=False,
        )
        
        issues = scanner.scan(
            "According to a study, 95% of people in 2050 will agree.",
            ScanDirection.OUTPUT
        )
        
        # Should only flag the future date
        citation_issues = [i for i in issues if "citation" in i.detail.lower()]
        assert len(citation_issues) == 0


class TestHallucinationEdgeCases:
    """Edge case tests for hallucination scanner."""
    
    def test_empty_text(self):
        """Test handling of empty text."""
        scanner = HallucinationScanner()
        issues = scanner.scan("", ScanDirection.OUTPUT)
        assert issues == []
    
    def test_very_short_text(self):
        """Test handling of very short text."""
        scanner = HallucinationScanner()
        issues = scanner.scan("Yes.", ScanDirection.OUTPUT)
        assert isinstance(issues, list)
    
    def test_context_as_list(self):
        """Test providing context as a list of documents."""
        scanner = HallucinationScanner()
        
        context = [
            "Document 1: Python is a programming language.",
            "Document 2: It was created by Guido van Rossum.",
        ]
        output = "Python is a programming language created by Guido van Rossum."
        
        issues = scanner.scan_with_context(output, context)
        assert isinstance(issues, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
