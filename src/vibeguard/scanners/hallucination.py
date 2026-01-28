"""
Hallucination Detection Scanner.

Detects potential hallucinations in LLM outputs by:
1. Checking for confident claims about uncertain topics
2. Detecting fabricated citations and references
3. Identifying impossible or contradictory statements
4. Comparing claims against provided context (RAG scenarios)
5. Flagging made-up entities, dates, and statistics

Note: Hallucination detection is inherently imperfect and should be
used as a signal, not a definitive judgment.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, ClassVar

from vibeguard.models import Issue, IssueSeverity, IssueType, ScanDirection
from vibeguard.scanners import Scanner


class HallucinationType(str, Enum):
    """Types of potential hallucinations."""
    
    FABRICATED_CITATION = "fabricated_citation"
    FABRICATED_STATISTIC = "fabricated_statistic"
    IMPOSSIBLE_DATE = "impossible_date"
    CONFIDENT_UNCERTAINTY = "confident_uncertainty"
    CONTEXT_CONTRADICTION = "context_contradiction"
    FABRICATED_ENTITY = "fabricated_entity"
    UNSUPPORTED_CLAIM = "unsupported_claim"


@dataclass
class HallucinationResult:
    """Result of hallucination analysis."""
    
    hallucination_type: HallucinationType
    confidence: float  # 0-1, how confident we are this is a hallucination
    description: str
    evidence: str
    suggestion: str


class HallucinationScanner(Scanner):
    """
    Detects potential hallucinations in LLM outputs.
    
    This scanner uses heuristics to identify likely hallucinations.
    It's most effective when used with context (e.g., in RAG systems).
    
    Usage:
        scanner = HallucinationScanner()
        issues = scanner.scan(llm_output, ScanDirection.OUTPUT)
        
    With context (RAG):
        scanner = HallucinationScanner()
        issues = scanner.scan_with_context(
            output=llm_output,
            context=retrieved_documents,
        )
    """
    
    name: str = "hallucination"
    
    # Patterns indicating fabricated citations
    CITATION_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        # Academic citation patterns
        (
            r"(?i)according\s+to\s+(?:a\s+)?(?:\d{4}\s+)?study\s+(?:by|from|in)\s+"
            r"(?:the\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)",
            "Study citation",
        ),
        (
            r"(?i)research\s+(?:by|from)\s+([A-Z][a-z]+(?:\s+(?:et\s+al\.?|and\s+[A-Z][a-z]+))?)",
            "Research citation",
        ),
        (
            r"(?i)published\s+in\s+(?:the\s+)?([A-Z][A-Za-z\s]+?)(?:\s+journal|\s+magazine|\s*,|\s*\.)",
            "Journal citation",
        ),
        # News citations
        (
            r"(?i)(?:according\s+to|reported\s+by)\s+(?:the\s+)?([A-Z][A-Za-z\s]+?)(?:\s*,|\s*\.)",
            "News source citation",
        ),
        # Quote attributions
        (
            r'"[^"]{20,}"\s*[-–—]\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)',
            "Quote attribution",
        ),
    ]
    
    # Patterns for specific statistics that might be fabricated
    STATISTIC_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (
            r"(\d{1,3}(?:\.\d+)?%)\s+of\s+(?:people|users|customers|respondents|participants)",
            "Percentage statistic",
        ),
        (
            r"(?:approximately|about|around|nearly|over|more\s+than)\s+"
            r"(\d+(?:,\d{3})*(?:\.\d+)?)\s+(?:million|billion|thousand|people|users)",
            "Large number statistic",
        ),
        (
            r"studies\s+show\s+that\s+(\d+(?:\.\d+)?%?)",
            "Study statistic",
        ),
        (
            r"(?:the\s+)?average\s+(?:person|user|customer)\s+.*?(\d+(?:\.\d+)?)",
            "Average statistic",
        ),
    ]
    
    # Patterns indicating confident claims about uncertain topics
    UNCERTAINTY_INDICATORS: ClassVar[list[str]] = [
        r"(?i)(?:definitely|certainly|absolutely|undoubtedly|without\s+(?:a\s+)?doubt)\s+"
        r"(?:will|is|are|has|have|was|were)",
        r"(?i)(?:it\s+is|this\s+is)\s+(?:a\s+)?(?:fact|proven|certain|guaranteed)\s+that",
        r"(?i)(?:everyone|all\s+experts?|scientists?)\s+(?:agrees?|knows?|believes?)\s+that",
        r"(?i)there\s+is\s+no\s+(?:doubt|question|debate)\s+that",
    ]
    
    # Known patterns that often precede hallucinations
    HALLUCINATION_PRECURSORS: ClassVar[list[str]] = [
        r"(?i)as\s+(?:we\s+)?(?:all\s+)?know",
        r"(?i)it(?:'s|\s+is)\s+(?:well|widely)\s+(?:known|established|documented)",
        r"(?i)(?:the\s+)?(?:famous|renowned|celebrated)\s+(?:study|research|paper|book)",
        r"(?i)(?:leading|top|prominent)\s+(?:experts?|scientists?|researchers?)\s+(?:say|believe|agree)",
    ]
    
    def __init__(
        self,
        check_citations: bool = True,
        check_statistics: bool = True,
        check_dates: bool = True,
        check_confidence: bool = True,
        confidence_threshold: float = 0.6,
        current_year: int | None = None,
    ):
        """
        Initialize the hallucination scanner.
        
        Args:
            check_citations: Check for potentially fabricated citations
            check_statistics: Check for potentially fabricated statistics
            check_dates: Check for impossible or unlikely dates
            check_confidence: Check for overconfident claims
            confidence_threshold: Minimum confidence to report (0-1)
            current_year: Current year for date validation (auto-detected if None)
        """
        self.check_citations = check_citations
        self.check_statistics = check_statistics
        self.check_dates = check_dates
        self.check_confidence = check_confidence
        self.confidence_threshold = confidence_threshold
        self.current_year = current_year or datetime.now().year
        
        # Compile patterns
        self._compiled_citations = [
            (re.compile(p), d) for p, d in self.CITATION_PATTERNS
        ]
        self._compiled_statistics = [
            (re.compile(p), d) for p, d in self.STATISTIC_PATTERNS
        ]
        self._compiled_uncertainty = [
            re.compile(p) for p in self.UNCERTAINTY_INDICATORS
        ]
        self._compiled_precursors = [
            re.compile(p) for p in self.HALLUCINATION_PRECURSORS
        ]
    
    def scan(self, text: str, direction: ScanDirection) -> list[Issue]:
        """
        Scan text for potential hallucinations.
        
        Args:
            text: The text to scan (typically LLM output)
            direction: Input or output direction
            
        Returns:
            List of potential hallucination issues
        """
        # Hallucination detection is primarily for outputs
        if direction == ScanDirection.INPUT:
            return []
        
        issues: list[Issue] = []
        
        if self.check_citations:
            issues.extend(self._check_citations(text))
        
        if self.check_statistics:
            issues.extend(self._check_statistics(text))
        
        if self.check_dates:
            issues.extend(self._check_dates(text))
        
        if self.check_confidence:
            issues.extend(self._check_confidence(text))
        
        # Check for hallucination precursors
        issues.extend(self._check_precursors(text))
        
        return issues
    
    def scan_with_context(
        self,
        output: str,
        context: str | list[str],
        strict: bool = False,
    ) -> list[Issue]:
        """
        Scan LLM output against provided context for contradictions.
        
        This is useful for RAG systems where the output should be
        grounded in the retrieved documents.
        
        Args:
            output: The LLM output to check
            context: The context/documents the output should be based on
            strict: If True, flag any claims not directly supported by context
            
        Returns:
            List of potential hallucination issues
        """
        issues = []
        
        # First run standard checks
        issues.extend(self.scan(output, ScanDirection.OUTPUT))
        
        # Combine context if it's a list
        if isinstance(context, list):
            context = "\n\n".join(context)
        
        context_lower = context.lower()
        
        # Extract claims from output
        claims = self._extract_claims(output)
        
        for claim in claims:
            # Check if claim has support in context
            claim_terms = set(re.findall(r'\b[A-Za-z]{4,}\b', claim.lower()))
            context_terms = set(re.findall(r'\b[A-Za-z]{4,}\b', context_lower))
            
            # Calculate overlap
            overlap = len(claim_terms & context_terms) / len(claim_terms) if claim_terms else 0
            
            if overlap < 0.3:  # Less than 30% term overlap
                confidence = 0.5 + (0.3 - overlap)  # Higher confidence for less overlap
                
                if confidence >= self.confidence_threshold:
                    issues.append(Issue(
                        type=IssueType.CUSTOM_RULE,
                        severity=IssueSeverity.MEDIUM if strict else IssueSeverity.LOW,
                        detail=f"Claim may not be supported by context: '{claim[:100]}...'",
                        scanner=self.name,
                        metadata={
                            "hallucination_type": HallucinationType.UNSUPPORTED_CLAIM.value,
                            "confidence": confidence,
                            "context_overlap": overlap,
                        },
                    ))
        
        return issues
    
    def _check_citations(self, text: str) -> list[Issue]:
        """Check for potentially fabricated citations."""
        issues = []
        
        for pattern, citation_type in self._compiled_citations:
            matches = pattern.finditer(text)
            for match in matches:
                # Extract the cited entity
                cited = match.group(1) if match.groups() else match.group()
                
                # Heuristics for likely fabrication:
                # 1. Very generic names
                # 2. Unusually specific details without verifiable info
                # 3. Format inconsistencies
                
                confidence = 0.4  # Base confidence
                
                # Generic-sounding names increase suspicion
                generic_terms = ["university", "institute", "research", "study", "journal"]
                if any(term in cited.lower() for term in generic_terms):
                    confidence += 0.1
                
                # Very specific-sounding but unverifiable
                if re.search(r'\d{4}', text[max(0, match.start()-50):match.end()+50]):
                    confidence += 0.1  # Year mentioned nearby
                
                if confidence >= self.confidence_threshold:
                    issues.append(Issue(
                        type=IssueType.CUSTOM_RULE,
                        severity=IssueSeverity.LOW,
                        detail=f"Potential fabricated {citation_type}: '{cited}'",
                        span=(match.start(), match.end()),
                        scanner=self.name,
                        metadata={
                            "hallucination_type": HallucinationType.FABRICATED_CITATION.value,
                            "confidence": confidence,
                            "cited_entity": cited,
                        },
                    ))
        
        return issues
    
    def _check_statistics(self, text: str) -> list[Issue]:
        """Check for potentially fabricated statistics."""
        issues = []
        
        for pattern, stat_type in self._compiled_statistics:
            matches = pattern.finditer(text)
            for match in matches:
                stat_value = match.group(1)
                
                confidence = 0.4  # Base confidence
                
                # Suspiciously round numbers
                if stat_value.endswith(('0', '0%', '.0', '.0%')):
                    confidence += 0.15
                
                # Very precise percentages (e.g., 73.2%)
                if re.match(r'\d+\.\d+%', stat_value):
                    confidence += 0.1
                
                # Extreme values
                try:
                    num = float(re.sub(r'[%,]', '', stat_value))
                    if num > 95 or num < 5:  # Extreme percentages
                        confidence += 0.1
                except ValueError:
                    pass
                
                if confidence >= self.confidence_threshold:
                    issues.append(Issue(
                        type=IssueType.CUSTOM_RULE,
                        severity=IssueSeverity.LOW,
                        detail=f"Potential fabricated {stat_type}: {stat_value}",
                        span=(match.start(), match.end()),
                        scanner=self.name,
                        metadata={
                            "hallucination_type": HallucinationType.FABRICATED_STATISTIC.value,
                            "confidence": confidence,
                            "statistic": stat_value,
                        },
                    ))
        
        return issues
    
    def _check_dates(self, text: str) -> list[Issue]:
        """Check for impossible or unlikely dates."""
        issues = []
        
        # Find year references
        year_pattern = re.compile(r'\b(1[0-9]{3}|2[0-9]{3})\b')
        
        for match in year_pattern.finditer(text):
            year = int(match.group(1))
            
            # Future years (beyond current year + 1)
            if year > self.current_year + 1:
                # Check context - might be legitimate (sci-fi, projections)
                context_start = max(0, match.start() - 50)
                context_end = min(len(text), match.end() + 50)
                context = text[context_start:context_end].lower()
                
                if not any(term in context for term in ['predict', 'project', 'forecast', 'expect', 'fiction', 'future']):
                    issues.append(Issue(
                        type=IssueType.CUSTOM_RULE,
                        severity=IssueSeverity.MEDIUM,
                        detail=f"Future date referenced: {year}",
                        span=(match.start(), match.end()),
                        scanner=self.name,
                        metadata={
                            "hallucination_type": HallucinationType.IMPOSSIBLE_DATE.value,
                            "confidence": 0.8,
                            "year": year,
                        },
                    ))
            
            # Very old dates with modern context
            elif year < 1900:
                context = text[max(0, match.start()-100):min(len(text), match.end()+100)].lower()
                modern_terms = ['internet', 'computer', 'digital', 'online', 'website', 'app', 'smartphone']
                if any(term in context for term in modern_terms):
                    issues.append(Issue(
                        type=IssueType.CUSTOM_RULE,
                        severity=IssueSeverity.MEDIUM,
                        detail=f"Anachronistic date: {year} with modern technology context",
                        span=(match.start(), match.end()),
                        scanner=self.name,
                        metadata={
                            "hallucination_type": HallucinationType.IMPOSSIBLE_DATE.value,
                            "confidence": 0.7,
                            "year": year,
                        },
                    ))
        
        return issues
    
    def _check_confidence(self, text: str) -> list[Issue]:
        """Check for overconfident claims about uncertain topics."""
        issues = []
        
        for pattern in self._compiled_uncertainty:
            matches = list(pattern.finditer(text))
            for match in matches:
                issues.append(Issue(
                    type=IssueType.CUSTOM_RULE,
                    severity=IssueSeverity.LOW,
                    detail=f"Overconfident claim: '{match.group()[:80]}...'",
                    span=(match.start(), match.end()),
                    scanner=self.name,
                    metadata={
                        "hallucination_type": HallucinationType.CONFIDENT_UNCERTAINTY.value,
                        "confidence": 0.5,
                    },
                ))
        
        return issues
    
    def _check_precursors(self, text: str) -> list[Issue]:
        """Check for phrases that often precede hallucinations."""
        issues = []
        
        for pattern in self._compiled_precursors:
            matches = list(pattern.finditer(text))
            for match in matches:
                issues.append(Issue(
                    type=IssueType.CUSTOM_RULE,
                    severity=IssueSeverity.LOW,
                    detail=f"Hallucination precursor phrase: '{match.group()}'",
                    span=(match.start(), match.end()),
                    scanner=self.name,
                    metadata={
                        "hallucination_type": HallucinationType.CONFIDENT_UNCERTAINTY.value,
                        "confidence": 0.4,
                        "precursor_phrase": match.group(),
                    },
                ))
        
        return issues
    
    def _extract_claims(self, text: str) -> list[str]:
        """Extract individual claims from text for verification."""
        # Split into sentences
        sentences = re.split(r'[.!?]+', text)
        
        claims = []
        for sentence in sentences:
            sentence = sentence.strip()
            if len(sentence) < 20:  # Too short to be a meaningful claim
                continue
            
            # Filter out questions, commands, etc.
            if sentence.endswith('?') or sentence.startswith(('Please', 'Could', 'Would', 'Can')):
                continue
            
            # Look for declarative statements
            if re.search(r'\b(is|are|was|were|has|have|had|will|would|can|could)\b', sentence, re.I):
                claims.append(sentence)
        
        return claims
