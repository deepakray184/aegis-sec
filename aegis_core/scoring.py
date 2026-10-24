"""
Scoring and Risk Assessment Engine for AegisSec.
"""

from typing import List, Dict
from aegis_core.models import Finding, Severity, AuditSummary


def calculate_audit_summary(findings: List[Finding], duration_seconds: float) -> AuditSummary:
    """
    Computes weighted score, grade, and statistical breakdown for findings.
    """
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0
    owasp_breakdown: Dict[str, int] = {}

    deduction = 0

    for f in findings:
        if f.severity == Severity.CRITICAL:
            critical_count += 1
            deduction += 25
        elif f.severity == Severity.HIGH:
            high_count += 1
            deduction += 15
        elif f.severity == Severity.MEDIUM:
            medium_count += 1
            deduction += 8
        elif f.severity == Severity.LOW:
            low_count += 1
            deduction += 3
        elif f.severity == Severity.INFO:
            info_count += 1

        if f.owasp_category:
            owasp_breakdown[f.owasp_category] = owasp_breakdown.get(f.owasp_category, 0) + 1

    # Base score of 100, clamped at 0
    score = max(0, 100 - deduction)

    # Determine letter grade
    if score >= 95:
        grade = "A+"
        grade_label = "Exceptional Posture"
    elif score >= 85:
        grade = "A"
        grade_label = "Strong Security"
    elif score >= 70:
        grade = "B"
        grade_label = "Good (Minor Hardening Needed)"
    elif score >= 55:
        grade = "C"
        grade_label = "Moderate Risk (Needs Attention)"
    elif score >= 40:
        grade = "D"
        grade_label = "Weak Posture (Significant Gaps)"
    else:
        grade = "F"
        grade_label = "Critical Exposure (Immediate Action Required)"

    return AuditSummary(
        score=score,
        grade=grade,
        grade_label=grade_label,
        total_findings=len(findings),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
        duration_seconds=round(duration_seconds, 2),
        owasp_breakdown=owasp_breakdown,
    )
