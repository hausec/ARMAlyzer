import json, pathlib, sys
sys.path.append(str(pathlib.Path(__file__).parent.parent))
from tools.entra_analyzer import analyze_entra_backup

ROOT = pathlib.Path(__file__).resolve().parents[1]
SAMPLE_ENTRA_BACKUP = ROOT / "fixtures" / "entra_test"

def test_entra_backup_findings_smoke():
    """Test Entra ID backup analysis with sanitized test data"""
    result = analyze_entra_backup(str(SAMPLE_ENTRA_BACKUP))

    # Verify we get findings
    assert result.stats["total"] > 0, "Should detect security issues"
    
    # Check for specific expected findings
    finding_ids = {f.id for f in result.findings}
    
    # Critical findings
    assert "AUTH-008" in finding_ids, "Should flag tenant creation by default users"
    
    # High severity findings
    assert "AUTH-002" in finding_ids, "Should flag guest invitations from everyone"
    assert "AUTH-006" in finding_ids, "Should flag app creation by default users"
    
    # Medium severity findings
    assert "ORG-004" in finding_ids, "Should flag missing security compliance emails"
    assert "AUTH-003" in finding_ids, "Should flag email-based subscriptions"
    assert "AUTH-004" in finding_ids, "Should flag self-service password reset"
    assert "AUTH-005" in finding_ids, "Should flag risky app consent not configured"
    assert "SYNC-002" in finding_ids, "Should flag password writeback disabled"
    assert "AUTH-METHOD-FIDO2" in finding_ids, "Should flag FIDO2 disabled"
    assert "AUTH-METHOD-MicrosoftAuthenticator" in finding_ids, "Should flag Microsoft Authenticator disabled"
    assert "AUTH-METHOD-SMS" in finding_ids, "Should flag SMS authentication enabled"
    
    # Low severity findings
    assert "ORG-005" in finding_ids, "Should flag legacy Azure AD tenant type"
    assert "SYNC-003" in finding_ids, "Should flag user writeback disabled"
    assert "SYNC-004" in finding_ids, "Should flag group writeback disabled"
    assert "SYNC-005" in finding_ids, "Should flag device writeback disabled"
    
    # Verify severity distribution
    assert result.stats["critical"] >= 1, "Should have at least 1 critical finding"
    assert result.stats["high"] >= 2, "Should have at least 2 high findings"
    assert result.stats["med"] >= 8, "Should have at least 8 medium findings"
    assert result.stats["low"] >= 4, "Should have at least 4 low findings"
    
    # Verify categories
    assert "organization" in result.summary["categories"], "Should have organization issues"
    assert "policies" in result.summary["categories"], "Should have policy issues"
    assert "sync" in result.summary["categories"], "Should have sync issues"
    assert "auth" in result.summary["categories"], "Should have auth issues"
    
    print("All Entra ID security checks passed!")

def test_entra_backup_structure():
    """Test that Entra ID backup analysis returns proper structure"""
    result = analyze_entra_backup(str(SAMPLE_ENTRA_BACKUP))
    
    # Verify structure
    assert hasattr(result, 'findings'), "Should have findings attribute"
    assert hasattr(result, 'stats'), "Should have stats attribute"
    assert hasattr(result, 'summary'), "Should have summary attribute"
    
    # Verify findings structure
    for finding in result.findings:
        assert hasattr(finding, 'id'), "Finding should have id"
        assert hasattr(finding, 'severity'), "Finding should have severity"
        assert hasattr(finding, 'category'), "Finding should have category"
        assert hasattr(finding, 'message'), "Finding should have message"
        assert hasattr(finding, 'recommendation'), "Finding should have recommendation"
        assert finding.severity in ['critical', 'high', 'med', 'low'], "Severity should be valid"
    
    # Verify stats structure
    assert 'total' in result.stats, "Stats should have total"
    assert 'critical' in result.stats, "Stats should have critical count"
    assert 'high' in result.stats, "Stats should have high count"
    assert 'med' in result.stats, "Stats should have med count"
    assert 'low' in result.stats, "Stats should have low count"
    
    print("Entra ID analysis structure validation passed!")

if __name__ == "__main__":
    test_entra_backup_findings_smoke()
    test_entra_backup_structure()
    print("\nAll Entra ID evaluation tests passed!")
