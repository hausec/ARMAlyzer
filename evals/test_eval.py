import json, pathlib, sys
sys.path.append(str(pathlib.Path(__file__).parent.parent))
from tools.arm_ingest import analyze_arm, IngestArgs

ROOT = pathlib.Path(__file__).resolve().parents[1]
SAMPLE_TEMPLATE = ROOT / "fixtures" / "template.json"
SAMPLE_PARAMS   = ROOT / "fixtures" / "parameters.json"

def load_fixture(p: pathlib.Path) -> str:
    return p.read_text(encoding="utf-8")

def test_vm_template_findings_smoke():
    """Test ARM template analysis with sanitized test data"""
    t = load_fixture(SAMPLE_TEMPLATE)
    p = load_fixture(SAMPLE_PARAMS)
    result = analyze_arm(IngestArgs(template_text=t, parameters_text=p))

    # Verify we get findings
    assert result.stats["total"] > 0, "Should detect security issues"
    
    # Check for specific expected findings
    ids = {f.id for f in result.findings}
    assert "IMG-001" in ids, "should flag image version 'latest'"
    assert "OS-001" in ids, "should flag adminUsername"
    assert "MI-001" in ids, "should flag system+user assigned identities"
    assert "PAR-001" in ids, "should flag null parameters"
    
    # Verify severity distribution
    assert result.stats["med"] >= 3, "Should have at least 3 medium findings"
    assert result.stats["low"] >= 1, "Should have at least 1 low finding"
    
    print("All ARM template security checks passed!")

def test_arm_template_structure():
    """Test that ARM template analysis returns proper structure"""
    t = load_fixture(SAMPLE_TEMPLATE)
    p = load_fixture(SAMPLE_PARAMS)
    result = analyze_arm(IngestArgs(template_text=t, parameters_text=p))
    
    # Verify structure
    assert hasattr(result, 'findings'), "Should have findings attribute"
    assert hasattr(result, 'stats'), "Should have stats attribute"
    
    # Verify findings structure
    for finding in result.findings:
        assert hasattr(finding, 'id'), "Finding should have id"
        assert hasattr(finding, 'severity'), "Finding should have severity"
        assert hasattr(finding, 'message'), "Finding should have message"
        assert finding.severity in ['high', 'med', 'low'], "Severity should be valid"
    
    # Verify stats structure
    assert 'total' in result.stats, "Stats should have total"
    assert 'high' in result.stats, "Stats should have high count"
    assert 'med' in result.stats, "Stats should have med count"
    assert 'low' in result.stats, "Stats should have low count"
    
    print("ARM template analysis structure validation passed!")

if __name__ == "__main__":
    test_vm_template_findings_smoke()
    test_arm_template_structure()
    print("\nAll ARM template evaluation tests passed!")
