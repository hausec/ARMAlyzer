#!/usr/bin/env python3
"""
Test script for Entra ID backup analysis.
This demonstrates how to analyze Entra ID backup files for security issues.
"""

import sys
import pathlib
from tools.entra_analyzer import analyze_entra_backup

def main():
    """Main function for command line usage"""
    if len(sys.argv) != 2:
        print("Usage: python test_entra_analyzer.py <backup_path>")
        print("Example: python test_entra_analyzer.py c:/EntraBackup")
        sys.exit(1)
    
    backup_path = sys.argv[1]
    
    try:
        print(f"Analyzing Entra ID backup: {backup_path}")
        print("=" * 60)
        
        findings = analyze_entra_backup(backup_path)
        
        # Print summary
        print(f"\nANALYSIS SUMMARY")
        print(f"Total findings: {findings.stats['total']}")
        print(f"Critical: {findings.stats['critical']} | High: {findings.stats['high']} | Medium: {findings.stats['med']} | Low: {findings.stats['low']}")
        
        # Print findings by severity
        severity_order = ["critical", "high", "med", "low"]
        for severity in severity_order:
            severity_findings = [f for f in findings.findings if f.severity == severity]
            if severity_findings:
                print(f"\n{severity.upper()} SEVERITY ISSUES:")
                for finding in severity_findings:
                    print(f"  - {finding.id}: {finding.message}")
                    print(f"    Recommendation: {finding.recommendation}")
                    print()
        
        # Print category breakdown
        if findings.summary.get("categories"):
            print(f"\nISSUES BY CATEGORY:")
            for category, issue_ids in findings.summary["categories"].items():
                print(f"  {category}: {len(issue_ids)} issues")
        
        print(f"\nAnalysis complete!")
        
    except Exception as e:
        print(f"Error analyzing backup: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
