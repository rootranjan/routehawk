#!/usr/bin/env python3
"""
Standalone RouteHawk scan script that can be called from Flask subprocess
This avoids Flask environment conflicts by running in a clean Python process
"""

import sys
import asyncio
import json
import argparse
from pathlib import Path

# ✅ SECURITY: Use relative path instead of hardcoded absolute path
current_dir = Path(__file__).parent.absolute()
sys.path.append(str(current_dir))

from models import ScanConfig, Framework
from routehawk import AttackSurfaceScanner, auto_detect_frameworks

async def run_scan(repo_path: str):
    """Run a RouteHawk scan using the exact CLI pattern"""
    
    # Auto-detect frameworks (same as CLI)
    auto_detected = auto_detect_frameworks(repo_path)
    frameworks = auto_detected if auto_detected else [Framework.EXPRESS]
    
    # Create config (same as CLI)
    config = ScanConfig(
        repo_path=repo_path,
        frameworks=[],  # Empty list for auto-detection
        use_ai_analysis=False,
        organization_patterns=True,
        resolve_prefixes=False,
        output_formats=['json'],
        output_directory='reports'
    )
    
    # Handle auto-detection (exactly like CLI _run_async_scan)
    if not config.frameworks:  # Auto-detect mode
        config.frameworks = auto_detected if auto_detected else [Framework.EXPRESS]
    
    # Run scan (exactly like CLI)
    scanner = AttackSurfaceScanner(config)
    scan_result = await scanner.scan_repository()
    
    # Return results as structured data
    result = {
        "success": True,
        "scan_id": str(scan_result.scan_id),
        "total_routes": scan_result.total_routes,
        "high_risk_routes": scan_result.high_risk_routes,
        "medium_risk_routes": scan_result.medium_risk_routes,
        "low_risk_routes": scan_result.low_risk_routes,
        "services_found": len(scan_result.services),
        "scan_duration": scan_result.scan_duration_seconds,
        "frameworks_detected": [str(f) for f in frameworks],
        "repository_path": scan_result.repository_path
    }
    
    return result

def main():
    """Main function for command line usage"""
    parser = argparse.ArgumentParser(description='Standalone RouteHawk scanner')
    parser.add_argument('--repo-path', required=True, help='Path to repository to scan')
    parser.add_argument('--output', choices=['json', 'pretty'], default='json', help='Output format')
    
    args = parser.parse_args()
    
    try:
        # Run the scan
        result = asyncio.run(run_scan(args.repo_path))
        
        if args.output == 'json':
            # Output as JSON for subprocess consumption
            print(json.dumps(result, indent=2))
        else:
            # Pretty print for human consumption
            print(f"✅ Scan completed successfully!")
            print(f"📊 Total routes: {result['total_routes']}")
            print(f"🚨 High risk routes: {result['high_risk_routes']}")
            print(f"🔧 Services found: {result['services_found']}")
            print(f"⏱️  Scan duration: {result['scan_duration']:.2f}s")
            print(f"🔍 Frameworks detected: {', '.join(result['frameworks_detected'])}")
            
    except Exception as e:
        error_result = {
            "success": False,
            "error": str(e),
            "error_type": type(e).__name__
        }
        
        if args.output == 'json':
            print(json.dumps(error_result, indent=2))
        else:
            print(f"❌ Scan failed: {e}")
        
        sys.exit(1)

if __name__ == "__main__":
    main() 