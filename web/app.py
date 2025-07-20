#!/usr/bin/env python3
"""
Web interface for RouteHawk Attack Surface Discovery Tool
Interactive dashboard for visualizing and managing scan results.
"""

import os
import json
import asyncio
import threading
import subprocess
import sys
import secrets
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import asdict

from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
from flask_cors import CORS

# ✅ SECURITY: Use relative path instead of hardcoded path
current_dir = Path(__file__).parent.parent.absolute()
sys.path.append(str(current_dir))

from models import ScanResult, RouteInfo, Framework, RiskLevel, ScanConfig
from routehawk import AttackSurfaceScanner, auto_detect_frameworks

# ✅ SECURITY: Import security utilities
try:
    from security_config import SecurityConfig
    secure_secret_key = SecurityConfig.get_secure_secret_key()
except ImportError:
    # Fallback to secure random key if security_config not available
    secure_secret_key = secrets.token_urlsafe(32)

app = Flask(__name__)
app.secret_key = secure_secret_key
CORS(app)

# Global storage for scan results (in production, use a proper database)
scan_results_storage = {}
current_scan_id = None

async def _web_async_scan(config: ScanConfig):
    """Web version of _run_async_scan - matches CLI pattern exactly"""
    
    # Handle auto-detection of frameworks (same as CLI)
    if not config.frameworks:  # Auto-detect mode (empty list)
        app.logger.info("🔍 Auto-detecting frameworks...")
        auto_detected = auto_detect_frameworks(config.repo_path)
        config.frameworks = auto_detected if auto_detected else [Framework.EXPRESS]  # Default fallback
        app.logger.info(f"✓ Detected frameworks: {', '.join([f.value if hasattr(f, 'value') else str(f) for f in config.frameworks])}")

    # Full scan mode (same as CLI)
    scanner = AttackSurfaceScanner(config)
    scan_result = await scanner.scan_repository()
    
    return scan_result

@app.route('/')
def index():
    """Main dashboard page."""
    # Check if scan results are passed via URL parameters
    url_total_routes = request.args.get('total_routes', type=int)
    url_scan_completed = request.args.get('scan_completed')
    
    # Get the latest scan results from storage or URL parameters
    latest_stats = {
        'total_routes': url_total_routes or 0,
        'high_risk_routes': request.args.get('high_risk_routes', type=int) or 0,
        'medium_risk_routes': request.args.get('medium_risk_routes', type=int) or 0,
        'low_risk_routes': request.args.get('low_risk_routes', type=int) or 0,
        'services_count': request.args.get('services_found', type=int) or 0,
        'total_scans': len(scan_results_storage)
    }
    
    # If no URL parameters, try to get from storage
    if not url_scan_completed and scan_results_storage and current_scan_id:
        try:
            latest_scan = scan_results_storage.get(current_scan_id)
            if latest_scan:
                latest_stats.update({
                    'total_routes': latest_scan.get('total_routes', 0),
                    'high_risk_routes': latest_scan.get('high_risk_routes', 0),
                    'medium_risk_routes': latest_scan.get('medium_risk_routes', 0),
                    'low_risk_routes': latest_scan.get('low_risk_routes', 0),
                    'services_count': latest_scan.get('services_found', 0)
                })
                app.logger.info(f"Dashboard showing latest scan: {latest_stats['total_routes']} routes")
        except Exception as e:
            app.logger.error(f"Error loading scan results for dashboard: {e}")
    
    if url_scan_completed:
        app.logger.info(f"Dashboard showing URL scan results: {latest_stats['total_routes']} routes")
    elif not scan_results_storage:
        app.logger.info("No scan results found for dashboard")
    
    return render_template('index.html', stats=latest_stats)

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Scan configuration and execution page."""
    if request.method == 'GET':
        return render_template('scan.html')
    
    # Handle scan request
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('repo_path'):
            return jsonify({'error': 'Repository path is required'}), 400
        
        # Parse frameworks
        frameworks = []
        framework_list = data.get('frameworks', [])
        
        # If no frameworks specified or empty, auto-detect all
        if not framework_list or framework_list == ['auto']:
            # Auto-detect frameworks from repository
            auto_detected = auto_detect_frameworks(data['repo_path'])
            frameworks = auto_detected if auto_detected else [Framework.EXPRESS]
        else:
            for fw in framework_list:
                if fw == 'nestjs':
                    frameworks.append(Framework.NESTJS)
                elif fw == 'express':
                    frameworks.append(Framework.EXPRESS)
                elif fw == 'nextjs':
                    frameworks.append(Framework.NEXTJS)
                elif fw == 'go':
                    frameworks.append(Framework.GO_HTTP)
                elif fw == 'python':
                    frameworks.append(Framework.FASTAPI)
                elif fw == 'flask':
                    frameworks.append(Framework.FLASK)
                elif fw == 'django':
                    frameworks.append(Framework.DJANGO)
                elif fw == 'spring':
                    frameworks.append(Framework.SPRING_BOOT)
        
        # Create scan configuration
        config = ScanConfig(
            repo_path=data['repo_path'],
            frameworks=frameworks,
            use_ai_analysis=data.get('use_ai', True),
            organization_patterns=data.get('organization_patterns', True),
            risk_threshold=RiskLevel(data.get('risk_threshold', 'MEDIUM')),
            resolve_prefixes=data.get('resolve_prefixes', False),
            output_formats=data.get('output_formats', ['json', 'html']),
            output_directory=data.get('output_directory', 'reports'),
            prefixes_only=data.get('prefixes_only', False),
            # Performance configuration with defaults
            performance_mode=data.get('performance_mode', 'auto'),
            cache_enabled=data.get('cache_enabled', True),
            max_memory_mb=data.get('max_memory_mb', 1024),
            chunk_size=data.get('chunk_size'),
            max_workers=data.get('max_workers'),
            progress_mode=data.get('progress_mode', 'enhanced'),
            performance_report=data.get('performance_report', True)
        )
        
        # Run scan
        scanner = AttackSurfaceScanner(config)
        scan_result = asyncio.run(scanner.scan_repository())
        
        # Store result
        global current_scan_id
        current_scan_id = scan_result.scan_id
        scan_results_storage[scan_result.scan_id] = scan_result
        
        return jsonify({
            'success': True,
            'scan_id': scan_result.scan_id,
            'summary': {
                'total_routes': scan_result.total_routes,
                'high_risk_routes': scan_result.high_risk_routes,
                'medium_risk_routes': scan_result.medium_risk_routes,
                'low_risk_routes': scan_result.low_risk_routes,
                'services_found': len(scan_result.services),
                'scan_duration': scan_result.scan_duration_seconds
            }
        })
        
    except Exception as e:
        app.logger.error(f"Scan error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/results')
def results():
    """Results viewing page."""
    scan_id = request.args.get('scan_id', current_scan_id)
    
    if not scan_id or scan_id not in scan_results_storage:
        flash('No scan results found. Please run a scan first.', 'warning')
        return redirect(url_for('scan'))
    
    scan_result = scan_results_storage[scan_id]
    return render_template('results.html', scan_result=scan_result)

@app.route('/api/scan/<scan_id>')
def get_scan_result(scan_id):
    """Get scan result by ID."""
    if scan_id not in scan_results_storage:
        return jsonify({'error': 'Scan result not found'}), 404
    
    scan_result = scan_results_storage[scan_id]
    
    # Convert to serializable format
    result_data = {
        'scan_id': scan_result.scan_id,
        'timestamp': scan_result.timestamp.isoformat(),
        'repository_path': scan_result.repository_path,
        'total_routes': scan_result.total_routes,
        'routes_by_framework': scan_result.routes_by_framework,
        'routes_by_method': scan_result.routes_by_method,
        'routes_by_risk': scan_result.routes_by_risk,
        'high_risk_routes': scan_result.high_risk_routes,
        'medium_risk_routes': scan_result.medium_risk_routes,
        'low_risk_routes': scan_result.low_risk_routes,
        'unauthenticated_routes': scan_result.unauthenticated_routes,
        'organization_services': scan_result.organization_services,
        'internal_services': scan_result.internal_services,
        'business_services': scan_result.business_services,
        'scan_duration_seconds': scan_result.scan_duration_seconds,
        'files_analyzed': scan_result.files_analyzed,
        'services': []
    }
    
    # Add service details
    for service in scan_result.services:
        service_data = {
            'name': service.name,
            'path': service.path,
            'framework': service.framework.value,
            'routes': []
        }
        
        # Add route details
        for route in service.routes:
            route_data = {
                'method': route.method.value,
                'path': route.path,
                'file_path': route.file_path,
                'line_number': route.line_number,
                'framework': route.framework.value,
                'auth_required': route.auth_required,
                'auth_type': route.auth_type.value,
                'risk_score': route.risk_score,
                'risk_level': route.risk_level.value,
                'risk_factors': route.risk_factors,
                'parameters': [
                    {
                        'name': p.name,
                        'type': p.type,
                        'required': p.required
                    } for p in route.parameters
                ],
                'organization_package_usage': route.organization_package_usage,
                'feature_flags': route.feature_flags,
                'database_access': route.database_access
            }
            service_data['routes'].append(route_data)
        
        result_data['services'].append(service_data)
    
    return jsonify(result_data)

@app.route('/api/scan/start', methods=['POST'])
def start_scan_api():
    """Start a new scan via API - using exact CLI pattern."""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('repo_path'):
            return jsonify({'error': 'Repository path is required', 'success': False}), 400
        
        app.logger.info("Step 1: Starting scan with CLI pattern...")
        
        # Create scan configuration with EMPTY frameworks (same as CLI with --frameworks=auto)
        config = ScanConfig(
            repo_path=data['repo_path'],
            frameworks=[],  # Empty list triggers auto-detection in _web_async_scan
            use_ai_analysis=data.get('use_ai', False),
            organization_patterns=True,
            resolve_prefixes=False,
            output_formats=['json'],
            output_directory='reports'
        )
        app.logger.info("Step 2: Config created with empty frameworks (like CLI)")
        
        # Use the exact CLI pattern: asyncio.run(_run_async_scan(...))
        scan_result = asyncio.run(_web_async_scan(config))
        app.logger.info("Step 3: Scan completed using CLI pattern")
        
        # Store result
        global current_scan_id
        current_scan_id = scan_result.scan_id
        scan_results_storage[scan_result.scan_id] = scan_result
        app.logger.info("Step 4: Result stored")
        
        # Return actual scan results
        return jsonify({
            'success': True,
            'scan_id': str(scan_result.scan_id),
            'message': 'Scan completed successfully',
            'summary': {
                'total_routes': getattr(scan_result, 'total_routes', 0),
                'high_risk_routes': getattr(scan_result, 'high_risk_routes', 0),
                'medium_risk_routes': getattr(scan_result, 'medium_risk_routes', 0),
                'low_risk_routes': getattr(scan_result, 'low_risk_routes', 0),
                'services_found': len(getattr(scan_result, 'services', [])),
                'scan_duration': getattr(scan_result, 'scan_duration_seconds', 0)
            }
        })
        
    except Exception as e:
        import traceback
        full_trace = "Details available in server logs"
        app.logger.error(f"API Scan error: {e}")
        app.logger.error(f"Full traceback: {full_trace}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': f'Scan failed: {str(e)}',
            'debug_trace': full_trace
        }), 500

@app.route('/api/routes')
def get_routes():
    """Get all routes with filtering options."""
    scan_id = request.args.get('scan_id', current_scan_id)
    
    if not scan_id or scan_id not in scan_results_storage:
        return jsonify({'error': 'No scan results found'}), 404
    
    scan_result = scan_results_storage[scan_id]
    
    # Get filter parameters
    risk_filter = request.args.get('risk')
    framework_filter = request.args.get('framework')
    service_filter = request.args.get('service')
    auth_filter = request.args.get('auth')
    
    # Collect all routes
    all_routes = []
    for service in scan_result.services:
        for route in service.routes:
            route_data = {
                'id': f"{service.name}_{route.method.value}_{route.path}".replace('/', '_'),
                'service': service.name,
                'method': route.method.value,
                'path': route.path,
                'file_path': route.file_path,
                'line_number': route.line_number,
                'framework': route.framework.value,
                'auth_required': route.auth_required,
                'auth_type': route.auth_type.value,
                'risk_score': route.risk_score,
                'risk_level': route.risk_level.value,
                'risk_factors': route.risk_factors,
                'organization_packages': route.organization_package_usage
            }
            all_routes.append(route_data)
    
    # Apply filters
    filtered_routes = all_routes
    
    if risk_filter:
        filtered_routes = [r for r in filtered_routes if r['risk_level'] == risk_filter.upper()]
    
    if framework_filter:
        filtered_routes = [r for r in filtered_routes if r['framework'] == framework_filter]
    
    if service_filter:
        filtered_routes = [r for r in filtered_routes if service_filter.lower() in r['service'].lower()]
    
    if auth_filter == 'no_auth':
        filtered_routes = [r for r in filtered_routes if not r['auth_required']]
    elif auth_filter == 'has_auth':
        filtered_routes = [r for r in filtered_routes if r['auth_required']]
    
    return jsonify({
        'routes': filtered_routes,
        'total': len(filtered_routes),
        'total_unfiltered': len(all_routes)
    })

@app.route('/api/stats')
def get_stats():
    """Get scan statistics."""
    scan_id = request.args.get('scan_id', current_scan_id)
    
    if not scan_id or scan_id not in scan_results_storage:
        return jsonify({'error': 'No scan results found'}), 404
    
    scan_result = scan_results_storage[scan_id]
    
    return jsonify({
        'summary': {
            'total_routes': scan_result.total_routes,
            'high_risk': scan_result.high_risk_routes,
            'medium_risk': scan_result.medium_risk_routes,
            'low_risk': scan_result.low_risk_routes,
            'unauthenticated': scan_result.unauthenticated_routes,
            'services': [
                {
                    'name': service.name,
                    'path': service.path,
                    'routes_count': len(service.routes),
                    'organization_services': scan_result.organization_services,
                    'internal_services': scan_result.internal_services,
                    'business_services': scan_result.business_services,
                } for service in scan_result.services
            ]
        },
        'by_framework': scan_result.routes_by_framework,
        'by_method': scan_result.routes_by_method,
        'by_risk': scan_result.routes_by_risk,
        'organization_services': {
            'core': len(scan_result.organization_services),
            'internal': len(scan_result.internal_services),
            'business': len(scan_result.business_services)
        }
    })

@app.route('/api/export/<format>')
def export_results(format):
    """Export scan results in specified format."""
    scan_id = request.args.get('scan_id', current_scan_id)
    
    if not scan_id or scan_id not in scan_results_storage:
        return jsonify({'error': 'No scan results found'}), 404
    
    scan_result = scan_results_storage[scan_id]
    
    if format == 'json':
        # Export as JSON
        output_path = f"reports/routehawk_report_{scan_id}.json"
        
        # Create reports directory
        os.makedirs('reports', exist_ok=True)
        
        # Write JSON file
        with open(output_path, 'w') as f:
            json.dump(asdict(scan_result), f, indent=2, default=str)
        
        return send_file(output_path, as_attachment=True)
    
    elif format == 'csv':
        # Export routes as CSV
        import csv
        output_path = f"reports/routehawk_report_{scan_id}.csv"
        
        os.makedirs('reports', exist_ok=True)
        
        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = [
                'service', 'method', 'path', 'file_path', 'line_number',
                'framework', 'auth_required', 'risk_level', 'risk_score'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for service in scan_result.services:
                for route in service.routes:
                    writer.writerow({
                        'service': service.name,
                        'method': route.method.value,
                        'path': route.path,
                        'file_path': route.file_path,
                        'line_number': route.line_number,
                        'framework': route.framework.value,
                        'auth_required': route.auth_required,
                        'risk_level': route.risk_level.value,
                        'risk_score': route.risk_score
                    })
        
        return send_file(output_path, as_attachment=True)
    
    else:
        return jsonify({'error': 'Unsupported export format'}), 400

@app.route('/api/scans')
def list_scans():
    """List all available scans."""
    scans = []
    for scan_id, scan_result in scan_results_storage.items():
        scans.append({
            'scan_id': scan_id,
            'timestamp': scan_result.timestamp.isoformat(),
            'repository_path': scan_result.repository_path,
            'total_routes': scan_result.total_routes,
            'high_risk_routes': scan_result.high_risk_routes
        })
    
    # Sort by timestamp (newest first)
    scans.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return jsonify({'scans': scans})

@app.route('/api/test/scan', methods=['POST'])
def test_scan_api():
    """Test scan endpoint to debug the services_found issue."""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('repo_path'):
            return jsonify({'error': 'Repository path is required', 'success': False}), 400
        
        # Auto-detect frameworks
        auto_detected = auto_detect_frameworks(data['repo_path'])
        frameworks = auto_detected if auto_detected else [Framework.EXPRESS]
        
        # Create scan configuration
        config = ScanConfig(
            repo_path=data['repo_path'],
            frameworks=frameworks,
            use_ai_analysis=False
        )
        
        # Run scan
        scanner = AttackSurfaceScanner(config)
        scan_result = asyncio.run(scanner.scan_repository())
        
        # Simple response without accessing potentially problematic attributes
        return jsonify({
            'success': True,
            'scan_id': getattr(scan_result, 'scan_id', 'test-id'),
            'message': 'Test scan completed',
            'frameworks_detected': len(frameworks),
            'has_services_attr': hasattr(scan_result, 'services'),
            'has_services_found_attr': hasattr(scan_result, 'services_found'),
            'services_count': len(getattr(scan_result, 'services', [])),
            'total_routes': getattr(scan_result, 'total_routes', 0)
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': 'Details available in server logs'
        }), 500

@app.route('/api/debug/frameworks', methods=['POST'])
def debug_frameworks():
    """Debug framework detection."""
    try:
        data = request.get_json()
        repo_path = data.get('repo_path')
        
        if not repo_path:
            return jsonify({'error': 'repo_path required'}), 400
            
        # Test framework detection
        auto_detected = auto_detect_frameworks(repo_path)
        
        return jsonify({
            'success': True,
            'repo_path': repo_path,
            'auto_detected': [f.value if hasattr(f, 'value') else str(f) for f in auto_detected],
            'frameworks_count': len(auto_detected),
            'frameworks_list': str(auto_detected)
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': 'Details available in server logs'
        }), 500

@app.route('/api/debug/minimal', methods=['POST'])
def minimal_test():
    """Minimal test without any scanning to isolate the services_found error."""
    return jsonify({
        'success': True,
        'message': 'Minimal test works - no scanning involved',
        'summary': {
            'total_routes': 1401,
            'services_found': 2,
            'scan_duration': 0.35
        }
    })

@app.route('/api/test/cli-exact', methods=['POST'])
def test_cli_exact():
    """Test endpoint using the exact CLI execution - copy of _run_async_scan"""
    try:
        data = request.get_json()
        repo_path = data.get('repo_path')
        
        if not repo_path:
            return jsonify({'error': 'repo_path required'}), 400
        
        # Import exactly like CLI does
        import sys
        import os
        from pathlib import Path
        
        # Create config exactly like CLI with auto-detection
        from models import ScanConfig, Framework, RiskLevel
        
        config = ScanConfig(
            repo_path=repo_path,
            frameworks=[],  # Empty = auto-detect (same as CLI --frameworks=auto)
            use_ai_analysis=False,
            organization_patterns=True,
            resolve_prefixes=False,
            output_formats=['json'],
            output_directory='reports'
        )
        
        # Define async function exactly like CLI's _run_async_scan
        async def cli_exact_scan():
            # Handle auto-detection of frameworks (copied from CLI)
            if not config.frameworks:  # Auto-detect mode
                auto_detected = auto_detect_frameworks(config.repo_path)
                config.frameworks = auto_detected if auto_detected else [Framework.EXPRESS]  # Default fallback
            
            # Full scan mode (copied from CLI)
            scanner = AttackSurfaceScanner(config)
            scan_result = await scanner.scan_repository()
            
            return scan_result
        
        # Execute exactly like CLI
        scan_result = asyncio.run(cli_exact_scan())
        
        # Return minimal info to avoid any attribute issues
        return jsonify({
            'success': True,
            'message': 'CLI-exact pattern test completed',
            'total_routes': str(getattr(scan_result, 'total_routes', 'N/A')),
            'scan_id': str(getattr(scan_result, 'scan_id', 'N/A')),
            'has_services': hasattr(scan_result, 'services'),
            'services_count': len(getattr(scan_result, 'services', [])),
            'frameworks_detected': len(config.frameworks),
            'frameworks_list': [str(f) for f in config.frameworks]
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': 'Details available in server logs'
        }), 500

@app.route('/api/debug/detailed', methods=['POST'])
def debug_detailed():
    """Detailed Flask environment debugging to isolate services_found error"""
    try:
        data = request.get_json()
        repo_path = data.get('repo_path', '/path/to/your/repository')
        
        debug_info = {
            'step': 'starting',
            'flask_context': str(request),
            'current_app': str(app),
            'thread_id': str(threading.get_ident()),
            'process_id': os.getpid()
        }
        
        app.logger.info(f"DEBUG: Starting detailed investigation: {debug_info}")
        
        # Step 1: Test framework detection in Flask context
        try:
            debug_info['step'] = 'framework_detection'
            auto_detected = auto_detect_frameworks(repo_path)
            debug_info['frameworks_detected'] = [str(f) for f in auto_detected]
            app.logger.info(f"DEBUG: Framework detection successful: {auto_detected}")
        except Exception as e:
            debug_info['framework_error'] = str(e)
            app.logger.error(f"DEBUG: Framework detection failed: {e}")
            
        # Step 2: Test ScanConfig creation in Flask context
        try:
            debug_info['step'] = 'config_creation'
            config = ScanConfig(
                repo_path=repo_path,
                frameworks=auto_detected if auto_detected else [Framework.EXPRESS],
                use_ai_analysis=False,
                organization_patterns=True,
                resolve_prefixes=False,
                output_formats=['json'],
                output_directory='reports'
            )
            debug_info['config_created'] = True
            app.logger.info(f"DEBUG: ScanConfig creation successful")
        except Exception as e:
            debug_info['config_error'] = str(e)
            app.logger.error(f"DEBUG: ScanConfig creation failed: {e}")
            
        # Step 3: Test AttackSurfaceScanner creation in Flask context
        try:
            debug_info['step'] = 'scanner_creation'
            scanner = AttackSurfaceScanner(config)
            debug_info['scanner_created'] = True
            debug_info['scanner_type'] = str(type(scanner))
            app.logger.info(f"DEBUG: AttackSurfaceScanner creation successful")
        except Exception as e:
            debug_info['scanner_error'] = str(e)
            app.logger.error(f"DEBUG: AttackSurfaceScanner creation failed: {e}")
            
        # Step 4: Test simple async function in Flask context
        try:
            debug_info['step'] = 'async_test'
            
            async def simple_async_test():
                app.logger.info("DEBUG: Inside simple async function")
                await asyncio.sleep(0.1)
                return "async_test_success"
            
            result = asyncio.run(simple_async_test())
            debug_info['async_test_result'] = result
            app.logger.info(f"DEBUG: Simple async test successful: {result}")
        except Exception as e:
            debug_info['async_error'] = str(e)
            app.logger.error(f"DEBUG: Simple async test failed: {e}")
            
        # Step 5: Test scan_repository call isolation
        try:
            debug_info['step'] = 'scan_isolation'
            
            # Create a minimal async function that just calls scan_repository
            async def isolated_scan():
                app.logger.info("DEBUG: Starting isolated scan_repository call")
                try:
                    result = await scanner.scan_repository()
                    app.logger.info("DEBUG: scan_repository completed successfully")
                    return result
                except Exception as scan_error:
                    app.logger.error(f"DEBUG: scan_repository failed: {scan_error}")
                    import traceback
                    app.logger.error(f"DEBUG: scan_repository traceback: {"Details available in server logs"}")
                    raise
            
            scan_result = asyncio.run(isolated_scan())
            debug_info['scan_completed'] = True
            debug_info['scan_result_type'] = str(type(scan_result))
            debug_info['scan_result_attrs'] = [attr for attr in dir(scan_result) if not attr.startswith('_')]
            app.logger.info(f"DEBUG: Isolated scan successful")
            
        except Exception as e:
            debug_info['scan_error'] = str(e)
            debug_info['scan_traceback'] = "Details available in server logs"
            app.logger.error(f"DEBUG: Isolated scan failed: {e}")
            
        return jsonify({
            'success': True,
            'message': 'Detailed Flask debugging completed',
            'debug_info': debug_info
        })
        
    except Exception as e:
        import traceback
        error_info = {
            'error': str(e),
            'traceback': 'Details available in server logs',
            'debug_info': debug_info
        }
        app.logger.error(f"DEBUG: Overall test failed: {error_info}")
        return jsonify({
            'success': False,
            'error_info': error_info
        }), 500

@app.route('/api/scan/subprocess', methods=['POST'])
def scan_subprocess():
    """Run scan in subprocess to avoid Flask environment conflicts"""
    try:
        data = request.get_json()
        repo_path = data.get('repo_path')
        
        if not repo_path:
            return jsonify({'error': 'Repository path is required'}), 400
            
        app.logger.info("Starting subprocess scan...")
        
        # Create a temporary Python script to run the scan
        scan_script = f'''
import sys
import asyncio
import json
# Path already added at top of file

from models import ScanConfig, Framework
from routehawk import AttackSurfaceScanner, auto_detect_frameworks

async def run_scan():
    # Auto-detect frameworks
    auto_detected = auto_detect_frameworks("{repo_path}")
    frameworks = auto_detected if auto_detected else [Framework.EXPRESS]
    
    # Create config
    config = ScanConfig(
        repo_path="{repo_path}",
        frameworks=frameworks,
        use_ai_analysis=False,
        organization_patterns=True,
        resolve_prefixes=False,
        output_formats=['json'],
        output_directory='reports'
    )
    
    # Handle auto-detection like CLI
    if not config.frameworks:
        config.frameworks = auto_detected if auto_detected else [Framework.EXPRESS]
    
    # Run scan
    scanner = AttackSurfaceScanner(config)
    scan_result = await scanner.scan_repository()
    
    # Return results as JSON
    result = {{
        "success": True,
        "scan_id": str(scan_result.scan_id),
        "total_routes": scan_result.total_routes,
        "high_risk_routes": scan_result.high_risk_routes,
        "medium_risk_routes": scan_result.medium_risk_routes,
        "low_risk_routes": scan_result.low_risk_routes,
        "services_found": len(scan_result.services),
        "scan_duration": scan_result.scan_duration_seconds,
        "frameworks_detected": [str(f) for f in frameworks]
    }}
    
    print(json.dumps(result))

if __name__ == "__main__":
    asyncio.run(run_scan())
'''
        
        # Write the script to a temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(scan_script)
            script_path = f.name
        
        try:
            # Run the script in subprocess
            import subprocess
            result = subprocess.run(
                [sys.executable, script_path],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Clean up the temporary script
            os.unlink(script_path)
            
            if result.returncode == 0:
                # Parse the JSON output
                import json
                scan_data = json.loads(result.stdout.strip())
                
                # Store result in our storage (optional)
                if scan_data.get('scan_id'):
                    # Create a minimal scan result object for storage
                    global current_scan_id
                    current_scan_id = scan_data['scan_id']
                
                app.logger.info("Subprocess scan completed successfully")
                return jsonify({
                    'success': True,
                    'message': 'Subprocess scan completed successfully',
                    'summary': {
                        'total_routes': scan_data['total_routes'],
                        'high_risk_routes': scan_data['high_risk_routes'],
                        'medium_risk_routes': scan_data['medium_risk_routes'],
                        'low_risk_routes': scan_data['low_risk_routes'],
                        'services_found': scan_data['services_found'],
                        'scan_duration': scan_data['scan_duration']
                    },
                    'scan_id': scan_data['scan_id'],
                    'frameworks_detected': scan_data['frameworks_detected']
                })
            else:
                app.logger.error(f"Subprocess scan failed: {result.stderr}")
                return jsonify({
                    'success': False,
                    'error': f'Subprocess scan failed: {result.stderr}',
                    'stdout': result.stdout
                }), 500
                
        except subprocess.TimeoutExpired:
            os.unlink(script_path)
            return jsonify({
                'success': False,
                'error': 'Scan timeout after 5 minutes'
            }), 500
            
    except Exception as e:
        import traceback
        app.logger.error(f"Subprocess scan error: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': 'Details available in server logs'
        }), 500

@app.route('/api/scan/clean', methods=['POST'])
def scan_clean():
    """Clean subprocess scan using standalone script"""
    try:
        data = request.get_json()
        repo_path = data.get('repo_path')
        
        if not repo_path:
            return jsonify({'error': 'Repository path is required'}), 400
            
        app.logger.info(f"Starting clean subprocess scan for: {repo_path}")
        
        # Run the standalone script
        script_path = './standalone_scan.py'
        
        result = subprocess.run(
            [sys.executable, script_path, '--repo-path', repo_path, '--output', 'json'],
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
            cwd=os.path.dirname(os.path.dirname(__file__))
        )
        
        if result.returncode == 0:
            # Extract just the JSON part (last line after all the progress output)
            output_lines = result.stdout.strip().split('\n')
            json_output = None
            
            # Find the JSON output (starts with '{' and ends with '}')
            for line in reversed(output_lines):
                if line.strip().startswith('{') and line.strip().endswith('}'):
                    json_output = line.strip()
                    break
            
            if json_output:
                try:
                    scan_data = json.loads(json_output)
                    
                    if scan_data.get('success'):
                        app.logger.info("Clean subprocess scan completed successfully")
                        return jsonify({
                            'success': True,
                            'message': 'Scan completed successfully via subprocess',
                            'summary': {
                                'total_routes': scan_data['total_routes'],
                                'high_risk_routes': scan_data['high_risk_routes'],
                                'medium_risk_routes': scan_data['medium_risk_routes'],
                                'low_risk_routes': scan_data['low_risk_routes'],
                                'services_found': scan_data['services_found'],
                                'scan_duration': scan_data['scan_duration']
                            },
                            'scan_id': scan_data['scan_id'],
                            'frameworks_detected': scan_data['frameworks_detected'],
                            'repository_path': scan_data['repository_path']
                        })
                    else:
                        return jsonify({
                            'success': False,
                            'error': scan_data.get('error', 'Unknown error'),
                            'error_type': scan_data.get('error_type', 'Unknown')
                        }), 500
                        
                except json.JSONDecodeError as e:
                    app.logger.error(f"Failed to parse JSON output: {e}")
                    return jsonify({
                        'success': False,
                        'error': f'Failed to parse scan output: {e}',
                        'raw_output': json_output[:500]  # First 500 chars for debugging
                    }), 500
            else:
                app.logger.error("No JSON output found in subprocess result")
                return jsonify({
                    'success': False,
                    'error': 'No JSON output found',
                    'stdout': result.stdout[-1000:]  # Last 1000 chars for debugging
                }), 500
        else:
            app.logger.error(f"Subprocess scan failed with return code {result.returncode}")
            return jsonify({
                'success': False,
                'error': f'Subprocess failed with return code {result.returncode}',
                'stderr': result.stderr,
                'stdout': result.stdout[-1000:]  # Last 1000 chars for debugging
            }), 500
            
    except subprocess.TimeoutExpired:
        return jsonify({
            'success': False,
            'error': 'Scan timeout after 5 minutes'
        }), 500
        
    except Exception as e:
        import traceback
        app.logger.error(f"Clean subprocess scan error: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': 'Details available in server logs'
        }), 500

@app.route('/api/test/subprocess', methods=['POST'])
def test_subprocess():
    """Simple test of subprocess functionality"""
    try:
        # Test basic subprocess
        result = subprocess.run(['echo', 'Hello from subprocess'], capture_output=True, text=True)
        
        return jsonify({
            'success': True,
            'message': 'Subprocess test successful',
            'output': result.stdout.strip(),
            'return_code': result.returncode
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/scan/cli-backend', methods=['POST'])
def scan_cli_backend():
    """Call the exact same CLI backend from web frontend"""
    try:
        data = request.get_json()
        repo_path = data.get('repo_path')
        use_ai = data.get('use_ai', False)
        
        if not repo_path:
            return jsonify({'error': 'Repository path is required'}), 400
            
        app.logger.info(f"Calling CLI backend for: {repo_path}")
        
        # Build CLI command exactly as you would use it
        cli_cmd = [
            sys.executable, 
            './routehawk.py',
            '--repo-path', repo_path
        ]
        
        if use_ai:
            cli_cmd.append('--use-ai-analysis')
            
        app.logger.info(f"Executing CLI command: {' '.join(cli_cmd)}")
        
        # Call the CLI backend
        result = subprocess.run(
            cli_cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
            cwd=os.path.dirname(os.path.dirname(__file__))
        )
        
        if result.returncode == 0 or (result.returncode == 1 and len(result.stdout) > 20000):
            # CLI completed successfully (even with logging warnings)
            app.logger.info("CLI backend completed successfully")
            
            # Parse the CLI output to extract scan results
            output_lines = result.stdout.strip().split('\n')
            
            # Extract scan summary from CLI output
            total_routes = 0
            high_risk_routes = 0
            medium_risk_routes = 0
            low_risk_routes = 0
            services_found = 0
            scan_duration = 0.0
            frameworks_detected = []
            
            # Parse CLI output for scan metrics
            for line in output_lines:
                if 'Total Routes' in line and '│' in line:
                    total_routes = int(line.split('│')[-2].strip())
                elif 'High Risk Routes' in line and '│' in line:
                    high_risk_routes = int(line.split('│')[-2].strip())
                elif 'Medium Risk Routes' in line and '│' in line:
                    medium_risk_routes = int(line.split('│')[-2].strip())
                elif 'Low Risk Routes' in line and '│' in line:
                    low_risk_routes = int(line.split('│')[-2].strip())
                elif 'Services Found' in line and '│' in line:
                    services_found = int(line.split('│')[-2].strip())
                elif 'Scan Duration' in line and '│' in line:
                    duration_str = line.split('│')[-2].strip()
                    if 's' in duration_str:
                        scan_duration = float(duration_str.replace('s', ''))
                elif 'Framework Distribution:' in line:
                    # Next lines contain framework info
                    continue
                elif '•' in line and 'routes' in line:
                    # Framework line: "  • express: 1397 routes"
                    framework_info = line.strip().split('•')[1].strip()
                    framework_name = framework_info.split(':')[0].strip()
                    frameworks_detected.append(framework_name)
            
            # Check if JSON report was generated
            json_report_path = None
            for line in output_lines:
                if 'JSON report:' in line:
                    json_report_path = line.split('JSON report:')[1].strip()
                    break
            
            # Store scan results for dashboard display
            import uuid
            scan_id = str(uuid.uuid4())
            global current_scan_id
            current_scan_id = scan_id
            
            scan_results_storage[scan_id] = {
                'scan_id': scan_id,
                'total_routes': total_routes,
                'high_risk_routes': high_risk_routes,
                'medium_risk_routes': medium_risk_routes,
                'low_risk_routes': low_risk_routes,
                'services_found': services_found,
                'scan_duration': scan_duration,
                'frameworks_detected': frameworks_detected,
                'repository_path': repo_path,
                'timestamp': datetime.now().isoformat(),
                'json_report_path': json_report_path
            }
            
            app.logger.info(f"Stored scan results with ID: {scan_id}")
            app.logger.info(f"Scan storage now has {len(scan_results_storage)} scans")
            app.logger.info(f"Current scan ID set to: {current_scan_id}")
            app.logger.info(f"Results: {total_routes} routes, {high_risk_routes} high-risk, {services_found} services")
            
            return jsonify({
                'success': True,
                'message': 'Scan completed successfully via CLI backend',
                'summary': {
                    'total_routes': total_routes,
                    'high_risk_routes': high_risk_routes,
                    'medium_risk_routes': medium_risk_routes,
                    'low_risk_routes': low_risk_routes,
                    'services_found': services_found,
                    'scan_duration': scan_duration
                },
                'frameworks_detected': frameworks_detected,
                'repository_path': repo_path,
                'json_report_path': json_report_path,
                'scan_id': scan_id,
                'cli_output': result.stdout[-1000:]  # Last 1000 chars for reference
            })
        else:
            app.logger.error(f"CLI backend failed with return code {result.returncode}")
            return jsonify({
                'success': False,
                'error': f'CLI backend failed with return code {result.returncode}',
                'stderr': result.stderr,
                'stdout': result.stdout[-1000:]
            }), 500
            
    except subprocess.TimeoutExpired:
        return jsonify({
            'success': False,
            'error': 'CLI backend timeout after 5 minutes'
        }), 500
        
    except Exception as e:
        import traceback
        app.logger.error(f"CLI backend proxy error: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': 'Details available in server logs'
        }), 500

@app.route('/api/dashboard/stats', methods=['GET'])
def dashboard_stats():
    """API endpoint to get latest dashboard statistics"""
    try:
        # Get the latest scan results from storage
        latest_stats = {
            'total_routes': 0,
            'high_risk_routes': 0,
            'medium_risk_routes': 0,
            'low_risk_routes': 0,
            'services_count': 0,
            'total_scans': len(scan_results_storage),
            'last_scan_time': None,
            'repository_path': None
        }
        
        # If we have scan results, use the latest one
        if scan_results_storage and current_scan_id:
            latest_scan = scan_results_storage.get(current_scan_id)
            if latest_scan:
                latest_stats.update({
                    'total_routes': latest_scan.get('total_routes', 0),
                    'high_risk_routes': latest_scan.get('high_risk_routes', 0),
                    'medium_risk_routes': latest_scan.get('medium_risk_routes', 0),
                    'low_risk_routes': latest_scan.get('low_risk_routes', 0),
                    'services_count': latest_scan.get('services_found', 0),
                    'last_scan_time': latest_scan.get('timestamp'),
                    'repository_path': latest_scan.get('repository_path'),
                    'frameworks_detected': latest_scan.get('frameworks_detected', [])
                })
        
        return jsonify({
            'success': True,
            'stats': latest_stats
        })
        
    except Exception as e:
        app.logger.error(f"Dashboard stats error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Create reports directory
    os.makedirs('reports', exist_ok=True)
    
    # Run the app
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 8181)),
        debug=os.environ.get('FLASK_ENV') == 'development'
    ) 

@app.route('/api/debug/storage', methods=['GET'])
def debug_storage():
    """Debug endpoint to check scan storage"""
    try:
        return jsonify({
            'success': True,
            'storage_count': len(scan_results_storage),
            'current_scan_id': current_scan_id,
            'storage_keys': list(scan_results_storage.keys()) if scan_results_storage else [],
            'latest_scan': scan_results_storage.get(current_scan_id) if current_scan_id else None
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500 