#!/usr/bin/env python3
"""
Simple Web-CLI Bridge for RouteHawk
Provides a clean web interface that calls the CLI backend directly
This avoids all Flask environment conflicts while providing web accessibility
"""

import subprocess
import sys
import json
import os
import re
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import threading
import time

class RouteHawkHandler(BaseHTTPRequestHandler):
    def _validate_repo_path(self, repo_path: str) -> bool:
        """
        Validate repository path to prevent command injection and path traversal.
        
        Args:
            repo_path: User-provided repository path
            
        Returns:
            True if path is safe
        """
        if not repo_path:
            return False
        
        # Remove any shell metacharacters that could be used for injection
        dangerous_chars = ['|', '&', ';', '$', '`', '(', ')', '<', '>', '"', "'", '\\']
        if any(char in repo_path for char in dangerous_chars):
            return False
        
        # Ensure path exists and is a directory
        try:
            path = Path(repo_path).resolve()
            return path.exists() and path.is_dir()
        except (OSError, ValueError):
            return False
    
    def _sanitize_repo_path(self, repo_path: str) -> str:
        """
        Sanitize repository path for safe subprocess execution.
        
        Args:
            repo_path: User-provided repository path
            
        Returns:
            Sanitized path
        """
        # Convert to absolute path and resolve any .. components
        try:
            return str(Path(repo_path).resolve())
        except (OSError, ValueError):
            raise ValueError(f"Invalid repository path: {repo_path}")

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html = '''
<!DOCTYPE html>
<html>
<head>
    <title>RouteHawk Web-CLI Bridge</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .form-group { margin: 20px 0; }
        input[type="text"] { width: 500px; padding: 10px; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .results { margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px; }
        .loading { color: #007bff; }
        .success { color: #28a745; }
        .error { color: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🦅 RouteHawk Web-CLI Bridge</h1>
        <p>Direct interface to the CLI backend - No Flask conflicts!</p>
        
        <div class="form-group">
            <label for="repo_path">Repository Path:</label><br>
            <input type="text" id="repo_path" placeholder="/path/to/your/repository" value="/path/to/your/repository">
        </div>
        
        <div class="form-group">
            <label>
                <input type="checkbox" id="use_ai"> Use AI Analysis
            </label>
        </div>
        
        <button onclick="startScan()">🚀 Start CLI Scan</button>
        
        <div id="results" class="results" style="display: none;"></div>
    </div>
    
    <script>
        function startScan() {
            const repoPath = document.getElementById('repo_path').value;
            const useAI = document.getElementById('use_ai').checked;
            const resultsDiv = document.getElementById('results');
            
            if (!repoPath) {
                alert('Please enter a repository path');
                return;
            }
            
            resultsDiv.style.display = 'block';
            resultsDiv.innerHTML = '<div class="loading">🔍 Calling CLI backend...</div>';
            
            fetch('/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({repo_path: repoPath, use_ai: useAI})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    resultsDiv.innerHTML = `
                        <div class="success">
                            <h3>✅ CLI Backend Scan Complete!</h3>
                            <p><strong>📊 Total Routes:</strong> ${data.summary.total_routes}</p>
                            <p><strong>🚨 High Risk:</strong> ${data.summary.high_risk_routes}</p>
                            <p><strong>⚠️ Medium Risk:</strong> ${data.summary.medium_risk_routes}</p>
                            <p><strong>✅ Low Risk:</strong> ${data.summary.low_risk_routes}</p>
                            <p><strong>🔧 Services:</strong> ${data.summary.services_found}</p>
                            <p><strong>⏱️ Duration:</strong> ${data.summary.scan_duration}s</p>
                            <p><strong>🔍 Frameworks:</strong> ${data.frameworks_detected.join(', ')}</p>
                        </div>
                    `;
                } else {
                    resultsDiv.innerHTML = `<div class="error">❌ Error: ${data.error}</div>`;
                }
            })
            .catch(error => {
                resultsDiv.innerHTML = `<div class="error">❌ Network Error: ${error}</div>`;
            });
        }
    </script>
</body>
</html>
            '''
            self.wfile.write(html.encode())
            
        else:
            self.send_error(404)
    
    def do_POST(self):
        if self.path == '/scan':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode('utf-8'))
                
                repo_path = data.get('repo_path')
                use_ai = data.get('use_ai', False)
                
                if not repo_path:
                    self.send_error_response({'error': 'Repository path is required'})
                    return
                
                # ✅ SECURITY: Validate and sanitize repository path
                if not self._validate_repo_path(repo_path):
                    self.send_error_response({'error': 'Invalid repository path provided'})
                    return
                
                try:
                    sanitized_repo_path = self._sanitize_repo_path(repo_path)
                except ValueError as e:
                    self.send_error_response({'error': str(e)})
                    return
                
                # Build CLI command with sanitized input
                cli_cmd = [
                    sys.executable, 
                    './routehawk.py',
                    '--repo-path', sanitized_repo_path
                ]
                
                # ✅ SECURITY: Validate AI flag is boolean
                if isinstance(use_ai, bool) and use_ai:
                    cli_cmd.append('--use-ai-analysis')
                
                result = subprocess.run(
                    cli_cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    cwd=os.path.dirname(__file__)
                )
                
                if result.returncode == 0 or (result.returncode == 1 and len(result.stdout) > 20000):
                    # Parse CLI output
                    output_lines = result.stdout.strip().split('\n')
                    
                    total_routes = 0
                    high_risk_routes = 0
                    medium_risk_routes = 0
                    low_risk_routes = 0
                    services_found = 0
                    scan_duration = 0.0
                    frameworks_detected = []
                    
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
                        elif '•' in line and 'routes' in line:
                            framework_info = line.strip().split('•')[1].strip()
                            framework_name = framework_info.split(':')[0].strip()
                            frameworks_detected.append(framework_name)
                    
                    response = {
                        'success': True,
                        'message': 'CLI backend scan completed successfully',
                        'summary': {
                            'total_routes': total_routes,
                            'high_risk_routes': high_risk_routes,
                            'medium_risk_routes': medium_risk_routes,
                            'low_risk_routes': low_risk_routes,
                            'services_found': services_found,
                            'scan_duration': scan_duration
                        },
                        'frameworks_detected': frameworks_detected,
                        'repository_path': repo_path
                    }
                    
                    self.send_json_response(response)
                else:
                    self.send_error_response({
                        'error': f'CLI backend failed with return code {result.returncode}',
                        'stderr': result.stderr
                    })
                    
            except Exception as e:
                self.send_error_response({'error': str(e)})
        else:
            self.send_error(404)
    
    def send_json_response(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def send_error_response(self, error_data):
        self.send_response(500)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(error_data).encode())

def run_server(port=8182):
    server = HTTPServer(('localhost', port), RouteHawkHandler)
    print(f"🌐 RouteHawk Web-CLI Bridge running on http://localhost:{port}")
    print(f"🦅 Direct CLI backend access - No Flask conflicts!")
    print(f"📊 Visit http://localhost:{port} to start scanning")
    server.serve_forever()

if __name__ == '__main__':
    run_server() 