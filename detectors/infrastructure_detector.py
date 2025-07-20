#!/usr/bin/env python3
"""
Infrastructure Detector for RouteHawk
Detects infrastructure configuration files and patterns
"""

import re
from typing import List, Optional, Dict, Any
from pathlib import Path

from .base_detector import BaseDetector
from models import RouteInfo, Framework

class InfrastructureDetector(BaseDetector):
    """Detects infrastructure-related configurations and endpoints"""
    
    def __init__(self):
        super().__init__()
        self.framework = Framework.ASPNET_CORE  # Generic infrastructure framework
        
        # Infrastructure file patterns
        self.config_files = [
            # Container files
            'dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
            # Kubernetes files  
            'deployment.yml', 'deployment.yaml', 'service.yml', 'service.yaml',
            'ingress.yml', 'ingress.yaml', 'configmap.yml', 'configmap.yaml',
            # Cloud config
            'terraform.tf', 'terraform.tfvars', 'cloudformation.yml',
            # CI/CD files
            '.gitlab-ci.yml', '.github/workflows/*.yml', 'azure-pipelines.yml',
            # Generic monitoring config
            'monitoring.yml', 'monitoring.yaml',
            'config.yml', 'config.yaml'
        ]
        
        # Infrastructure endpoint patterns
        self.endpoint_patterns = [
            # Health checks
            r'(GET|POST)\s+[\'"`]/(health|healthz|ping|status)[\'"`]',
            # Metrics endpoints
            r'(GET|POST)\s+[\'"`]/(metrics|stats|info)[\'"`]',
            # Management endpoints
            r'(GET|POST)\s+[\'"`]/(admin|management|actuator)[\'"`]',
            # Debug endpoints
            r'(GET|POST)\s+[\'"`]/(debug|test|dev)[\'"`]'
        ]
        
    def can_handle_file(self, file_path: str, content: str) -> bool:
        """Check if this detector can handle the file"""
        file_path_lower = file_path.lower()
        
        # Check for infrastructure config files
        for pattern in self.config_files:
            if pattern.lower() in file_path_lower:
                return True
                
        # Check for infrastructure-related content
        content_lower = content.lower()
        infrastructure_indicators = [
            'apiversion:', 'kind:', 'metadata:',  # Kubernetes
            'version:', 'services:',              # Docker Compose
            'resource', 'provider',               # Terraform
            'stages:', 'script:',                 # CI/CD
            'server:', 'port:', 'host:'          # Generic config
        ]
        
        return any(indicator in content_lower for indicator in infrastructure_indicators)
    
    def extract_routes(self, file_path: str, content: str) -> List[RouteInfo]:
        """Extract infrastructure-related routes"""
        routes = []
        
        try:
            # Look for endpoint patterns in config files
            for pattern in self.endpoint_patterns:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    method = match.group(1).upper()
                    path = match.group(2)
                    
                    # Calculate line number
                    line_number = content[:match.start()].count('\n') + 1
                    
                    route = RouteInfo(
                        path=f"/{path}",
                        method=method,
                        framework=self.framework,
                        service_name=self._extract_service_name(file_path),
                        file_path=file_path,
                        line_number=line_number,
                        authenticated=False,  # Infrastructure endpoints often unauthenticated
                        risk_score=self._calculate_infrastructure_risk(path)
                    )
                    routes.append(route)
                    
            # Extract configuration-based routes
            config_routes = self._extract_config_routes(file_path, content)
            routes.extend(config_routes)
            
        except Exception as e:
            print(f"Error extracting infrastructure routes from {file_path}: {e}")
            
        return routes
    
    def _extract_config_routes(self, file_path: str, content: str) -> List[RouteInfo]:
        """Extract routes from configuration files"""
        routes = []
        
        try:
            # Look for URL/endpoint configurations
            url_patterns = [
                r'url[\'"`]?\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
                r'endpoint[\'"`]?\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
                r'path[\'"`]?\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
                r'route[\'"`]?\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]'
            ]
            
            for pattern in url_patterns:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    url = match.group(1)
                    
                    # Skip if not a valid path
                    if not url.startswith('/') or len(url) < 2:
                        continue
                        
                    line_number = content[:match.start()].count('\n') + 1
                    
                    route = RouteInfo(
                        path=url,
                        method="GET",  # Default for config-based routes
                        framework=self.framework,
                        service_name=self._extract_service_name(file_path),
                        file_path=file_path,
                        line_number=line_number,
                        authenticated=False,
                        risk_score=self._calculate_infrastructure_risk(url)
                    )
                    routes.append(route)
                    
        except Exception as e:
            print(f"Error extracting config routes from {file_path}: {e}")
            
        return routes
    
    def _extract_service_name(self, file_path: str) -> str:
        """Extract service name from file path"""
        path_parts = Path(file_path).parts
        
        # Look for common service directory indicators
        service_indicators = ['services', 'apps', 'src', 'config']
        
        for i, part in enumerate(path_parts):
            if part.lower() in service_indicators and i + 1 < len(path_parts):
                return path_parts[i + 1]
                
        # Fallback to parent directory
        return Path(file_path).parent.name or "infrastructure"
    
    def _calculate_infrastructure_risk(self, path: str) -> float:
        """Calculate risk score for infrastructure endpoints"""
        risk_score = 10.0  # Base score for infrastructure
        
        # High risk patterns
        high_risk_patterns = ['/admin', '/debug', '/dev', '/test']
        if any(pattern in path.lower() for pattern in high_risk_patterns):
            risk_score += 40.0
            
        # Medium risk patterns  
        medium_risk_patterns = ['/metrics', '/stats', '/info', '/management']
        if any(pattern in path.lower() for pattern in medium_risk_patterns):
            risk_score += 20.0
            
        # Low risk patterns
        low_risk_patterns = ['/health', '/ping', '/status']
        if any(pattern in path.lower() for pattern in low_risk_patterns):
            risk_score += 5.0
            
        return min(100.0, risk_score) 