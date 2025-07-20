"""
Enhanced gRPC detector for Protocol Buffer services and RPC method definitions.
Handles .proto files, service definitions, and enterprise gRPC patterns.
"""

import re
import logging
from typing import List, Optional, Dict, Any
from pathlib import Path

from .base_detector import BaseDetector
from models import RouteInfo, Framework, HTTPMethod, AuthType, RouteParameter, SecurityFinding, RiskLevel


class GRPCDetector(BaseDetector):
    """
    gRPC service detector with comprehensive pattern recognition for enterprise environments.
    """
    
    def __init__(self):
        super().__init__(Framework.GRPC)
        self.logger = logging.getLogger(__name__)
        
        # gRPC service definition patterns
        self.service_patterns = [
            # Basic service definitions
            r'service\s+(\w+)\s*\{',
            
            # RPC method definitions
            r'rpc\s+(\w+)\s*\(\s*(\w+)\s*\)\s*returns\s*\(\s*(\w+)\s*\)',
            r'rpc\s+(\w+)\s*\(\s*stream\s+(\w+)\s*\)\s*returns\s*\(\s*(\w+)\s*\)',
            r'rpc\s+(\w+)\s*\(\s*(\w+)\s*\)\s*returns\s*\(\s*stream\s+(\w+)\s*\)',
            r'rpc\s+(\w+)\s*\(\s*stream\s+(\w+)\s*\)\s*returns\s*\(\s*stream\s+(\w+)\s*\)',
        ]
        
        # Message type patterns
        self.message_patterns = [
            r'message\s+(\w+)\s*\{',
            r'enum\s+(\w+)\s*\{',
        ]
        
        # gRPC authentication and security patterns
        self.auth_patterns = [
            # gRPC authentication
            r'google\.rpc\.context\.AttributeContext',
            r'grpc\.metadata',
            r'authorization',
            r'bearer[_-]?token',
            r'api[_-]?key',
            
            # Enterprise gRPC auth
            r'grpc[_-]?auth',
            r'service[_-]?auth',
            r'jwt[_-]?interceptor',
            r'auth[_-]?interceptor',
        ]
        
        # Enterprise gRPC service types
        self.service_types = {
            'translation': ['translate', 'language', 'locale', 'i18n', 'localization'],
            'user': ['user', 'customer', 'member', 'profile', 'account'],
            'merchant': ['merchant', 'store', 'seller', 'vendor'],
            'payment': ['payment', 'billing', 'transaction', 'financial'],
            'auth': ['auth', 'identity', 'security', 'oauth', 'sso'],
            'notification': ['notification', 'message', 'email', 'sms'],
            'data': ['data', 'analytics', 'reporting', 'metrics'],
            'integration': ['integration', 'connector', 'sync', 'webhook'],
        }
        
        # gRPC method risk patterns
        self.risk_patterns = {
            'high': [
                'delete', 'remove', 'destroy', 'terminate',
                'create', 'insert', 'add', 'register',
                'update', 'modify', 'change', 'edit',
                'transfer', 'payment', 'charge', 'refund',
                'admin', 'manage', 'control'
            ],
            'medium': [
                'get', 'list', 'search', 'query', 'find',
                'validate', 'verify', 'check', 'confirm',
                'notify', 'send', 'publish', 'subscribe'
            ],
            'low': [
                'ping', 'health', 'status', 'version',
                'info', 'describe', 'schema'
            ]
        }
    
    def detect_routes(self, file_path: str, content: str) -> List[RouteInfo]:
        """Detect gRPC service methods from .proto files and service definitions."""
        routes = []
        
        if not self._is_grpc_file(file_path, content):
            return routes
        
        # Extract service definitions
        services = self._extract_services(content)
        
        for service in services:
            service_routes = self._extract_service_routes(service, file_path, content)
            routes.extend(service_routes)
        
        return routes
    
    def _is_grpc_file(self, file_path: str, content: str) -> bool:
        """Check if this is a gRPC-related file."""
        # Check file extension
        if file_path.endswith('.proto'):
            return True
        
        # Check for gRPC indicators in content
        grpc_indicators = [
            r'syntax\s*=\s*[\'"`]proto[23][\'"`]',
            r'service\s+\w+\s*\{',
            r'rpc\s+\w+',
            r'import.*\.proto',
            r'package\s+[\w.]+',
            r'@grpc/grpc-js',
            r'grpc-tools',
            r'protobufjs'
        ]
        
        return any(re.search(indicator, content, re.IGNORECASE) for indicator in grpc_indicators)
    
    def _extract_services(self, content: str) -> List[Dict[str, Any]]:
        """Extract service definitions from proto content."""
        services = []
        
        # Find service blocks
        service_pattern = re.compile(
            r'service\s+(\w+)\s*\{([^}]*)\}',
            re.DOTALL | re.IGNORECASE
        )
        
        for match in service_pattern.finditer(content):
            service_name = match.group(1)
            service_body = match.group(2)
            line_number = content[:match.start()].count('\n') + 1
            
            services.append({
                'name': service_name,
                'body': service_body,
                'line_number': line_number,
                'full_match': match.group(0)
            })
        
        return services
    
    def _extract_service_routes(self, service: Dict[str, Any], file_path: str, content: str) -> List[RouteInfo]:
        """Extract RPC methods from a service definition."""
        routes = []
        
        # RPC method pattern
        rpc_pattern = re.compile(
            r'rpc\s+(\w+)\s*\(\s*(stream\s+)?(\w+)\s*\)\s*returns\s*\(\s*(stream\s+)?(\w+)\s*\)',
            re.IGNORECASE
        )
        
        for match in rpc_pattern.finditer(service['body']):
            method_name = match.group(1)
            input_stream = match.group(2) is not None
            input_type = match.group(3)
            output_stream = match.group(4) is not None
            output_type = match.group(5)
            
            # Calculate line number within the service
            service_start_line = service['line_number']
            method_line_offset = service['body'][:match.start()].count('\n')
            line_number = service_start_line + method_line_offset
            
            # Create route info
            route = self._create_grpc_route_info(
                service_name=service['name'],
                method_name=method_name,
                input_type=input_type,
                output_type=output_type,
                input_stream=input_stream,
                output_stream=output_stream,
                file_path=file_path,
                line_number=line_number,
                content=content
            )
            
            if route:
                routes.append(route)
        
        return routes
    
    def _create_grpc_route_info(self, service_name: str, method_name: str, 
                               input_type: str, output_type: str,
                               input_stream: bool, output_stream: bool,
                               file_path: str, line_number: int, content: str) -> Optional[RouteInfo]:
        """Create RouteInfo for a gRPC method."""
        
        # Construct gRPC path
        grpc_path = f"/{service_name}/{method_name}"
        
        # Determine HTTP method equivalent
        http_method = self._determine_http_method(method_name)
        
        # Detect authentication
        auth_type = self._detect_grpc_authentication(content, service_name, method_name)
        
        # Extract parameters
        parameters = self._extract_grpc_parameters(input_type, content)
        
        # Assess risk
        risk_level, risk_score, risk_factors = self._assess_grpc_risk(
            service_name, method_name, input_stream, output_stream, auth_type
        )
        
        # Classify service type
        service_type = self._classify_grpc_service(service_name, method_name)
        
        # Create streaming metadata
        streaming_info = {
            'input_stream': input_stream,
            'output_stream': output_stream,
            'bidirectional': input_stream and output_stream
        }
        
        return RouteInfo(
            method=http_method,
            path=grpc_path,
            file_path=file_path,
            line_number=line_number,
            framework=Framework.GRPC,
            service_name=service_name,
            handler_name=method_name,
            auth_required=auth_type != AuthType.NONE,
            auth_type=auth_type,
            parameters=parameters,
            risk_level=risk_level,
            risk_score=risk_score,
            risk_factors=risk_factors,
            organization_package_usage=[],  # Could be enhanced later
            feature_flags=[],
            database_access=[],
            metadata={
                'grpc_service': service_name,
                'grpc_method': method_name,
                'input_type': input_type,
                'output_type': output_type,
                'service_type': service_type,
                **streaming_info
            }
        )
    
    def _determine_http_method(self, method_name: str) -> HTTPMethod:
        """Map gRPC method name to equivalent HTTP method."""
        method_lower = method_name.lower()
        
        # CREATE operations
        if any(keyword in method_lower for keyword in ['create', 'add', 'insert', 'register']):
            return HTTPMethod.POST
        
        # UPDATE operations
        if any(keyword in method_lower for keyword in ['update', 'modify', 'edit', 'change']):
            return HTTPMethod.PUT
        
        # DELETE operations  
        if any(keyword in method_lower for keyword in ['delete', 'remove', 'destroy']):
            return HTTPMethod.DELETE
        
        # READ operations (default)
        return HTTPMethod.GET
    
    def _detect_grpc_authentication(self, content: str, service_name: str, method_name: str) -> AuthType:
        """Detect authentication requirements for gRPC methods."""
        
        # Check for authentication patterns in the file
        for pattern in self.auth_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                if 'jwt' in pattern.lower():
                    return AuthType.JWT
                elif 'api' in pattern.lower() or 'key' in pattern.lower():
                    return AuthType.API_KEY
                else:
                    return AuthType.UNKNOWN
        
        # Service-specific auth inference
        service_lower = service_name.lower()
        method_lower = method_name.lower()
        
        # Admin/management services typically require auth
        if any(keyword in service_lower for keyword in ['admin', 'management', 'internal']):
            return AuthType.UNKNOWN
        
        # Payment/financial services require auth
        if any(keyword in service_lower for keyword in ['payment', 'billing', 'financial']):
            return AuthType.UNKNOWN
        
        # Public health/status checks typically don't require auth
        if any(keyword in method_lower for keyword in ['health', 'ping', 'status']):
            return AuthType.NONE
        
        return AuthType.UNKNOWN  # Default to requiring auth for security
    
    def _extract_grpc_parameters(self, input_type: str, content: str) -> List[RouteParameter]:
        """Extract parameters from gRPC message types."""
        parameters = []
        
        # Find the message definition for input_type
        message_pattern = re.compile(
            rf'message\s+{re.escape(input_type)}\s*\{{([^}}]*)\}}',
            re.DOTALL | re.IGNORECASE
        )
        
        match = message_pattern.search(content)
        if match:
            message_body = match.group(1)
            
            # Extract field definitions
            field_pattern = re.compile(
                r'(\w+)\s+(\w+)\s*=\s*\d+',
                re.IGNORECASE
            )
            
            for field_match in field_pattern.finditer(message_body):
                field_type = field_match.group(1)
                field_name = field_match.group(2)
                
                parameters.append(RouteParameter(
                    name=field_name,
                    type=field_type,
                    required=True,  # gRPC fields are typically required unless marked optional
                    location="body"
                ))
        
        return parameters
    
    def _assess_grpc_risk(self, service_name: str, method_name: str, 
                         input_stream: bool, output_stream: bool, 
                         auth_type: AuthType) -> tuple[RiskLevel, float, List[str]]:
        """Assess risk level for gRPC methods."""
        risk_score = 0.0
        risk_factors = []
        
        method_lower = method_name.lower()
        service_lower = service_name.lower()
        
        # Method-based risk
        for risk_level, methods in self.risk_patterns.items():
            if any(keyword in method_lower for keyword in methods):
                if risk_level == 'high':
                    risk_score += 0.4
                    risk_factors.append(f"high_risk_grpc_method_{method_lower}")
                elif risk_level == 'medium':
                    risk_score += 0.2
                    risk_factors.append(f"medium_risk_grpc_method")
                break
        
        # Service-based risk
        critical_services = ['payment', 'billing', 'financial', 'admin', 'management']
        if any(keyword in service_lower for keyword in critical_services):
            risk_score += 0.3
            risk_factors.append(f"critical_grpc_service_{service_lower}")
        
        # Streaming risk (can be resource intensive)
        if input_stream or output_stream:
            risk_score += 0.1
            risk_factors.append("grpc_streaming_method")
        
        # Authentication risk
        if auth_type == AuthType.NONE:
            risk_score += 0.3
            risk_factors.append("no_grpc_authentication")
        elif auth_type == AuthType.UNKNOWN:
            risk_score += 0.2
            risk_factors.append("unknown_grpc_auth")
        
        # Ensure score is within bounds
        risk_score = max(0.0, min(1.0, risk_score))
        
        # Convert to risk level
        if risk_score >= 0.7:
            return RiskLevel.HIGH, risk_score, risk_factors
        elif risk_score >= 0.4:
            return RiskLevel.MEDIUM, risk_score, risk_factors
        else:
            return RiskLevel.LOW, risk_score, risk_factors
    
    def _classify_grpc_service(self, service_name: str, method_name: str) -> str:
        """Classify the type of gRPC service."""
        service_lower = service_name.lower()
        method_lower = method_name.lower()
        
        for service_type, keywords in self.service_types.items():
            if any(keyword in service_lower or keyword in method_lower for keyword in keywords):
                return service_type
        
        return 'general' 