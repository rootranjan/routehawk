import logging
from typing import List, Dict, Any, Optional
from models import RouteInfo, RiskLevel, AuthType, HTTPMethod

class RiskScorer:
    """
    Calculate and assign risk scores to routes based on various factors.
    Now supports enterprise configuration and custom risk rules.
    """
    
    def __init__(self, organization_patterns: Dict[str, Any] = None, config_manager = None):
        self.logger = logging.getLogger(__name__)
        self.organization_patterns = organization_patterns or {}
        self.config_manager = config_manager
        
        # Risk multipliers for different factors
        self.method_scores = {
            HTTPMethod.GET: 1,
            HTTPMethod.POST: 3,
            HTTPMethod.PUT: 3,
            HTTPMethod.PATCH: 3,
            HTTPMethod.DELETE: 4,
            HTTPMethod.HEAD: 1,
            HTTPMethod.OPTIONS: 1,
            HTTPMethod.ALL: 4        # High risk for wildcard methods that accept all HTTP methods
        }
        
        self.auth_scores = {
            AuthType.NONE: 4,
            AuthType.SESSION: 2,
            AuthType.JWT: 1,
            AuthType.API_KEY: 2,
            AuthType.OAUTH: 1
        }
    
    def calculate_risk_score(self, route: RouteInfo) -> float:
        """
        Calculate a comprehensive risk score for a route.
        Now includes custom risk rules from enterprise configuration.
        """
        score = 0.0
        
        # Base method score
        score += self.method_scores.get(route.method, 2)
        
        # Authentication score
        score += self.auth_scores.get(route.auth_type, 3)
        
        # Path-based scoring
        score += self._calculate_path_risk(route.path)
        
        # Parameter-based scoring
        score += self._calculate_parameter_risk(route.parameters)
        
        # Apply custom risk rules from enterprise configuration
        if self.config_manager:
            score = self._apply_custom_risk_rules(route, score)
        
        return score
    
    def _apply_custom_risk_rules(self, route: RouteInfo, base_score: float) -> float:
        """
        Apply custom risk rules from enterprise configuration.
        
        Args:
            route: Route information
            base_score: Base calculated risk score
            
        Returns:
            Modified risk score after applying custom rules
        """
        try:
            # Convert route to dict format for rule matching
            route_dict = {
                'path': route.path,
                'method': route.method.value if hasattr(route.method, 'value') else str(route.method),
                'framework': route.framework.value if hasattr(route.framework, 'value') else str(route.framework),
                'auth_type': route.auth_type.value if hasattr(route.auth_type, 'value') else str(route.auth_type),
                'authenticated': route.authenticated,
                'parameters': route.parameters,
                'file_path': route.file_path
            }
            
            # Apply custom risk rules
            modified_route = self.config_manager.apply_custom_risk_rules(route_dict)
            
            # Update route with applied rules if any
            if 'applied_rules' in modified_route:
                self.logger.debug(f"Applied custom rules {modified_route['applied_rules']} to route {route.path}")
                
                # Add applied rules to route metadata if not already present
                if not hasattr(route, 'metadata'):
                    route.metadata = {}
                route.metadata['applied_custom_rules'] = modified_route['applied_rules']
            
            # Return modified score
            return modified_route.get('risk_score', base_score)
            
        except Exception as e:
            self.logger.error(f"Error applying custom risk rules: {e}")
            return base_score
    
    def calculate_risk(self, route: RouteInfo) -> tuple[float, List[str]]:
        """
        Calculate risk score and return both score and list of risk factors.
        """
        risk_factors = []
        score = 0.0
        
        # Base method score
        method_score = self.method_scores.get(route.method, 2)
        score += method_score
        if method_score >= 3:
            risk_factors.append(f"High-risk HTTP method: {route.method}")
        
        # Authentication score
        auth_score = self.auth_scores.get(route.auth_type, 3)
        score += auth_score
        if route.auth_type == AuthType.NONE:
            risk_factors.append("No authentication required")
        elif auth_score >= 2:
            risk_factors.append(f"Authentication type: {route.auth_type}")
        
        # Path-based scoring
        path_score = self._calculate_path_risk(route.path)
        score += path_score
        if path_score > 0:
            if '/admin' in route.path.lower():
                risk_factors.append("Admin endpoint")
            if '/api/v1' in route.path.lower():
                risk_factors.append("API v1 endpoint")
            if any(sensitive in route.path.lower() for sensitive in ['payment', 'user', 'auth', 'internal']):
                risk_factors.append("Sensitive path detected")
        
        # Parameter-based scoring
        param_score = self._calculate_parameter_risk(route.parameters)
        score += param_score
        if param_score > 0:
            risk_factors.append("Unvalidated parameters")
        
        # Security findings impact
        findings_score = self._calculate_security_findings_risk(route.security_findings)
        score += findings_score
        if findings_score > 0:
            risk_factors.append("Security vulnerabilities found")
        
        # Organization-specific scoring
        org_score = self._calculate_organization_specific_risk(route)
        score += org_score
        if org_score > 0:
            risk_factors.append("Organization-specific risk factors")
        
        return min(score, 10.0), risk_factors
    
    def assign_risk_level(self, score: float) -> RiskLevel:
        """
        Convert numeric score to risk level.
        """
        if score >= 7.0:
            return RiskLevel.HIGH
        elif score >= 4.0:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_path_risk(self, path: str) -> float:
        """
        Enhanced path risk calculation based on enterprise patterns.
        """
        score = 0.0
        path_lower = path.lower()
        
        # Critical business paths (highest risk)
        critical_patterns = {
            'payment': 3.0, 'billing': 3.0, 'financial': 3.0, 'transaction': 2.5,
            'cashier': 2.8, 'money': 2.5, 'refund': 2.3, 'invoice': 2.0
        }
        
        # Administrative and internal paths (high risk)  
        admin_patterns = {
            'admin': 2.5, 'internal': 2.3, 'debug': 2.8, 'test': 1.8, 'dev': 1.8,
            'management': 2.0, 'console': 2.2, 'control': 2.0
        }
        
        # User and authentication paths (medium-high risk)
        user_patterns = {
            'user': 1.8, 'customer': 1.8, 'member': 1.8, 'profile': 1.5,
            'account': 1.8, 'auth': 2.0, 'login': 1.8, 'oauth': 1.5,
            'security': 1.8, 'token': 1.5, 'session': 1.3
        }
        
        # Business entity paths (medium risk)
        business_patterns = {
            'merchant': 1.5, 'store': 1.3, 'seller': 1.3, 'vendor': 1.3,
            'partner': 1.2, 'organization': 1.2
        }
        
        # API and service paths (context-dependent risk)
        api_patterns = {
            'api/gateway': 1.8, 'api/internal': 2.0, 'api/admin': 2.5,
            'api/private': 1.8, 'api/v1': 0.5, 'api/public': 0.3,
            'gateway': 1.5, 'proxy': 1.3, 'forward': 1.2
        }
        
        # Data operation patterns (method-dependent risk)
        operation_patterns = {
            'delete': 2.0, 'remove': 2.0, 'destroy': 2.5, 'terminate': 2.3,
            'create': 1.3, 'add': 1.3, 'insert': 1.3, 'register': 1.5,
            'update': 1.5, 'modify': 1.5, 'edit': 1.3, 'change': 1.3
        }
        
        # Check all pattern categories
        pattern_groups = [
            critical_patterns, admin_patterns, user_patterns, 
            business_patterns, api_patterns, operation_patterns
        ]
        
        for patterns in pattern_groups:
            for pattern, risk_value in patterns.items():
                if pattern in path_lower:
                    score += risk_value
        
        # Enterprise-specific high-risk patterns
        enterprise_patterns = [
            '/whale/',  # Browser extension prefix
            '/sbgo-',   # Service-specific prefix  
            '/coral-',  # Member service prefix
            'unified-', # Unified service patterns
        ]
        
        for pattern in enterprise_patterns:
            if pattern in path_lower:
                    score += 1.0
        
        # File operation risks
        file_patterns = {
            'upload': 1.8, 'download': 1.3, 'file': 1.5, 'document': 1.2,
            'export': 1.3, 'import': 1.5, 'backup': 1.8, 'restore': 2.0
        }
        
        for pattern, risk_value in file_patterns.items():
            if pattern in path_lower:
                score += risk_value
        
        # Parameter indicators (additional risk)
        param_indicators = ['{', '<', ':', '*']
        if any(indicator in path for indicator in param_indicators):
            score += 0.3  # Path parameters add risk
        
        # Versioning considerations
        if '/v1/' in path_lower:
            score += 0.2  # Legacy API versions may have more vulnerabilities
        elif '/v2/' in path_lower or '/v3/' in path_lower:
            score += 0.1  # Newer versions typically more secure
        
        # Health and status endpoints (lower risk)
        if any(pattern in path_lower for pattern in ['health', 'status', 'ping', 'version']):
            score = max(0, score - 1.0)  # Reduce risk for health checks
        
        return min(score, 5.0)  # Cap path risk contribution
    
    def _calculate_parameter_risk(self, parameters: List) -> float:
        """
        Calculate risk based on route parameters.
        """
        score = 0.0
        
        # Risk increases with number of parameters
        score += len(parameters) * 0.2
        
        for param in parameters:
            # Required parameters are riskier
            if param.required:
                score += 0.3
            # Parameters without validation are riskier
            if not param.validation:
                score += 0.2
        
        return score
    
    def _calculate_security_findings_risk(self, findings: List) -> float:
        """
        Calculate risk based on security findings.
        """
        score = 0.0
        
        severity_scores = {
            'critical': 3.0,
            'high': 2.0,
            'medium': 1.0,
            'low': 0.5
        }
        
        for finding in findings:
            severity = finding.severity.lower()
            score += severity_scores.get(severity, 1.0)
        
        return score
    
    def _calculate_organization_specific_risk(self, route: RouteInfo) -> float:
        """
        Enhanced organization-specific risk based on enterprise business patterns.
        """
        score = 0.0
        path_lower = route.path.lower()
        
        # Service type-based risk assessment
        service_risk_multipliers = {
            'core': 1.5,      # Core platform services
            'payment': 2.5,   # Financial/payment services
            'merchant': 1.8,  # Merchant-facing services  
            'user': 1.6,      # User/member services
            'web': 1.2,       # Web platform services
            'data': 1.3,      # Analytics/reporting
            'integration': 1.4, # External integrations
            'platform': 1.1,   # Infrastructure services
        }
        
        # Check if service type information is available in metadata
        if hasattr(route, 'metadata') and route.metadata:
            service_type = route.metadata.get('service_type')
            if service_type in service_risk_multipliers:
                score += service_risk_multipliers[service_type]
        
        # Business criticality patterns
        critical_business_patterns = {
            # Core business operations
            'cashier': 2.8, 'transaction': 2.5, 'payment': 2.8, 'billing': 2.5,
            'financial': 2.6, 'refund': 2.3, 'chargeback': 2.5,
            
            # User and merchant data
            'profile': 1.8, 'account': 2.0, 'member': 1.8, 'customer': 1.8,
            'merchant': 2.0, 'store': 1.6, 'seller': 1.6,
            
            # Administrative operations
            'admin': 2.2, 'management': 2.0, 'internal': 2.1, 'debug': 2.5,
            'console': 2.0, 'control': 2.0,
            
            # External integrations (potential attack vectors)
            'shopify': 1.8, 'salesforce': 1.6, 'webhook': 1.5, 'callback': 1.5,
            'integration': 1.4, 'connector': 1.3, 'sync': 1.2,
            
            # Authentication and security
            'auth': 2.0, 'oauth': 1.8, 'token': 1.6, 'session': 1.4,
            'security': 1.8, 'verify': 1.5, 'validate': 1.3,
        }
        
        for pattern, risk_multiplier in critical_business_patterns.items():
            if pattern in path_lower:
                score += risk_multiplier
        
        # Enterprise architecture patterns
        architecture_patterns = {
            # Microservice patterns
            'unified-': 1.5,   # Unified services (payment, merchant)
            'group-': 1.3,     # Group services (core, consumer, merchant)
            'coral-': 1.4,     # Member service suite
            'sbgo-': 1.6,      # Business-specific services
            'westeros-': 1.2,  # Legacy web core
            'orca-': 1.1,      # Search services
            
            # API gateway patterns
            'api-gateway': 1.8, 'gateway': 1.5, 'proxy': 1.3,
            'forward': 1.2, 'route': 1.2,
            
            # Multi-app patterns
            '/apps/': 1.3, 'main.ts': 1.2, 'bootstrap': 1.1,
        }
        
        for pattern, risk_multiplier in architecture_patterns.items():
            if pattern in path_lower:
                score += risk_multiplier
        
        # Technology stack risk assessment
        if hasattr(route, 'metadata') and route.metadata:
            tech_stack = route.metadata.get('technology_stack', [])
            
            # High-risk technology combinations
            if 'grpc' in [tech.lower() for tech in tech_stack]:
                score += 0.8  # gRPC services may have different security models
            if 'kafka' in [tech.lower() for tech in tech_stack]:
                score += 0.6  # Message queues can be attack vectors
            if any('external' in tech.lower() for tech in tech_stack):
                score += 1.0  # External API integrations
        
        # Business logic complexity indicators
        complexity_indicators = [
            'workflow', 'process', 'pipeline', 'queue', 'batch',
            'scheduler', 'cron', 'job', 'task', 'worker'
        ]
        
        for indicator in complexity_indicators:
            if indicator in path_lower:
                score += 0.5  # Complex business logic = higher risk
        
        # File and data operations
        data_operations = {
            'upload': 1.8, 'download': 1.3, 'export': 1.5, 'import': 1.6,
            'backup': 1.8, 'restore': 2.0, 'migrate': 1.7, 'sync': 1.2
        }
        
        for operation, risk_value in data_operations.items():
            if operation in path_lower:
                score += risk_value
        
        # Organization package usage (if available)
        if hasattr(route, 'organization_package_usage') and route.organization_package_usage:
            score += len(route.organization_package_usage) * 0.3  # More org packages = higher risk
        
        return min(score, 8.0)  # Cap organization-specific risk
    
    def analyze_risk_distribution(self, routes: List[RouteInfo]) -> Dict[str, Any]:
        """
        Analyze the risk distribution across all routes.
        """
        if not routes:
            return {}
        
        scores = [self.calculate_risk_score(route) for route in routes]
        risk_levels = [self.assign_risk_level(score) for score in scores]
        
        # Count by risk level
        risk_counts = {
            'high': sum(1 for level in risk_levels if level == RiskLevel.HIGH),
            'medium': sum(1 for level in risk_levels if level == RiskLevel.MEDIUM),
            'low': sum(1 for level in risk_levels if level == RiskLevel.LOW)
        }
        
        # Calculate statistics
        avg_score = sum(scores) / len(scores)
        max_score = max(scores)
        min_score = min(scores)
        
        return {
            'total_routes': len(routes),
            'risk_distribution': risk_counts,
            'average_score': round(avg_score, 2),
            'max_score': round(max_score, 2),
            'min_score': round(min_score, 2),
            'risk_percentage': {
                'high': round((risk_counts['high'] / len(routes)) * 100, 1),
                'medium': round((risk_counts['medium'] / len(routes)) * 100, 1),
                'low': round((risk_counts['low'] / len(routes)) * 100, 1)
            }
        }
    
    def get_highest_risk_routes(self, routes: List[RouteInfo], limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get the highest risk routes with their scores.
        """
        route_scores = []
        for route in routes:
            score = self.calculate_risk_score(route)
            route_scores.append({
                'route': route,
                'score': score,
                'risk_level': self.assign_risk_level(score)
            })
        
        # Sort by score descending
        route_scores.sort(key=lambda x: x['score'], reverse=True)
        
        return route_scores[:limit] 