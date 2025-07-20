"""
Organization Pattern Analyzer for Attack Surface Discovery

Analyzes code to detect organization-specific patterns, services, packages,
architectural patterns, and business logic across the codebase.
"""

import re
import logging
import yaml
import os
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from models import SecurityFinding, RiskLevel


class ServiceType(Enum):
    """Types of organization services"""
    USER = "user"
    AUTH = "auth"
    PAYMENT = "payment"
    ADMIN = "admin"
    API = "api"
    INTERNAL = "internal"
    PUBLIC = "public"
    INFRASTRUCTURE = "infrastructure"
    UNKNOWN = "unknown"


@dataclass
class OrganizationService:
    """Represents a detected organization service"""
    name: str
    type: ServiceType
    path: str
    confidence: float
    patterns_matched: List[str]
    business_domain: str
    risk_level: RiskLevel


@dataclass
class OrganizationPattern:
    """Represents a detected organization-specific pattern"""
    pattern_type: str
    pattern_name: str
    file_path: str
    line_number: int
    matched_text: str
    confidence: float
    business_context: str


class OrganizationPatternAnalyzer:
    """Analyzer for detecting organization-specific patterns and services"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        
        # Load organization patterns configuration
        self.config = self._load_config(config_path)
        
        # Service identification patterns (configurable via config)
        self.service_patterns = self.config.get('service_patterns', {
            'user': {
                'name_patterns': [
                    r'user-[a-zA-Z-]+',
                    r'user_[a-zA-Z_]+',
                    r'services/user',
                    r'@[a-zA-Z0-9-]+/user-[a-zA-Z-]+'
                ],
                'path_patterns': [
                    r'user-service/',
                    r'user-[^/]+/',
                    r'services/user'
                ],
                'code_patterns': [
                    r'UserModule',
                    r'UserService',
                    r'UserController'
                ],
                'business_domain': 'User Management',
                'risk_level': RiskLevel.MEDIUM
            },
            'auth': {
                'name_patterns': [
                    r'auth-[a-zA-Z-]+',
                    r'authentication',
                    r'@[a-zA-Z0-9-]+/auth-[a-zA-Z-]+'
                ],
                'path_patterns': [
                    r'auth-service/',
                    r'authentication/',
                    r'services/auth'
                ],
                'code_patterns': [
                    r'AuthModule',
                    r'AuthService',
                    r'AuthController',
                    r'AuthGuard'
                ],
                'business_domain': 'Authentication',
                'risk_level': RiskLevel.HIGH
            },
            'payment': {
                'name_patterns': [
                    r'payment-[a-zA-Z-]+',
                    r'billing-[a-zA-Z-]+',
                    r'financial-[a-zA-Z-]+'
                ],
                'path_patterns': [
                    r'payment-service/',
                    r'billing/',
                    r'financial/'
                ],
                'code_patterns': [
                    r'PaymentModule',
                    r'PaymentService',
                    r'BillingService',
                    r'TransactionService'
                ],
                'business_domain': 'Financial Services',
                'risk_level': RiskLevel.CRITICAL
            }
        })
        
        # High-risk business logic patterns (configurable)
        self.business_logic_patterns = self.config.get('business_logic_patterns', {
            'payment_processing': {
                'patterns': [
                    r'processPayment\s*\(',
                    r'chargeCard\s*\(',
                    r'refundPayment\s*\(',
                    r'transferFunds\s*\(',
                    r'validatePayment\s*\(',
                    r'paymentGateway\.',
                    r'stripeCharge\s*\(',
                    r'paypalPayment\s*\('
                ],
                'risk_level': RiskLevel.CRITICAL,
                'description': 'Payment processing logic'
            },
            'user_data_processing': {
                'patterns': [
                    r'encryptPII\s*\(',
                    r'decryptPII\s*\(',
                    r'hashPassword\s*\(',
                    r'validateEmail\s*\(',
                    r'getUserProfile\s*\(',
                    r'updateUserData\s*\(',
                    r'deleteUserAccount\s*\(',
                    r'exportUserData\s*\('
                ],
                'risk_level': RiskLevel.HIGH,
                'description': 'User data processing logic'
            },
            'admin_operations': {
                'patterns': [
                    r'adminOnly\s*\(',
                    r'superUserAccess\s*\(',
                    r'elevatedPermissions\s*\(',
                    r'systemOverride\s*\(',
                    r'adminPanel\.',
                    r'backdoorAccess\s*\(',
                    r'debugAccess\s*\('
                ],
                'risk_level': RiskLevel.HIGH,
                'description': 'Administrative operations'
            }
        })
        
        # Organization package patterns (configurable)
        self.package_patterns = self.config.get('package_patterns', {
            'internal_packages': [
                r'@[a-zA-Z0-9-]+/[a-zA-Z-]+',  # Generic scoped packages
                r'internal-[a-zA-Z-]+',
                r'common-[a-zA-Z-]+'
            ],
            'external_integrations': [
                r'@google-cloud/',
                r'@aws-sdk/',
                r'stripe',
                r'paypal',
                r'twilio',
                r'sendgrid',
                r'redis',
                r'mongodb'
            ]
        })
        
        # Database and data access patterns
        self.data_patterns = {
            'database_access': [
                r'prisma\.',
                r'typeorm\.',
                r'mongoose\.',
                r'sequelize\.',
                r'knex\.',
                r'db\.',
                r'database\.',
                r'connection\.',
                r'query\(',
                r'execute\(',
                r'findOne\(',
                r'findMany\(',
                r'create\(',
                r'update\(',
                r'delete\(',
                r'upsert\('
            ],
            'cache_access': [
                r'redis\.',
                r'cache\.',
                r'memcached\.',
                r'get\(',
                r'set\(',
                r'del\(',
                r'expire\(',
                r'ttl\('
            ],
            'external_apis': [
                r'axios\.',
                r'fetch\(',
                r'request\(',
                r'http\.',
                r'https\.',
                r'RestClient\.',
                r'ApiClient\.',
                r'webhooks?\.',
                r'callback\s*\('
            ]
        }

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load organization patterns configuration from YAML file"""
        if not config_path:
            # Default to config/organization_patterns.yaml
            config_path = Path(__file__).parent.parent / "config" / "organization_patterns.yaml"
            
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f)
        except Exception as e:
            self.logger.warning(f"Could not load organization config from {config_path}: {e}")
            
        return {}

    def analyze_organization_patterns(self, file_path: str, content: str) -> Dict[str, Any]:
        """
        Analyze organization-specific patterns in the given file
        
        Args:
            file_path: Path to the file being analyzed
            content: File content as string
            
        Returns:
            Dictionary containing organization pattern analysis results
        """
        results = {
            'services': [],
            'patterns': [],
            'business_logic': [],
            'packages': [],
            'security_findings': [],
            'organization_score': 0.0,
            'risk_level': RiskLevel.LOW
        }
        
        try:
            # Detect organization services
            services = self._detect_services(file_path, content)
            results['services'] = services
            
            # Detect business logic patterns
            business_logic = self._detect_business_logic(file_path, content)
            results['business_logic'] = business_logic
            
            # Detect package usage
            packages = self._detect_packages(content)
            results['packages'] = packages
            
            # Detect general patterns
            patterns = self._detect_patterns(file_path, content)
            results['patterns'] = patterns
            
            # Analyze security implications
            security_findings = self._analyze_security_implications(
                services, business_logic, file_path
            )
            results['security_findings'] = security_findings
            
            # Calculate organization relevance score
            org_score = self._calculate_organization_score(
                services, patterns, business_logic, packages
            )
            results['organization_score'] = org_score
            
            # Determine overall risk level
            risk_level = self._determine_risk_level(services, business_logic)
            results['risk_level'] = risk_level
            
        except Exception as e:
            self.logger.error(f"Error analyzing organization patterns in {file_path}: {str(e)}")
            
        return results

    def _detect_services(self, file_path: str, content: str) -> List[OrganizationService]:
        """Detect organization services based on path and content patterns"""
        services = []
        
        for service_type, patterns in self.service_patterns.items():
            confidence = 0.0
            matched_patterns = []
            
            # Check path patterns
            for path_pattern in patterns.get('path_patterns', []):
                if re.search(path_pattern, file_path, re.IGNORECASE):
                    confidence += 0.4
                    matched_patterns.append(f"path:{path_pattern}")
                    
            # Check name patterns
            for name_pattern in patterns.get('name_patterns', []):
                if re.search(name_pattern, file_path, re.IGNORECASE):
                    confidence += 0.3
                    matched_patterns.append(f"name:{name_pattern}")
                    
            # Check code patterns
            for code_pattern in patterns.get('code_patterns', []):
                if re.search(code_pattern, content, re.IGNORECASE):
                    confidence += 0.3
                    matched_patterns.append(f"code:{code_pattern}")
                    
            # Create service if confidence is high enough
            if confidence >= 0.3 and matched_patterns:
                service = OrganizationService(
                    name=self._extract_service_name(file_path, service_type),
                    type=ServiceType(service_type) if service_type in [e.value for e in ServiceType] else ServiceType.UNKNOWN,
                    path=file_path,
                    confidence=min(confidence, 1.0),
                    patterns_matched=matched_patterns,
                    business_domain=patterns.get('business_domain', 'Unknown'),
                    risk_level=patterns.get('risk_level', RiskLevel.MEDIUM)
                )
                services.append(service)
                
        return services

    def _detect_business_logic(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Detect business logic patterns"""
        business_logic = []
        
        for logic_type, config in self.business_logic_patterns.items():
            for pattern in config['patterns']:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    
                    logic_item = {
                        'type': logic_type,
                        'pattern': match.group(0),
                        'file_path': file_path,
                        'line_number': line_number,
                        'risk_level': config['risk_level'],
                        'description': config['description'],
                        'context': self._extract_context(content, match.start(), match.end())
                    }
                    
                    business_logic.append(logic_item)
                    
        return business_logic

    def _detect_packages(self, content: str) -> Dict[str, List[str]]:
        """Detect package usage patterns"""
        packages = {
            'internal': [],
            'external': []
        }
        
        # Internal organization packages
        for pattern in self.package_patterns.get('internal_packages', []):
            matches = re.findall(pattern, content, re.IGNORECASE)
            packages['internal'].extend(matches)
            
        # External integrations
        for pattern in self.package_patterns.get('external_integrations', []):
            matches = re.findall(pattern, content, re.IGNORECASE)
            packages['external'].extend(matches)
            
        # Remove duplicates
        packages['internal'] = list(set(packages['internal']))
        packages['external'] = list(set(packages['external']))
        
        return packages

    def _detect_patterns(self, file_path: str, content: str) -> List[OrganizationPattern]:
        """Detect general organization patterns"""
        patterns = []
        
        # Database access patterns
        for pattern in self.data_patterns['database_access']:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                pattern_obj = OrganizationPattern(
                    pattern_type='database_access',
                    pattern_name=match.group(0),
                    file_path=file_path,
                    line_number=line_number,
                    matched_text=match.group(0),
                    confidence=0.7,
                    business_context='Data persistence and retrieval'
                )
                
                patterns.append(pattern_obj)
                
        # Cache access patterns
        for pattern in self.data_patterns['cache_access']:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                pattern_obj = OrganizationPattern(
                    pattern_type='cache_access',
                    pattern_name=match.group(0),
                    file_path=file_path,
                    line_number=line_number,
                    matched_text=match.group(0),
                    confidence=0.6,
                    business_context='Performance optimization and caching'
                )
                
                patterns.append(pattern_obj)
                
        # External API patterns
        for pattern in self.data_patterns['external_apis']:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                pattern_obj = OrganizationPattern(
                    pattern_type='external_api',
                    pattern_name=match.group(0),
                    file_path=file_path,
                    line_number=line_number,
                    matched_text=match.group(0),
                    confidence=0.8,
                    business_context='External service integration'
                )
                
                patterns.append(pattern_obj)
                
        return patterns

    def _analyze_security_implications(
        self, 
        services: List[OrganizationService], 
        business_logic: List[Dict[str, Any]], 
        file_path: str
    ) -> List[SecurityFinding]:
        """Analyze security implications of detected patterns"""
        findings = []
        
        # Check for high-risk service combinations
        for service in services:
            if service.type == ServiceType.PAYMENT:
                finding = SecurityFinding(
                    type="High-Risk Financial Service",
                    severity=RiskLevel.CRITICAL,
                    description=f"Financial service detected: {service.name}. Requires maximum security controls.",
                    recommendation="Implement comprehensive security controls including authentication, authorization, encryption, and audit logging."
                )
                findings.append(finding)
                
        # Check for risky business logic
        for logic in business_logic:
            if logic['risk_level'] == RiskLevel.CRITICAL:
                finding = SecurityFinding(
                    type="Critical Business Logic",
                    severity=RiskLevel.CRITICAL,
                    description=f"Critical business logic detected: {logic['description']}",
                    recommendation="Implement strict access controls, input validation, and audit logging for this functionality."
                )
                findings.append(finding)
                
        return findings

    def _calculate_organization_score(
        self, 
        services: List[OrganizationService], 
        patterns: List[OrganizationPattern], 
        business_logic: List[Dict[str, Any]], 
        packages: Dict[str, List[str]]
    ) -> float:
        """Calculate how organization-specific this file is (0.0 to 1.0)"""
        score = 0.0
        
        # Services contribute significantly
        if services:
            score += 0.4 * min(len(services) * 0.3, 1.0)
            
        # Internal packages are strong indicators
        if packages.get('internal', []):
            score += 0.3 * min(len(packages['internal']) * 0.2, 1.0)
            
        # Business logic patterns
        if business_logic:
            score += 0.2 * min(len(business_logic) * 0.1, 1.0)
            
        # General patterns
        if patterns:
            score += 0.1 * min(len(patterns) * 0.05, 1.0)
            
        return min(score, 1.0)

    def _determine_risk_level(
        self, 
        services: List[OrganizationService], 
        business_logic: List[Dict[str, Any]]
    ) -> RiskLevel:
        """Determine overall risk level based on detected patterns"""
        max_risk = RiskLevel.LOW
        
        # Check service risk levels
        for service in services:
            if service.risk_level.value > max_risk.value:
                max_risk = service.risk_level
                
        # Check business logic risk levels
        for logic in business_logic:
            if logic['risk_level'].value > max_risk.value:
                max_risk = logic['risk_level']
                
        return max_risk

    def _extract_service_name(self, file_path: str, service_type: str) -> str:
        """Extract service name from file path"""
        path_parts = file_path.split('/')
        
        for part in path_parts:
            if service_type in part.lower():
                return part
                
        # Fallback to directory name
        if len(path_parts) > 1:
            return path_parts[-2]
            
        return f"unknown-{service_type}-service"

    def _extract_context(self, content: str, start: int, end: int, window: int = 100) -> str:
        """Extract context around a match"""
        context_start = max(0, start - window)
        context_end = min(len(content), end + window)
        return content[context_start:context_end].strip()

    def is_organization_service(self, file_path: str) -> Tuple[bool, str]:
        """
        Quick check if a file path indicates an organization service
        
        Returns:
            Tuple of (is_organization_service, service_type)
        """
        # Check against configured service patterns
        for service_type, patterns in self.service_patterns.items():
            for pattern in patterns.get('path_patterns', []):
                if re.search(pattern, file_path, re.IGNORECASE):
                    return True, service_type
                    
        return False, ""

    def get_service_business_context(self, service_name: str) -> Dict[str, Any]:
        """Get business context for a service"""
        # This could be loaded from configuration or predefined mappings
        default_context = {
            'domain': 'Unknown',
            'criticality': 'MEDIUM',
            'data_types': []
        }
        
        # Check if we have specific configuration for this service
        service_config = self.config.get('service_contexts', {})
        return service_config.get(service_name, default_context)

    def analyze_architectural_patterns(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze architectural patterns specific to the organization"""
        patterns = {
            'microservice_patterns': [],
            'event_patterns': [],
            'integration_patterns': [],
            'data_patterns': []
        }
        
        # Microservice patterns
        microservice_indicators = [
            r'@Module\s*\(',
            r'@Controller\s*\(',
            r'@Service\s*\(',
            r'express\s*\(\s*\)',
            r'fastify\s*\(\s*\)',
            r'koa\s*\(\s*\)'
        ]
        
        for pattern in microservice_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                patterns['microservice_patterns'].append(pattern)
                
        # Event-driven patterns
        event_indicators = [
            r'EventEmitter',
            r'@EventPattern\s*\(',
            r'@MessagePattern\s*\(',
            r'publish\s*\(',
            r'subscribe\s*\(',
            r'kafka',
            r'rabbitmq',
            r'redis.*pub',
            r'event.*bus'
        ]
        
        for pattern in event_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                patterns['event_patterns'].append(pattern)
                
        return patterns 