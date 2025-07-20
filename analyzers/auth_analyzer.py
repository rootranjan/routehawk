"""
Authentication Analyzer for Attack Surface Discovery

Analyzes code to detect authentication patterns, authorization mechanisms,
and security controls across different frameworks and technologies.
"""

import re
import logging
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum

from models import AuthType, SecurityFinding, RiskLevel


class AuthMechanism(Enum):
    """Types of authentication mechanisms"""
    JWT = "jwt"
    OAUTH2 = "oauth2"
    BASIC_AUTH = "basic_auth"
    API_KEY = "api_key"
    SESSION = "session"
    BEARER_TOKEN = "bearer_token"
    DIGEST_AUTH = "digest_auth"
    MUTUAL_TLS = "mutual_tls"
    CUSTOM = "custom"
    NONE = "none"


@dataclass
class AuthPattern:
    """Represents an authentication pattern found in code"""
    mechanism: AuthMechanism
    pattern: str
    confidence: float
    description: str
    file_path: str
    line_number: int
    context: str


@dataclass
class AuthGuard:
    """Represents an authentication guard or middleware"""
    name: str
    type: str
    file_path: str
    line_number: int
    parameters: Dict[str, Any]
    framework: str


class AuthAnalyzer:
    """Analyzer for detecting authentication and authorization patterns"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Authentication patterns by framework
        self.auth_patterns = {
            'nestjs': {
                'guards': [
                    r'@UseGuards\s*\(\s*([^)]+)\)',
                    r'@AuthGuard\s*\(\s*([^)]+)\)',
                    r'JwtAuthGuard',
                    r'LocalAuthGuard',
                    r'GoogleOAuthGuard',
                    r'InternalAuthGuard',
                    r'RoleGuard',
                    r'AdminGuard',
                    r'CustomAuthGuard',
                    r'OrganizationAuthGuard'
                ],
                'decorators': [
                    r'@Public\s*\(\s*\)',
                    r'@Roles\s*\(\s*([^)]+)\)',
                    r'@Permissions\s*\(\s*([^)]+)\)',
                    r'@RequireAuth\s*\(\s*([^)]+)\)',
                    r'@ApiSecurity\s*\(\s*([^)]+)\)'
                ],
                'jwt': [
                    r'JwtService',
                    r'jwt\.sign\s*\(',
                    r'jwt\.verify\s*\(',
                    r'@nestjs/jwt',
                    r'PassportStrategy.*Jwt'
                ]
            },
            'express': {
                'middleware': [
                    r'passport\.',
                    r'express-session',
                    r'cookie-session',
                    r'express-jwt',
                    r'jsonwebtoken',
                    r'authenticate\s*\(',
                    r'isAuthenticated',
                    r'requireAuth',
                    r'checkAuth'
                ],
                'jwt': [
                    r'jwt\.sign\s*\(',
                    r'jwt\.verify\s*\(',
                    r'jwt\.decode\s*\(',
                    r'jsonwebtoken',
                    r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+'
                ],
                'session': [
                    r'req\.session',
                    r'session\(',
                    r'express-session',
                    r'connect-redis',
                    r'session-store'
                ]
            },
            'nextjs': {
                'auth': [
                    r'next-auth',
                    r'getServerSession',
                    r'unstable_getServerSession',
                    r'getSession\s*\(',
                    r'useSession\s*\(',
                    r'signIn\s*\(',
                    r'signOut\s*\(',
                    r'withAuth\s*\(',
                    r'NextAuth\s*\('
                ],
                'middleware': [
                    r'middleware\s*\(',
                    r'withIronSession',
                    r'iron-session',
                    r'getToken\s*\('
                ]
            },
            'go': {
                'auth': [
                    r'gin\.BasicAuth',
                    r'jwt-go',
                    r'golang-jwt',
                    r'oauth2',
                    r'context\.WithValue.*user',
                    r'Authorization.*Bearer',
                    r'middleware\.Auth',
                    r'checkAuth\s*\(',
                    r'validateToken\s*\('
                ],
                'session': [
                    r'gorilla/sessions',
                    r'session\.Values',
                    r'session\.Save',
                    r'session\.Get'
                ]
            },
            'python': {
                'django': [
                    r'@login_required',
                    r'@permission_required',
                    r'@user_passes_test',
                    r'IsAuthenticated',
                    r'IsAdminUser',
                    r'DjangoModelPermissions',
                    r'TokenAuthentication',
                    r'SessionAuthentication',
                    r'django\.contrib\.auth'
                ],
                'fastapi': [
                    r'Depends\s*\(\s*get_current_user',
                    r'HTTPBearer\s*\(',
                    r'OAuth2PasswordBearer',
                    r'Security\s*\(',
                    r'@require_auth',
                    r'@authenticated',
                    r'verify_token\s*\('
                ],
                'flask': [
                    r'@login_required',
                    r'flask_login',
                    r'current_user',
                    r'login_user\s*\(',
                    r'logout_user\s*\(',
                    r'@auth\.route',
                    r'Flask-Security'
                ]
            }
        }
        
        # Security vulnerability patterns
        self.vulnerability_patterns = {
            'weak_auth': [
                r'password\s*==\s*[\'"][^\'"]*[\'"]',  # Hardcoded passwords
                r'basic.*auth.*base64',  # Basic auth usage
                r'auth.*false',  # Disabled authentication
                r'no.*auth',  # No authentication
                r'skip.*auth',  # Skip authentication
                r'bypass.*auth'  # Bypass authentication
            ],
            'insecure_jwt': [
                r'jwt\.sign\s*\([^,]*,\s*[\'"][^\'"]*[\'"](?!.*expiresIn)',  # JWT without expiration
                r'jwt\.verify\s*\([^,]*,\s*[\'"][^\'"]{1,10}[\'"]',  # Weak JWT secret
                r'jwt.*none',  # JWT with no algorithm
                r'algorithm.*none'  # No algorithm specified
            ],
            'session_issues': [
                r'session.*secure.*false',  # Insecure session cookies
                r'session.*httpOnly.*false',  # Non-HTTP-only cookies
                r'session.*sameSite.*none',  # No SameSite protection
                r'maxAge.*undefined',  # No session expiration
                r'cookie.*secure.*false'  # Insecure cookies
            ],
            'cors_issues': [
                r'cors.*origin.*\*',  # Wildcard CORS origin
                r'Access-Control-Allow-Origin.*\*',  # Wildcard CORS header
                r'credentials.*true.*origin.*\*'  # Dangerous CORS configuration
            ]
        }
        
        # Organization-specific authentication patterns (configurable)
        self.organization_patterns = {
            'custom_auth': [
                r'CustomAuthGuard',
                r'OrganizationAuthGuard',
                r'@[a-zA-Z0-9-]+/auth'
            ],
            'organization_guards': [
                r'AdminAuthGuard',
                r'InternalAuthGuard',
                r'UserAuthGuard',
                r'ServiceAuthGuard'
            ],
            'organization_jwt': [
                r'JWT_SECRET',
                r'organization\.jwt',
                r'app\.token',
                r'service\.token'
            ]
        }

    def analyze_authentication(self, file_path: str, content: str, framework: str) -> Dict[str, Any]:
        """
        Analyze authentication patterns in the given file content
        
        Args:
            file_path: Path to the file being analyzed
            content: File content as string
            framework: Framework type (nestjs, express, etc.)
            
        Returns:
            Dictionary containing authentication analysis results
        """
        results = {
            'auth_mechanisms': [],
            'auth_guards': [],
            'security_findings': [],
            'auth_required': False,
            'auth_type': AuthType.NONE,
            'confidence': 0.0,
            'organization_auth': False
        }
        
        try:
            # Detect authentication mechanisms
            mechanisms = self._detect_auth_mechanisms(content, framework)
            results['auth_mechanisms'] = mechanisms
            
            # Detect authentication guards/middleware
            guards = self._detect_auth_guards(content, framework, file_path)
            results['auth_guards'] = guards
            
            # Check for security vulnerabilities
            findings = self._detect_security_issues(guards, mechanisms)
            results['security_findings'] = findings
            
            # Detect organization-specific authentication
            organization_auth = self._detect_organization_auth(content)
            results['organization_auth'] = organization_auth
            
            # Determine overall authentication status
            if mechanisms or guards:
                results['auth_required'] = True
                results['auth_type'] = self._determine_auth_type(mechanisms)
                results['confidence'] = self._calculate_confidence(mechanisms, guards)
                
        except Exception as e:
            self.logger.error(f"Error analyzing authentication in {file_path}: {str(e)}")
            
        return results

    def _detect_auth_mechanisms(self, content: str, framework: str) -> List[AuthPattern]:
        """Detect authentication mechanisms in code"""
        mechanisms = []
        
        framework_patterns = self.auth_patterns.get(framework.lower(), {})
        
        for category, patterns in framework_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    context = self._extract_context(content, match.start(), match.end())
                    
                    mechanism = self._classify_mechanism(pattern, match.group(0))
                    confidence = self._calculate_pattern_confidence(pattern, context)
                    
                    auth_pattern = AuthPattern(
                        mechanism=mechanism,
                        pattern=match.group(0),
                        confidence=confidence,
                        description=f"{category.title()} authentication pattern",
                        file_path="",  # Will be set by caller
                        line_number=line_number,
                        context=context
                    )
                    
                    mechanisms.append(auth_pattern)
                    
        return mechanisms

    def _detect_auth_guards(self, content: str, framework: str, file_path: str) -> List[AuthGuard]:
        """Detect authentication guards and middleware"""
        guards = []
        
        if framework.lower() == 'nestjs':
            # NestJS guards
            guard_patterns = [
                r'@UseGuards\s*\(\s*([^)]+)\)',
                r'class\s+(\w*Guard)\s+implements\s+CanActivate',
                r'@Injectable\s*\(\s*\)\s*export\s+class\s+(\w*Guard)'
            ]
            
            for pattern in guard_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    guard_name = match.group(1) if match.lastindex >= 1 else 'Unknown'
                    
                    guard = AuthGuard(
                        name=guard_name,
                        type='decorator' if '@UseGuards' in match.group(0) else 'class',
                        file_path=file_path,
                        line_number=line_number,
                        parameters=self._extract_guard_parameters(match.group(0)),
                        framework=framework
                    )
                    
                    guards.append(guard)
                    
        elif framework.lower() == 'express':
            # Express middleware
            middleware_patterns = [
                r'app\.use\s*\(\s*([^)]*auth[^)]*)\)',
                r'router\.use\s*\(\s*([^)]*auth[^)]*)\)',
                r'\.get\s*\(\s*[\'"][^\'"]*[\'"],\s*([^,]*auth[^,]*)',
                r'\.post\s*\(\s*[\'"][^\'"]*[\'"],\s*([^,]*auth[^,]*)'
            ]
            
            for pattern in middleware_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    middleware_name = match.group(1) if match.lastindex >= 1 else 'Unknown'
                    
                    guard = AuthGuard(
                        name=middleware_name.strip(),
                        type='middleware',
                        file_path=file_path,
                        line_number=line_number,
                        parameters={},
                        framework=framework
                    )
                    
                    guards.append(guard)
                    
        return guards

    def _detect_security_issues(self, content: str, file_path: str) -> List[SecurityFinding]:
        """Detect authentication-related security issues"""
        findings = []
        
        for issue_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    
                    finding = SecurityFinding(
                        type=self._get_finding_type(issue_type),
                        severity=self._get_severity_for_issue(issue_type),
                        description=self._get_finding_description(issue_type, match.group(0)),
                        recommendation=self._get_recommendation_for_issue(issue_type)
                    )
                    
                    findings.append(finding)
                    
        return findings

    def _detect_organization_auth(self, content: str) -> bool:
        """Detect organization-specific authentication patterns"""
        for category, patterns in self.organization_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
        return False

    def _classify_mechanism(self, pattern: str, match: str) -> AuthMechanism:
        """Classify the authentication mechanism based on pattern"""
        pattern_lower = pattern.lower()
        match_lower = match.lower()
        
        if 'jwt' in pattern_lower or 'jwt' in match_lower:
            return AuthMechanism.JWT
        elif 'oauth' in pattern_lower or 'oauth' in match_lower:
            return AuthMechanism.OAUTH2
        elif 'basic' in pattern_lower:
            return AuthMechanism.BASIC_AUTH
        elif 'session' in pattern_lower:
            return AuthMechanism.SESSION
        elif 'bearer' in pattern_lower:
            return AuthMechanism.BEARER_TOKEN
        elif 'api.*key' in pattern_lower or 'apikey' in match_lower:
            return AuthMechanism.API_KEY
        else:
            return AuthMechanism.CUSTOM

    def _determine_auth_type(self, mechanisms: List[AuthPattern]) -> AuthType:
        """Determine the primary authentication type"""
        if not mechanisms:
            return AuthType.NONE
            
        # Priority order for authentication types
        for mechanism in mechanisms:
            if mechanism.mechanism == AuthMechanism.JWT:
                return AuthType.JWT
            elif mechanism.mechanism == AuthMechanism.OAUTH2:
                return AuthType.OAUTH
            elif mechanism.mechanism == AuthMechanism.API_KEY:
                return AuthType.API_KEY
            elif mechanism.mechanism == AuthMechanism.SESSION:
                return AuthType.SESSION
            elif mechanism.mechanism == AuthMechanism.BASIC_AUTH:
                return AuthType.BASIC
                
        return AuthType.CUSTOM

    def _calculate_confidence(self, mechanisms: List[AuthPattern], guards: List[AuthGuard]) -> float:
        """Calculate confidence score for authentication detection"""
        if not mechanisms and not guards:
            return 0.0
            
        total_confidence = 0.0
        count = 0
        
        for mechanism in mechanisms:
            total_confidence += mechanism.confidence
            count += 1
            
        # Guards add to confidence
        for guard in guards:
            total_confidence += 0.8  # Guards are high confidence indicators
            count += 1
            
        return min(total_confidence / count, 1.0) if count > 0 else 0.0

    def _calculate_pattern_confidence(self, pattern: str, context: str) -> float:
        """Calculate confidence score for a specific pattern match"""
        confidence = 0.5  # Base confidence
        
        # Higher confidence for specific patterns
        if any(keyword in pattern.lower() for keyword in ['guard', 'auth', 'jwt', 'oauth']):
            confidence += 0.3
            
        # Higher confidence if in proper context
        if any(keyword in context.lower() for keyword in ['class', 'function', 'method', 'decorator']):
            confidence += 0.2
            
        return min(confidence, 1.0)

    def _extract_context(self, content: str, start: int, end: int, window: int = 100) -> str:
        """Extract context around a match"""
        context_start = max(0, start - window)
        context_end = min(len(content), end + window)
        return content[context_start:context_end].strip()

    def _extract_guard_parameters(self, guard_text: str) -> Dict[str, Any]:
        """Extract parameters from guard usage"""
        parameters = {}
        
        # Extract roles if present
        roles_match = re.search(r'Roles\s*\(\s*([^)]+)\)', guard_text)
        if roles_match:
            parameters['roles'] = roles_match.group(1)
            
        # Extract permissions if present  
        perms_match = re.search(r'Permissions\s*\(\s*([^)]+)\)', guard_text)
        if perms_match:
            parameters['permissions'] = perms_match.group(1)
            
        return parameters

    def _get_finding_type(self, issue_type: str) -> str:
        """Get security finding type from issue type"""
        type_mapping = {
            'weak_auth': 'Weak Authentication',
            'insecure_jwt': 'Insecure JWT Configuration',
            'session_issues': 'Session Security Issues',
            'cors_issues': 'CORS Misconfiguration'
        }
        return type_mapping.get(issue_type, 'Authentication Security Issue')

    def _get_severity_for_issue(self, issue_type: str) -> RiskLevel:
        """Get severity level for security issue type"""
        severity_mapping = {
            'weak_auth': RiskLevel.HIGH,
            'insecure_jwt': RiskLevel.HIGH,
            'session_issues': RiskLevel.MEDIUM,
            'cors_issues': RiskLevel.MEDIUM
        }
        return severity_mapping.get(issue_type, RiskLevel.MEDIUM)

    def _get_finding_description(self, issue_type: str, match: str) -> str:
        """Get description for security finding"""
        descriptions = {
            'weak_auth': f"Weak authentication pattern detected: {match}",
            'insecure_jwt': f"Insecure JWT configuration: {match}",
            'session_issues': f"Session security issue: {match}",
            'cors_issues': f"CORS misconfiguration: {match}"
        }
        return descriptions.get(issue_type, f"Authentication security issue: {match}")

    def _get_recommendation_for_issue(self, issue_type: str) -> str:
        """Get recommendation for security issue"""
        recommendations = {
            'weak_auth': "Implement strong authentication mechanisms like JWT or OAuth2",
            'insecure_jwt': "Use strong JWT secrets, set expiration times, and proper algorithms",
            'session_issues': "Configure secure session cookies with HttpOnly, Secure, and SameSite flags",
            'cors_issues': "Restrict CORS origins to specific domains and avoid wildcard origins"
        }
        return recommendations.get(issue_type, "Review and strengthen authentication configuration")

    def analyze_route_auth(self, route_info: Dict[str, Any], file_content: str) -> Dict[str, Any]:
        """
        Analyze authentication requirements for a specific route
        
        Args:
            route_info: Route information dictionary
            file_content: Content of the file containing the route
            
        Returns:
            Authentication analysis for the route
        """
        result = {
            'auth_required': False,
            'auth_type': AuthType.NONE,
            'guards': [],
            'roles': [],
            'permissions': [],
            'is_public': False,
            'security_findings': []
        }
        
        try:
            # Extract route context from file content
            route_context = self._extract_route_context(route_info, file_content)
            
            # Check for authentication decorators/middleware
            auth_info = self._analyze_route_auth_patterns(route_context)
            result.update(auth_info)
            
            # Check for organization-specific patterns
            if self._detect_organization_auth(route_context):
                result['organization_auth'] = True
                
        except Exception as e:
            self.logger.error(f"Error analyzing route authentication: {str(e)}")
            
        return result

    def _extract_route_context(self, route_info: Dict[str, Any], file_content: str) -> str:
        """Extract the context around a route definition"""
        # This would extract the relevant code section for the route
        # Implementation depends on the specific route_info structure
        return file_content  # Simplified for now

    def _analyze_route_auth_patterns(self, route_context: str) -> Dict[str, Any]:
        """Analyze authentication patterns in route context"""
        result = {
            'auth_required': False,
            'auth_type': AuthType.NONE,
            'guards': [],
            'roles': [],
            'is_public': False
        }
        
        # Check for public route markers
        if re.search(r'@Public\s*\(\s*\)', route_context):
            result['is_public'] = True
            return result
            
        # Check for authentication guards
        guard_matches = re.findall(r'@UseGuards\s*\(\s*([^)]+)\)', route_context)
        if guard_matches:
            result['auth_required'] = True
            result['guards'] = [guard.strip() for guard in guard_matches]
            
        # Check for role requirements
        role_matches = re.findall(r'@Roles\s*\(\s*([^)]+)\)', route_context)
        if role_matches:
            result['roles'] = [role.strip().strip('"\'') for role in role_matches[0].split(',')]
            
        return result 