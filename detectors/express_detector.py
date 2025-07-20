import re
import os
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple

from models import RouteInfo, Framework, HTTPMethod, AuthType, RiskLevel, RouteParameter, SecurityFinding
from detectors.base_detector import BaseDetector

class ExpressDetector(BaseDetector):
    """
    Enhanced Express.js detector with comprehensive modern pattern support.
    Supports Express 4.x/5.x, microservices, proxies, and enterprise patterns.
    """
    
    def __init__(self, framework: Framework = Framework.EXPRESS):
        super().__init__(framework)
        self.seen_routes = set()  # For deduplication
        
        # Enhanced file detection patterns
        self.express_indicators = [
            # Core Express imports
            r'require\s*\(\s*[\'"`]express[\'"`]\s*\)',
            r'import.*express.*from\s*[\'"`]express[\'"`]',
            r'import\s*{\s*.*express.*\s*}\s*from',
            
            # Express application patterns
            r'express\s*\(\s*\)',
            r'app\s*=.*express',
            r'const\s+app\s*=.*express',
            
            # Router patterns
            r'express\.Router\s*\(\s*\)',
            r'Router\s*\(\s*\)',
            r'new\s+Router\s*\(\s*\)',
            
            # Route method patterns
            r'app\.(get|post|put|delete|patch|head|options|all|use)',
            r'router\.(get|post|put|delete|patch|head|options|all|use)',
            
            # Modern Express patterns
            r'app\.listen\s*\(',
            r'app\.set\s*\(',
            r'app\.engine\s*\(',
            
            # Express middleware
            r'express\.static',
            r'express\.json',
            r'express\.urlencoded',
            
            # Express Gateway and proxy patterns
            r'express-gateway',
            r'http-proxy-middleware',
            r'express-http-proxy',
            r'createProxyMiddleware',
            
            # Microservice patterns
            r'@express-microservice',
            r'express-microservices',
            r'service-registry',
        ]
        
        # Enhanced template resolution patterns
        self.template_patterns = {
            # Variable references: ${variableName}
            'variable': re.compile(r'\$\{([^}()]+)\}'),
            # Function calls: ${functionName()}
            'function_call': re.compile(r'\$\{([^}]+)\(\)\}'),
            # Complex expressions: ${expr + other}
            'expression': re.compile(r'\$\{([^}]+)\}'),
            # Variable declarations with enhanced patterns
            'var_declaration': re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]'),
            # Template literals: `${var}/path`
            'template_literal': re.compile(r'`([^`]*\$\{[^`]*\}[^`]*)`'),
            # Object destructuring: const { API_PREFIX } = config
            'destructuring': re.compile(r'const\s*{\s*([^}]+)\s*}\s*=\s*(\w+)'),
            # ES6 imports: import { API_VERSION } from './config'
            'import_destructuring': re.compile(r'import\s*{\s*([^}]+)\s*}\s*from'),
        }
        
        # Comprehensive route patterns
        self.route_patterns = [
            # Standard Express patterns
            re.compile(r'(router|app)\.(get|post|put|delete|patch|head|options|all)\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]'),
            re.compile(r'(router|app)\.(use)\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]'),
            re.compile(r'(express\.Router\(\))\.(get|post|put|delete|patch|head|options|all)\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]'),
            
            # Template literal patterns
            re.compile(r'(router|app)\.(get|post|put|delete|patch|head|options|all)\s*\(\s*`([^`]*)`'),
            re.compile(r'(router|app)\.(use)\s*\(\s*`([^`]*)`'),
            
            # Class-based routing (Express 5.x)
            re.compile(r'@(Get|Post|Put|Delete|Patch|Head|Options|All)\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]\s*\)'),
            re.compile(r'@Route\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]\s*\)'),
            
            # Modern ES6+ patterns
            re.compile(r'(router|app)\[(\'"`)(get|post|put|delete|patch|head|options|all)\1\]\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]'),
            
            # Proxy and gateway patterns
            re.compile(r'(proxy\.forward|proxy\.forwardWithRules|apiProxy)\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]'),
            re.compile(r'(httpProxy|createProxyMiddleware)\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]'),
            re.compile(r'proxyTable\s*\[\s*[\'"`]([^\'"`,]+)[\'"`]\s*\]'),
            
            # Microservice routing patterns
            re.compile(r'serviceRouter\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]'),
            re.compile(r'microservice\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]'),
            re.compile(r'gateway\.route\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]'),
            
            # Dynamic routing patterns
            re.compile(r'dynamicRoute\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]'),
            re.compile(r'loadRoute\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]'),
            
            # Async/await route patterns
            re.compile(r'async\s+.*\.(get|post|put|delete|patch|head|options|all)\s*\(\s*[\'"`]([^\'"`,]+)[\'"`]'),
        ]
        
        # Enhanced proxy and gateway patterns
        self.proxy_patterns = [
            r'httpProxy\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'proxy\.forward',
            r'createProxyMiddleware',
            r'http-proxy-middleware',
            r'express-http-proxy',
            r'apiProxy\s*\(\s*\[([^\]]+)\]',
            r'gateway\.proxy\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'proxyMiddleware\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'reverseProxy\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            # Express Gateway specific
            r'express-gateway.*proxy',
            r'eg\.proxy',
        ]
        
        # Comprehensive authentication patterns
        self.auth_patterns = [
            # JWT and token-based auth
            r'auth(?:enticate)?(?:Token|JWT|Bearer)',
            r'jwtAuth', r'bearerAuth', r'tokenAuth',
            r'jwt\.verify', r'jwt\.decode', r'jwt\.sign',
            
            # Session and passport auth
            r'passport\.authenticate',
            r'session(?:Auth|Required)',
            r'expressSession',
            
            # Custom auth patterns
            r'requireAuth', r'isAuthenticated', r'checkAuth',
            r'authMiddleware', r'authGuard', r'verifyAuth',
            r'apiKeyAuth', r'keyAuth', r'secretAuth',
            
            # Organization-specific auth patterns
            r'organizationAuth', r'internalAuth', r'serviceAuth',
            r'adminAuth', r'userAuth', r'merchantAuth',
            r'clientAuth', r'customerAuth',
            
            # Enterprise SSO patterns
            r'ssoAuth', r'oauthMiddleware', r'oauth2',
            r'ldapAuth', r'adAuth', r'samlAuth',
            r'openidConnect', r'oidcAuth',
            
            # Modern auth patterns
            r'auth0\.', r'cognito\.', r'firebase\.auth',
            r'supabase\.auth', r'clerk\.', r'nextAuth',
            
            # API security patterns
            r'apiSecurity', r'corsMiddleware',
            r'rateLimitAuth', r'throttleAuth',
        ]
        
        # Enhanced enterprise middleware patterns
        self.middleware_patterns = [
            # Rate limiting and throttling
            r'rateLimit', r'rateLimiter', r'throttle',
            r'slowDown', r'expressSlowDown',
            r'express-rate-limit', r'express-slow-down',
            
            # CORS and security
            r'cors\(', r'helmet\(', r'security',
            r'xss', r'csrf', r'contentSecurityPolicy',
            r'expressSecurity', r'securityHeaders',
            
            # Request processing
            r'compression\(', r'morgan\(', r'bodyParser',
            r'multer\(', r'fileUpload', r'busboy',
            r'express\.json', r'express\.urlencoded',
            
            # Validation and parsing
            r'expressValidator', r'joi\.', r'yup\.',
            r'express-validator', r'validationMiddleware',
            r'celebrate\(', r'ajv\.', r'schema-validation',
            
            # Custom enterprise middleware
            r'organizationMiddleware', r'loggingMiddleware',
            r'metricsMiddleware', r'auditMiddleware',
            r'tracingMiddleware', r'monitoringMiddleware',
            
            # Microservice middleware
            r'serviceDiscovery', r'loadBalancer',
            r'circuitBreaker', r'retryMiddleware',
            r'timeoutMiddleware', r'cachingMiddleware',
            
            # Modern middleware patterns
            r'asyncMiddleware', r'errorHandler',
            r'notFoundHandler', r'globalErrorHandler',
        ]
        
        # Enhanced parameter patterns
        self.param_patterns = [
            r':(?P<n>\w+)',  # Express path parameters like :id
            r'req\.params\.(?P<n>\w+)',
            r'req\.query\.(?P<n>\w+)',
            r'req\.body\.(?P<n>\w+)',
            r'req\.headers\.(?P<n>\w+)',
            r'req\.cookies\.(?P<n>\w+)',
            # Destructuring patterns
            r'{\s*(?P<n>\w+)\s*}\s*=\s*req\.params',
            r'{\s*(?P<n>\w+)\s*}\s*=\s*req\.query',
            r'{\s*(?P<n>\w+)\s*}\s*=\s*req\.body',
        ]
        
        # Modern Express patterns
        self.modern_patterns = [
            # Express 5.x async patterns
            r'app\.async\.',
            r'router\.async\.',
            r'async\s+function.*app\.',
            
            # ES6+ class-based controllers
            r'class\s+\w+Controller',
            r'@Controller\s*\(',
            r'@Route\s*\(',
            
            # Modern middleware patterns
            r'app\.use\s*\(\s*async',
            r'router\.use\s*\(\s*async',
            
            # Promise-based routing
            r'\.then\s*\(\s*\(',
            r'\.catch\s*\(\s*\(',
            r'Promise\.all',
            
            # Modern error handling
            r'asyncHandler\s*\(',
            r'catchAsync\s*\(',
            r'errorHandler\s*\(',
        ]
    
    def detect_routes(self, file_path: str, content: str) -> List[RouteInfo]:
        """
        Enhanced Express.js route detection with template literal resolution
        """
        routes = []
        self.seen_routes.clear()  # Reset for each file
        
        if not self._is_express_file(content):
            return routes
        
        # Step 1: Extract variable declarations for template resolution
        variables = self._extract_variables(content)
        
        try:
            lines = content.split('\n')
            
            # Step 2: Process each route pattern
            for pattern in self.route_patterns:
                for match in pattern.finditer(content):
                    groups = match.groups()
                    
                    if len(groups) >= 3:
                        # Standard pattern: (router/app, method, path)
                        router_type, method, raw_path = groups[0], groups[1], groups[2]
                        
                        # Skip 'use' method as it's middleware, not a route
                        if method == 'use':
                            continue
                        
                        # Step 3: Enhanced template literal resolution
                        if '${' in raw_path:
                            # Template literal detected - resolve it
                            resolved_path, path_params, query_params = self._resolve_template_literal(raw_path, variables)
                        else:
                            # Standard path - just normalize
                            resolved_path = self._normalize_route_path(raw_path)
                            path_params = re.findall(r':(\w+)', raw_path)  # Express params
                            query_params = []
                        
                        # Step 4: Create route with enhanced information
                        line_number = self._find_line_number(content, match.start())
                        
                        # Convert method name
                        http_method = self._convert_to_http_method(method)
                        if not http_method:
                            continue
                        
                        # Create deduplication key
                        route_key = (http_method.value, resolved_path, file_path)
                        if route_key in self.seen_routes:
                            continue
                        self.seen_routes.add(route_key)
                        
                        # Create enhanced route info
                        route_info = self._create_enhanced_route_info(
                            method=http_method,
                            path=resolved_path,
                            original_path=raw_path,
                            file_path=file_path,
                            line_number=line_number,
                            path_params=path_params,
                            query_params=query_params,
                            variables=variables,
                            content=content
                        )
                        
                        routes.append(route_info)
                        
        except Exception as e:
            self.logger.error(f"Error detecting Express routes in {file_path}: {e}")
        
        return routes
    
    def _create_enhanced_route_info(self, method: HTTPMethod, path: str, original_path: str, 
                                   file_path: str, line_number: int, path_params: List[str], 
                                   query_params: List[str], variables: Dict[str, str], content: str) -> RouteInfo:
        """Create enhanced RouteInfo with template resolution context"""
        
        # Extract authentication info
        auth_info = self._extract_auth_info(content, line_number)
        if auth_info is None:
            auth_info = {}
        
        # Enhanced parameter extraction
        route_parameters = []
        
        # Add path parameters
        for param in path_params:
            route_parameters.append(RouteParameter(
                name=param,
                type="string",
                required=True,
                location="path",
                description=f"Path parameter: {param}"
            ))
            
        # Add query parameters  
        for param in query_params:
            route_parameters.append(RouteParameter(
                name=param,
                type="string", 
                required=False,
                location="query",
                description=f"Query parameter: {param}"
            ))
            
        # Enhanced metadata with template resolution info
        metadata = {
            'original_template': original_path if '${' in original_path else None,
            'resolved_variables': {k: v for k, v in variables.items() if f'${{{k}}}' in original_path},
            'path_parameters': path_params,
            'query_parameters': query_params,
            'template_resolution': '${' in original_path
        }
        
        # Create route info
        route_info = RouteInfo(
            method=method,
                path=path,
                file_path=file_path,
                line_number=line_number,
                framework=self.framework,
            auth_type=auth_info.get('type', AuthType.UNKNOWN),
            auth_required=auth_info.get('required', False),
            parameters=route_parameters,
            metadata=metadata
        )
        
        # Set original path for prefix resolution
        if '${' in original_path:
            route_info.original_path = original_path
        
        # Enhanced risk assessment
        route_info.risk_level = self._assess_risk_level(path, method.value, route_info.auth_type)
        route_info.risk_score = self._calculate_enhanced_risk_score(route_info, content)
        
        return route_info
    
    def _detect_authentication(self, content: str, match_start: int) -> AuthType:
        """Enhanced authentication detection for enterprise Express.js patterns."""
        # Look in a larger window around the match for better context
        window_start = max(0, match_start - 800)
        window_end = min(len(content), match_start + 800)
        window_content = content[window_start:window_end]
        
        # Check for specific authentication types with priority order
        
        # JWT Authentication (highest priority for enterprise)
        jwt_patterns = [
            r'jwt\.verify', r'bearerAuth', r'jwtAuth', r'tokenAuth',
            r'Authorization.*Bearer', r'jwt\.decode', r'jsonwebtoken'
        ]
        if any(re.search(pattern, window_content, re.IGNORECASE) for pattern in jwt_patterns):
                    return AuthType.JWT
        
        # API Key Authentication
        api_key_patterns = [
            r'apiKeyAuth', r'keyAuth', r'secretAuth', r'x-api-key',
            r'api[_-]?key', r'auth[_-]?key'
        ]
        if any(re.search(pattern, window_content, re.IGNORECASE) for pattern in api_key_patterns):
            return AuthType.API_KEY
        
        # Session-based Authentication
        session_patterns = [
            r'session(?:Auth|Required)', r'passport\.authenticate',
            r'req\.session', r'express-session'
        ]
        if any(re.search(pattern, window_content, re.IGNORECASE) for pattern in session_patterns):
                    return AuthType.SESSION
        
        # OAuth Authentication
        oauth_patterns = [
            r'oauth', r'ssoAuth', r'oauthMiddleware', r'oauth2',
            r'passport-oauth', r'passport-google', r'passport-github'
        ]
        if any(re.search(pattern, window_content, re.IGNORECASE) for pattern in oauth_patterns):
            return AuthType.OAUTH
        
        # Basic Authentication
        basic_auth_patterns = [
            r'basicAuth', r'basic[_-]?auth', r'Authorization.*Basic',
            r'passport-http'
        ]
        if any(re.search(pattern, window_content, re.IGNORECASE) for pattern in basic_auth_patterns):
            return AuthType.BASIC
        
        # Enterprise SSO patterns
        sso_patterns = [
            r'ldapAuth', r'adAuth', r'samlAuth', r'ssoAuth',
            r'active[_-]?directory', r'ldap'
        ]
        if any(re.search(pattern, window_content, re.IGNORECASE) for pattern in sso_patterns):
            return AuthType.OAUTH  # Map to OAuth for now
        
        # General authentication patterns (fallback)
        general_auth_patterns = [
            r'requireAuth', r'isAuthenticated', r'checkAuth',
            r'authMiddleware', r'authGuard', r'verifyAuth'
        ]
        if any(re.search(pattern, window_content, re.IGNORECASE) for pattern in general_auth_patterns):
            return AuthType.UNKNOWN
        
        # Organization-specific auth patterns
        org_auth_patterns = [
            r'organizationAuth', r'internalAuth', r'serviceAuth',
            r'adminAuth', r'userAuth', r'merchantAuth'
        ]
        if any(re.search(pattern, window_content, re.IGNORECASE) for pattern in org_auth_patterns):
            return AuthType.CUSTOM
        
        return AuthType.NONE
    
    def _extract_parameters(self, path: str, content: str, match_start: int) -> List[RouteParameter]:
        """Extract route parameters from path and surrounding code.""" 
        parameters = []
        
        # Extract path parameters
        path_params = re.findall(r':(\w+)', path)
        for param_name in path_params:
            parameters.append(RouteParameter(
                name=param_name,
                type="path",
                required=True,
                location="path"
            ))
        
        # Look for query/body parameters in surrounding code
        window_start = max(0, match_start - 200)
        window_end = min(len(content), match_start + 800)
        window_content = content[window_start:window_end]
        
        # Extract query parameters
        query_matches = re.findall(r'req\.query\.(\w+)', window_content)
        for param_name in set(query_matches):
            parameters.append(RouteParameter(
                name=param_name,
                type="string",
                required=False,
                location="query"
            ))
        
        # Extract body parameters
        body_matches = re.findall(r'req\.body\.(\w+)', window_content)
        for param_name in set(body_matches):
            parameters.append(RouteParameter(
                name=param_name,
                type="any",
                required=False,
                location="body"
            ))
        
        return parameters
    
    def _extract_variables(self, content: str) -> Dict[str, str]:
        """Enhanced variable extraction with modern JavaScript patterns"""
        variables = {}
        
        # Extract const/let/var declarations
        var_patterns = [
            # Standard variable declarations
            r'(?:const|let|var)\s+(\w+)\s*=\s*[\'"`]([^\'"`,]+)[\'"`]',
            # Template literal declarations
            r'(?:const|let|var)\s+(\w+)\s*=\s*`([^`]+)`',
            # Numeric and boolean declarations
            r'(?:const|let|var)\s+(\w+)\s*=\s*(\d+|true|false)',
        ]
        
        for pattern in var_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                var_name, var_value = match.groups()
                variables[var_name] = var_value
        
        # Extract object destructuring
        destructuring_pattern = r'const\s*{\s*([^}]+)\s*}\s*=\s*(\w+)'
        matches = re.finditer(destructuring_pattern, content, re.MULTILINE)
        for match in matches:
            destructured_vars = match.group(1)
            source_object = match.group(2)
            
            # Parse individual variables from destructuring
            var_names = [v.strip() for v in destructured_vars.split(',')]
            for var_name in var_names:
                # Handle renamed variables: { oldName: newName }
                if ':' in var_name:
                    old_name, new_name = [v.strip() for v in var_name.split(':')]
                    variables[new_name] = f"{source_object}.{old_name}"
                else:
                    variables[var_name] = f"{source_object}.{var_name}"
        
        # Extract import destructuring
        import_pattern = r'import\s*{\s*([^}]+)\s*}\s*from\s*[\'"`]([^\'"`,]+)[\'"`]'
        matches = re.finditer(import_pattern, content, re.MULTILINE)
        for match in matches:
            imported_vars = match.group(1)
            module_name = match.group(2)
            
            var_names = [v.strip() for v in imported_vars.split(',')]
            for var_name in var_names:
                variables[var_name] = f"IMPORT:{module_name}"
        
        # Extract environment variables
        env_pattern = r'process\.env\.(\w+)'
        matches = re.finditer(env_pattern, content)
        for match in matches:
            env_var = match.group(1)
            variables[env_var] = "ENVIRONMENT_VARIABLE"
        
        return variables
    
    def _resolve_template_literal(self, raw_path: str, variables: Dict[str, str]) -> Tuple[str, List[str], List[str]]:
        """Enhanced template literal resolution with complex expressions"""
        resolved_path = raw_path
        path_params = []
        query_params = []
        
        # Handle template literal expressions: ${variable}
        template_vars = re.findall(r'\$\{([^}]+)\}', raw_path)
        
        for var_expr in template_vars:
            var_expr = var_expr.strip()
            
            # Simple variable reference
            if var_expr in variables:
                resolved_path = resolved_path.replace(f'${{{var_expr}}}', variables[var_expr])
            
            # Function call: functionName()
            elif var_expr.endswith('()'):
                func_name = var_expr[:-2]
                if func_name in variables:
                    resolved_path = resolved_path.replace(f'${{{var_expr}}}', variables[func_name])
                else:
                    # Keep as dynamic parameter
                    resolved_path = resolved_path.replace(f'${{{var_expr}}}', f'{{{func_name}}}')
                    path_params.append(func_name)
            
            # Object property access: config.apiVersion
            elif '.' in var_expr:
                base_obj, prop = var_expr.split('.', 1)
                if base_obj in variables:
                    # Try to resolve if we know the object structure
                    resolved_path = resolved_path.replace(f'${{{var_expr}}}', f'{{{prop}}}')
                    path_params.append(prop)
                else:
                    resolved_path = resolved_path.replace(f'${{{var_expr}}}', f'{{{var_expr}}}')
                    path_params.append(var_expr)
            
            # Complex expressions: var + '/suffix'
            elif '+' in var_expr or '-' in var_expr:
                # Keep as dynamic for complex expressions
                resolved_path = resolved_path.replace(f'${{{var_expr}}}', f'{{{var_expr}}}')
                path_params.append(var_expr)
            
            # Unknown variable - keep as parameter
            else:
                resolved_path = resolved_path.replace(f'${{{var_expr}}}', f'{{{var_expr}}}')
                path_params.append(var_expr)
        
        # Normalize the resolved path
        resolved_path = self._normalize_route_path(resolved_path)
        
        # Extract Express-style parameters (:param)
        express_params = re.findall(r':(\w+)', resolved_path)
        path_params.extend(express_params)
        
        return resolved_path, path_params, query_params
    
    def _normalize_route_path(self, path: str) -> str:
        """Normalize route path to standard format"""
        # Remove query string for path normalization
        clean_path = path.split('?')[0]
        
        # Ensure starts with /
        if not clean_path.startswith('/'):
            clean_path = '/' + clean_path
        
        # Clean up multiple slashes
        clean_path = re.sub(r'/+', '/', clean_path)
        
        # Convert Express params :id to OpenAPI {id}
        clean_path = re.sub(r':(\w+)', r'{\1}', clean_path)
        
        return clean_path
    
    def _find_line_number(self, content: str, match_start: int) -> int:
        """Find line number from character position in content"""
        return content[:match_start].count('\n') + 1
    
    def _convert_to_http_method(self, method_string: str) -> Optional[HTTPMethod]:
        """Convert string method to HTTPMethod enum"""
        method_upper = method_string.upper()
        
        method_mapping = {
            'GET': HTTPMethod.GET,
            'POST': HTTPMethod.POST,
            'PUT': HTTPMethod.PUT,
            'DELETE': HTTPMethod.DELETE,
            'PATCH': HTTPMethod.PATCH,
            'HEAD': HTTPMethod.HEAD,
            'OPTIONS': HTTPMethod.OPTIONS,
            'ALL': HTTPMethod.ALL,  # Fixed: router.all() -> ALL enum (not OPTIONS)
            '*': HTTPMethod.ALL     # Fixed: wildcard -> ALL enum (not OPTIONS)
        }
        
        return method_mapping.get(method_upper)
    
    def _extract_auth_info(self, content: str, line_number: int) -> Dict[str, any]:
        """Extract authentication information around a specific line"""
        lines = content.split('\n')
        
        # Look at the specific line and surrounding lines for auth patterns
        start_line = max(0, line_number - 3)
        end_line = min(len(lines), line_number + 3)
        context_lines = lines[start_line:end_line]
        context = '\n'.join(context_lines)
        
        auth_info = {
            'type': AuthType.UNKNOWN,
            'required': False
        }
        
        # Enhanced authentication patterns
        auth_patterns = {
            AuthType.JWT: [
                r'validateJWT|verifyJWT|jwtAuth|BearerAuth',
                r'jwt\.verify|jwt\.decode',
                r'bearer.*token|authorization.*bearer'
            ],
            AuthType.API_KEY: [
                r'validateApiKey|apiKeyAuth|api_key',
                r'x-api-key|apikey|api-token'
            ],
            AuthType.SESSION: [
                r'session|cookie|express-session',
                r'req\.session|isAuthenticated'
            ],
            AuthType.OAUTH: [
                r'oauth|OAuth2|validateOauthToken',
                r'passport\.authenticate'
            ],
            AuthType.BASIC: [
                r'basic.*auth|basicAuth',
                r'authorization.*basic'
            ]
        }
        
        # Check for auth patterns
        for auth_type, patterns in auth_patterns.items():
            for pattern in patterns:
                if re.search(pattern, context, re.IGNORECASE):
                    auth_info['type'] = auth_type
                    auth_info['required'] = True
                    break
            if auth_info['required']:
                break
        
        return auth_info
    
    def _calculate_enhanced_risk_score(self, route_info: RouteInfo, content: str) -> float:
        """Calculate enhanced risk score with template resolution context"""
        base_score = 0.0
        risk_factors = []
        
        # Method-based risk
        method_risks = {
            HTTPMethod.GET: 1.0,
            HTTPMethod.POST: 2.0,
            HTTPMethod.PUT: 2.5,
            HTTPMethod.DELETE: 3.0,
            HTTPMethod.PATCH: 2.0
        }
        base_score += method_risks.get(route_info.method, 1.0)
        if route_info.method in [HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.DELETE, HTTPMethod.ALL]:
            risk_factors.append(f"High-risk HTTP method: {route_info.method}")
        
        # Path-based risk patterns
        high_risk_patterns = [
            r'/admin',
            r'/api/internal',
            r'/debug',
            r'/config',
            r'/management',
            r'/actuator',
            r'/health',
            r'/metrics',
            r'/delete',
            r'/upload',
            r'/download',
            r'/password',
            r'/token',
            r'/auth',
            r'/login',
            r'/logout',
            r'/reset'
        ]
        
        for pattern in high_risk_patterns:
            if re.search(pattern, route_info.path, re.IGNORECASE):
                base_score += 2.0
                risk_factors.append("Sensitive path detected")
                break
        
        # Authentication risk
        if route_info.auth_type == AuthType.UNKNOWN:
            base_score += 3.0
            risk_factors.append("No authentication required")
        elif route_info.auth_type == AuthType.API_KEY:
            base_score += 1.0
            risk_factors.append(f"Authentication type: {route_info.auth_type}")
        
        # Parameter validation risk
        if route_info.parameters:
            param_count = len(route_info.parameters)
            if param_count > 0:
                base_score += 0.5 * param_count
                risk_factors.append("Unvalidated parameters")
        
        # Template resolution specific risks
        if route_info.metadata.get('template_resolution'):
            base_score += 1.0
            risk_factors.append("Dynamic route construction")
        
        # Organization-specific patterns
        org_risk_patterns = [
            r'/internal/',
            r'/private/',
            r'/restricted/',
            r'/secret'
        ]
        
        for pattern in org_risk_patterns:
            if re.search(pattern, route_info.path, re.IGNORECASE):
                base_score += 1.5
                risk_factors.append("Organization-specific risk factors")
                break
        
        # Security findings
        if hasattr(route_info, 'security_findings') and route_info.security_findings:
            base_score += len(route_info.security_findings)
            risk_factors.append("Security vulnerabilities found")
        
        # Store risk factors in route info
        route_info.risk_factors = risk_factors
        
        return min(base_score, 10.0)  # Cap at 10.0
    
    def _is_express_file(self, content: str) -> bool:
        """Enhanced Express.js file detection with comprehensive patterns"""
        if not content:
            return False
        
        # Check for any Express indicators
        for indicator in self.express_indicators:
            if re.search(indicator, content, re.IGNORECASE | re.MULTILINE):
                return True
        
        # Check for modern Express patterns
        for pattern in self.modern_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                return True
        
        # Check for proxy and gateway patterns (common in microservices)
        for pattern in self.proxy_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                return True
        
        # Enhanced content-based detection
        express_keywords = [
            'express', 'router', 'middleware', 'app.listen',
            'req.params', 'req.query', 'req.body', 'res.json',
            'res.send', 'res.status', 'next()', 'app.use'
        ]
        
        # Count Express-specific patterns
        express_score = 0
        for keyword in express_keywords:
            if keyword.lower() in content.lower():
                express_score += 1
        
        # If we have multiple Express indicators, it's likely an Express file
        return express_score >= 3
    
    def can_handle_file(self, file_path: str, content: str) -> bool:
        """Enhanced file handling detection"""
        # Check file extension
        if not (file_path.endswith('.js') or file_path.endswith('.ts') or 
                file_path.endswith('.mjs') or file_path.endswith('.cjs')):
            return False
        
        # Extract just the filename for pattern matching (not full path)
        filename = os.path.basename(file_path).lower()
        
        # Skip obvious non-Express files based on filename only
        skip_patterns = [
            '.test.', '.spec.', '.min.', 'bundle.',
            'webpack.', 'babel.', 'rollup.',
            '.d.ts'  # TypeScript declarations
        ]
        
        for pattern in skip_patterns:
            if pattern in filename:
                return False
        
        # Skip common non-source directories in full path
        skip_directories = ['node_modules/', 'dist/', 'build/', 'coverage/']
        for directory in skip_directories:
            if directory in file_path:
                return False
        
        # Enhanced content-based detection
        return self._is_express_file(content)
    
    def _assess_risk_level(self, path: str, method: str, auth_type: AuthType) -> RiskLevel:
        """Enhanced risk assessment based on enterprise Express.js patterns."""
        risk_score = 0.0
        
        # Enhanced method-based risk scoring
        method_risks = {
            'POST': 0.25,    # Data creation/modification
            'PUT': 0.3,      # Full resource replacement  
            'PATCH': 0.2,    # Partial updates
            'DELETE': 0.35,  # Data deletion - highest risk
            'GET': 0.05,     # Read operations
            'HEAD': 0.0,     # Metadata only
            'OPTIONS': 0.0,  # CORS preflight
            'ALL': 0.4       # Wildcard methods - very risky
        }
        
        if method in method_risks:
            risk_score += method_risks[method]
        
        # Enhanced path-based risk patterns from enterprise analysis
        critical_paths = {
            # Administrative and internal
            '/admin': 0.4, '/internal': 0.35, '/debug': 0.4,
            '/management': 0.3, '/console': 0.35,
            
            # Financial and payment (critical in enterprise)
            '/payment': 0.5, '/billing': 0.5, '/financial': 0.5,
            '/cashier': 0.45, '/transaction': 0.4, '/money': 0.4,
            '/invoice': 0.3, '/refund': 0.3,
            
            # Authentication and security
            '/auth': 0.35, '/login': 0.3, '/oauth': 0.3,
            '/security': 0.3, '/token': 0.25, '/session': 0.2,
            
            # User and customer data
            '/user': 0.25, '/customer': 0.25, '/member': 0.25,
            '/profile': 0.2, '/account': 0.25, '/personal': 0.3,
            
            # Business entities (enterprise-specific)
            '/merchant': 0.3, '/store': 0.25, '/seller': 0.25,
            '/vendor': 0.25, '/partner': 0.2,
            
            # API endpoints
            '/api/gateway': 0.3, '/api/internal': 0.35,
            '/api/admin': 0.4, '/api/v1': 0.1, '/api/private': 0.3,
            
            # Service and platform routes
            '/service': 0.2, '/platform': 0.2, '/core': 0.25,
            '/integration': 0.2, '/connector': 0.2, '/sync': 0.15,
            
            # Proxy and gateway patterns (from analysis)
            '/proxy': 0.25, '/gateway': 0.3, '/forward': 0.2,
            '/redirect': 0.15, '/route': 0.2,
        }
        
        path_lower = path.lower()
        for risk_path, risk_value in critical_paths.items():
            if risk_path in path_lower:
                risk_score += risk_value
        
        # Authentication risk assessment
        if auth_type == AuthType.NONE:
            risk_score += 0.4  # No authentication is high risk
        elif auth_type == AuthType.UNKNOWN:
            risk_score += 0.25  # Unknown auth mechanism
        elif auth_type == AuthType.API_KEY:
            risk_score += 0.1   # API keys less secure than JWT
        
        # Gateway/proxy specific risks
        if any(pattern in path_lower for pattern in ['proxy', 'gateway', 'forward']):
            risk_score += 0.2   # Proxy endpoints can be risky
        
        # Express-specific risk patterns
        if '/health' in path_lower or '/status' in path_lower:
            risk_score -= 0.1   # Health checks are typically low risk
        elif '/upload' in path_lower or '/file' in path_lower:
            risk_score += 0.3   # File uploads are risky
        elif '/download' in path_lower:
            risk_score += 0.2   # File downloads can be risky
        
        # Ensure score stays within bounds
        risk_score = max(0.0, min(1.0, risk_score))
        
        # Convert to risk level with more granular thresholds
        if risk_score >= 0.7:
            return RiskLevel.HIGH
        elif risk_score >= 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _find_security_issues(self, content: str, match: re.Match, path: str, method: str) -> List[SecurityFinding]:
        """Find potential security issues in the route."""
        findings = []
        
        # Look in a window around the route
        window_start = max(0, match.start() - 300)
        window_end = min(len(content), match.start() + 1000)
        window_content = content[window_start:window_end]
        
        # Check for missing input validation
        if not re.search(r'validation|validate|sanitize|escape', window_content, re.IGNORECASE):
            findings.append(SecurityFinding(
                type="Missing Input Validation",
                severity="MEDIUM",
                description="Route may not have proper input validation",
                recommendation="Implement proper input validation and sanitization"
            ))
        
        # Check for SQL injection risks
        if re.search(r'query\s*\([\'"`][^\'"`]*\+|SELECT.*\+.*FROM', window_content, re.IGNORECASE):
            findings.append(SecurityFinding(
                type="SQL Injection Risk",
                severity="HIGH", 
                description="Possible SQL injection vulnerability detected",
                recommendation="Use parameterized queries and input sanitization"
            ))
        
        # Check for missing authentication on sensitive endpoints
        if (any(keyword in path.lower() for keyword in ['admin', 'delete', 'internal']) and
            not any(pattern in window_content.lower() for pattern in ['auth', 'authenticate', 'login'])):
            findings.append(SecurityFinding(
                type="Missing Authentication",
                severity="HIGH",
                description="Sensitive endpoint may be missing authentication",
                recommendation="Add proper authentication middleware"
            ))
        
        return findings
    
    def get_supported_extensions(self) -> Set[str]:
        """Return file extensions this detector supports."""
        return {'.js', '.mjs', '.ts'}
    
    def is_relevant_file(self, file_path: str, content: str) -> bool:
        """Check if the file is relevant for Express.js detection."""
        if not any(file_path.endswith(ext) for ext in self.get_supported_extensions()):
            return False
        
        # Check for Express indicators
        express_indicators = [
            'express()',
            'require(\'express\')',
            'from \'express\'',
            'import express',
            'app.get(',
            'app.post(',
            'router.get(',
            'router.post(',
            'express.Router()'
        ]
        
        return any(indicator in content for indicator in express_indicators) 

    def _detect_proxy_routes(self, content: str) -> List[Dict[str, str]]:
        """Detect proxy and gateway route patterns"""
        proxy_routes = []
        
        for pattern in self.proxy_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                if match.groups():
                    proxy_path = match.group(1) if len(match.groups()) >= 1 else match.group(0)
                    proxy_routes.append({
                        'path': proxy_path,
                        'type': 'proxy',
                        'pattern': pattern,
                        'line': content[:match.start()].count('\n') + 1
                    })
        
        return proxy_routes
    
    def _analyze_authentication(self, content: str, line_number: int) -> AuthType:
        """Enhanced authentication analysis with modern patterns"""
        # Get context around the route (5 lines before and after)
        lines = content.split('\n')
        start_line = max(0, line_number - 5)
        end_line = min(len(lines), line_number + 5)
        context = '\n'.join(lines[start_line:end_line])
        
        # Check for authentication patterns in context
        for auth_pattern in self.auth_patterns:
            if re.search(auth_pattern, context, re.IGNORECASE):
                # Determine specific auth type
                if re.search(r'jwt|bearer|token', auth_pattern, re.IGNORECASE):
                    return AuthType.JWT
                elif re.search(r'session|passport', auth_pattern, re.IGNORECASE):
                    return AuthType.SESSION
                elif re.search(r'api.?key|key.?auth', auth_pattern, re.IGNORECASE):
                    return AuthType.API_KEY
                elif re.search(r'oauth|sso|saml|openid', auth_pattern, re.IGNORECASE):
                    return AuthType.OAUTH
                else:
                    return AuthType.CUSTOM
        
        return AuthType.UNKNOWN
    
    def _extract_middleware_info(self, content: str, line_number: int) -> List[str]:
        """Extract middleware information for security analysis"""
        middleware_found = []
        
        # Get context around the route
        lines = content.split('\n')
        start_line = max(0, line_number - 10)
        end_line = min(len(lines), line_number + 5)
        context = '\n'.join(lines[start_line:end_line])
        
        # Check for middleware patterns
        for middleware_pattern in self.middleware_patterns:
            if re.search(middleware_pattern, context, re.IGNORECASE):
                middleware_found.append(middleware_pattern)
        
        return middleware_found
    
    def _calculate_risk_score(self, route_info: RouteInfo, middleware: List[str]) -> float:
        """Enhanced risk scoring with modern security considerations"""
        risk_score = 0.0
        
        # Base risk by HTTP method
        method_risks = {
            'GET': 0.2, 'HEAD': 0.1, 'OPTIONS': 0.1,
            'POST': 0.6, 'PUT': 0.7, 'PATCH': 0.6,
            'DELETE': 0.8, 'ALL': 0.9
        }
        
        method = route_info.method.value if hasattr(route_info.method, 'value') else str(route_info.method)
        risk_score += method_risks.get(method.upper(), 0.5)
        
        # Authentication factor
        if route_info.auth_type == AuthType.UNKNOWN:
            risk_score += 0.3
        elif route_info.auth_type == AuthType.NONE:
            risk_score += 0.4
        
        # Path-based risk factors
        high_risk_paths = [
            '/admin', '/api/admin', '/internal', '/private',
            '/delete', '/remove', '/destroy', '/drop',
            '/config', '/settings', '/env',
            '/payment', '/billing', '/transaction',
            '/user', '/users', '/account', '/profile'
        ]
        
        path = route_info.path.lower()
        for risk_path in high_risk_paths:
            if risk_path in path:
                risk_score += 0.2
                break
        
        # Middleware security factors
        security_middleware = [
            'helmet', 'cors', 'rateLimit', 'csrf',
            'validation', 'sanitiz', 'security'
        ]
        
        has_security = any(
            any(sec_pattern in mw.lower() for sec_pattern in security_middleware)
            for mw in middleware
        )
        
        if not has_security:
            risk_score += 0.2
        
        # Normalize to 0-1 scale
        return min(risk_score, 1.0) 