import re
import os
from typing import List, Dict, Optional, Set, Tuple, Any

from models import RouteInfo, Framework, HTTPMethod, AuthType, RiskLevel, RouteParameter, SecurityFinding
from detectors.base_detector import BaseDetector
from analyzers.template_resolver import get_template_resolver, FrameworkContext, ResolvedRoute


class GoDetector(BaseDetector):
    """
    Enhanced Go HTTP detector with comprehensive modern framework support.
    Supports Gin, Echo, Fiber, gRPC, and enterprise microservice patterns.
    """
    
    def __init__(self, framework: Framework = Framework.GO_HTTP):
        super().__init__(framework)
        self.seen_routes = set()  # For deduplication
        
        # Initialize template resolver
        self.template_resolver = get_template_resolver(Framework.GO_HTTP)
        
        # Enhanced Go framework detection indicators
        self.go_indicators = [
            # Core Go HTTP
            r'"net/http"',
            r'http\.',
            r'http\.Handle',
            r'http\.HandleFunc',
            r'http\.ListenAndServe',
            r'http\.Server',
            
            # Gin framework
            r'github\.com/gin-gonic/gin',
            r'"gin-gonic/gin"',
            r'gin\.Default\(\)',
            r'gin\.New\(\)',
            r'gin\.Engine',
            r'gin\.RouterGroup',
            
            # Echo framework
            r'github\.com/labstack/echo',
            r'"labstack/echo"',
            r'echo\.New\(\)',
            r'echo\.Echo',
            r'echo\.Group',
            
            # Fiber framework
            r'github\.com/gofiber/fiber',
            r'"gofiber/fiber"',
            r'fiber\.New\(\)',
            r'fiber\.App',
            r'fiber\.Router',
            
            # Gorilla Mux
            r'github\.com/gorilla/mux',
            r'"gorilla/mux"',
            r'mux\.NewRouter\(\)',
            r'mux\.Router',
            
            # gRPC patterns
            r'google\.golang\.org/grpc',
            r'"google.golang.org/grpc"',
            r'grpc\.NewServer\(\)',
            r'pb\.',
            r'\.proto',
            
            # Chi router
            r'github\.com/go-chi/chi',
            r'"go-chi/chi"',
            r'chi\.NewRouter\(\)',
            
            # FastHTTP
            r'github\.com/valyala/fasthttp',
            r'"valyala/fasthttp"',
            r'fasthttp\.',
            
            # Microservice patterns
            r'github\.com/micro/micro',
            r'github\.com/go-kit/kit',
            r'github\.com/nats-io/nats',
            r'github\.com/hashicorp/consul',
        ]
        
        # Comprehensive Go HTTP framework patterns
        self.go_frameworks = {
            'gin': {
                'import_patterns': [
                    r'github\.com/gin-gonic/gin',
                    r'"gin-gonic/gin"',
                    r'gin\.',
                    r'gin\.Default',
                    r'gin\.New',
                ],
                'route_patterns': [
                    # Standard Gin routing
                    re.compile(r'(\w+)\.(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any)\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'(\w+)\.(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any)\s*\(\s*fmt\.Sprintf\s*\([^)]+\)'),
                    re.compile(r'(\w+)\.(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any)\s*\(\s*([a-zA-Z_]\w*)\s*,'),
                    
                    # Group routing
                    re.compile(r'(\w+)\.Group\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'(\w+)\.Use\s*\([^)]*\)\.(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any)\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    
                    # Static routing
                    re.compile(r'(\w+)\.Static\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'(\w+)\.StaticFS\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                ],
                'method_patterns': [
                    re.compile(r'(\w+)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any)\s*\('),
                ],
                'middleware_patterns': [
                    r'gin\.Logger\(\)',
                    r'gin\.Recovery\(\)',
                    r'cors\.Default\(\)',
                    r'gin\.BasicAuth\(',
                ]
            },
            'echo': {
                'import_patterns': [
                    r'github\.com/labstack/echo',
                    r'"labstack/echo"',
                    r'echo\.',
                    r'echo\.New',
                ],
                'route_patterns': [
                    # Standard Echo routing
                    re.compile(r'(\w+)\.(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any)\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'(\w+)\.(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any)\s*\(\s*fmt\.Sprintf\s*\([^)]+\)'),
                    
                    # Group routing
                    re.compile(r'(\w+)\.Group\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    
                    # Static routing
                    re.compile(r'(\w+)\.Static\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'(\w+)\.File\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                ],
                'method_patterns': [
                    re.compile(r'(\w+)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any)\s*\('),
                ],
                'middleware_patterns': [
                    r'middleware\.Logger\(\)',
                    r'middleware\.Recover\(\)',
                    r'middleware\.CORS\(\)',
                    r'middleware\.BasicAuth\(',
                ]
            },
            'fiber': {
                'import_patterns': [
                    r'github\.com/gofiber/fiber',
                    r'"gofiber/fiber"',
                    r'fiber\.',
                    r'fiber\.New',
                ],
                'route_patterns': [
                    # Standard Fiber routing (note the capitalization)
                    re.compile(r'(\w+)\.(?:Get|Post|Put|Delete|Patch|Head|Options|All)\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'(\w+)\.(?:Get|Post|Put|Delete|Patch|Head|Options|All)\s*\(\s*fmt\.Sprintf\s*\([^)]+\)'),
                    
                    # Group routing
                    re.compile(r'(\w+)\.Group\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    
                    # Static routing
                    re.compile(r'(\w+)\.Static\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                ],
                'method_patterns': [
                    re.compile(r'(\w+)\.(Get|Post|Put|Delete|Patch|Head|Options|All)\s*\('),
                ],
                'middleware_patterns': [
                    r'logger\.New\(\)',
                    r'recover\.New\(\)',
                    r'cors\.New\(\)',
                    r'basicauth\.New\(',
                ]
            },
            'gorilla': {
                'import_patterns': [
                    r'github\.com/gorilla/mux',
                    r'"gorilla/mux"',
                    r'mux\.',
                    r'mux\.NewRouter',
                ],
                'route_patterns': [
                    # Gorilla Mux patterns
                    re.compile(r'(\w+)\.HandleFunc\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'(\w+)\.Handle\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'(\w+)\.PathPrefix\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'(\w+)\.(?:Methods|Path)\s*\([^)]*[\'"`]([^\'"`,]*)[\'"`]'),
                    
                    # Subrouter patterns
                    re.compile(r'(\w+)\.NewRoute\s*\(\s*\)\.Path\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                ],
                'method_patterns': [
                    re.compile(r'\.Methods\s*\(\s*[\'"`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[\'"`]'),
                ]
            },
            'chi': {
                'import_patterns': [
                    r'github\.com/go-chi/chi',
                    r'"go-chi/chi"',
                    r'chi\.',
                    r'chi\.NewRouter',
                ],
                'route_patterns': [
                    re.compile(r'(\w+)\.(?:Get|Post|Put|Delete|Patch|Head|Options)\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'(\w+)\.Route\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'(\w+)\.Mount\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                ],
                'method_patterns': [
                    re.compile(r'(\w+)\.(Get|Post|Put|Delete|Patch|Head|Options)\s*\('),
                ]
            },
            'stdlib': {
                'import_patterns': [
                    r'"net/http"',
                    r'http\.',
                    r'http\.Handle',
                    r'http\.HandleFunc'
                ],
                'route_patterns': [
                    re.compile(r'http\.HandleFunc\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'http\.Handle\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'(\w+)\.HandleFunc\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                    re.compile(r'mux\.HandleFunc\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
                ],
                'method_patterns': [
                    re.compile(r'r\.Method\s*==\s*[\'"`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[\'"`]'),
                    re.compile(r'switch\s+r\.Method\s*\{[^}]*case\s+[\'"`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[\'"`]'),
                ]
            },
            'grpc': {
                'import_patterns': [
                    r'google\.golang\.org/grpc',
                    r'"google.golang.org/grpc"',
                    r'grpc\.',
                    r'\.proto',
                ],
                'route_patterns': [
                    # gRPC service patterns
                    re.compile(r'pb\.Register(\w+)Server\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)'),
                    re.compile(r'func\s*\(\s*\w+\s*\*\s*\w+\s*\)\s*(\w+)\s*\('),
                ],
                'method_patterns': [
                    # gRPC doesn't use traditional HTTP methods, but we can detect RPC methods
                    re.compile(r'rpc\s+(\w+)\s*\('),
                    re.compile(r'func\s*\(\s*\w+\s*\*\s*\w+\s*\)\s*(\w+)\s*\([^)]*context\.Context'),
                ],
                'service_patterns': [
                    re.compile(r'service\s+(\w+)\s*\{'),
                    re.compile(r'rpc\s+(\w+)\s*\('),
                ]
            }
        }
        
        # Enhanced Go variable and constant patterns
        self.go_patterns = {
            'var_declaration': re.compile(r'var\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            'const_declaration': re.compile(r'const\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            'const_block': re.compile(r'const\s*\(\s*([^)]+)\s*\)'),
            'sprintf': re.compile(r'fmt\.Sprintf\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*,\s*([^)]+)\)'),
            'string_concat': re.compile(r'([a-zA-Z_]\w*)\s*\+\s*[\'"`]([^\'"`]+)[\'"`]'),
            'template_var': re.compile(r'%[sdvfgtT]'),
            
            # Modern Go patterns
            'embed_fs': re.compile(r'//go:embed\s+(.+)'),
            'build_tags': re.compile(r'//\s*\+build\s+(.+)'),
            'env_var': re.compile(r'os\.Getenv\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'),
            'config_struct': re.compile(r'type\s+(\w*[Cc]onfig\w*)\s+struct'),
        }
        
        # Comprehensive Go authentication patterns
        self.auth_patterns = {
            AuthType.JWT: [
                r'jwt-go',
                r'golang-jwt',
                r'dgrijalva/jwt-go',
                r'jwt\.Parse',
                r'jwt\.Token',
                r'jwt\.NewWithClaims',
                r'JWTAuth',
                r'BearerAuth',
            ],
            AuthType.OAUTH: [
                r'oauth2',
                r'golang\.org/x/oauth2',
                r'OAuthConfig',
                r'oauth2\.Config',
                r'oauth2\.Token',
            ],
            AuthType.SESSION: [
                r'sessions',
                r'gorilla/sessions',
                r'session',
                r'SessionStore',
                r'CookieStore',
            ],
            AuthType.API_KEY: [
                r'api.?key',
                r'X-API-Key',
                r'Authorization.*Bearer',
                r'APIKeyAuth',
            ],
            AuthType.BASIC: [
                r'BasicAuth',
                r'http\.Request\.BasicAuth',
                r'basic.?auth',
            ],
            AuthType.CUSTOM: [
                r'AuthMiddleware',
                r'authenticate',
                r'requireAuth',
                r'checkAuth',
                r'authHandler',
            ]
        }
        
        # Modern Go security and middleware patterns
        self.security_patterns = [
            # CORS
            r'github\.com/rs/cors',
            r'cors\.New',
            r'cors\.Default',
            
            # Rate limiting
            r'github\.com/didip/tollbooth',
            r'github\.com/ulule/limiter',
            r'ratelimit',
            
            # Security headers
            r'github\.com/unrolled/secure',
            r'secure\.New',
            
            # Input validation
            r'github\.com/go-playground/validator',
            r'validator\.New',
            r'validate\.',
            
            # Encryption
            r'crypto/',
            r'tls\.',
            r'x509\.',
        ]
        
        # Enterprise and microservice patterns
        self.enterprise_patterns = [
            # Service discovery
            r'github\.com/hashicorp/consul',
            r'consul\.',
            r'etcd',
            
            # Monitoring
            r'github\.com/prometheus/client_golang',
            r'prometheus\.',
            r'metrics\.',
            
            # Tracing
            r'go\.opentelemetry\.io',
            r'jaeger',
            r'zipkin',
            
            # Circuit breakers
            r'github\.com/afex/hystrix-go',
            r'hystrix\.',
            r'circuitbreaker',
            
            # gRPC and protobuf
            r'google\.golang\.org/protobuf',
            r'google\.golang\.org/grpc',
            r'\.pb\.go',
            
            # Message queues
            r'github\.com/nats-io/nats',
            r'github\.com/rabbitmq/amqp091-go',
            r'kafka',
        ]
        
        # gRPC specific patterns
        self.grpc_patterns = [
            r'grpc\.NewServer',
            r'grpc\.Dial',
            r'pb\.Register\w+Server',
            r'grpc\.UnaryInterceptor',
            r'grpc\.StreamInterceptor',
            r'context\.Context',
            r'status\.Error',
        ]
    
    def detect_routes(self, file_path: str, content: str) -> List[RouteInfo]:
        """
        Enhanced Go HTTP route detection with template resolution and string templating
        """
        routes = []
        self.seen_routes.clear()  # Reset for each file
        
        if not self._is_go_file(file_path, content):
            return routes
        
        try:
            # Step 1: Extract Go variables and constants
            variables = self._extract_go_variables(content)
            
            # Step 2: Detect Go HTTP framework
            framework_info = self._detect_go_framework(content)
            
            # Step 3: Extract route definitions with template resolution
            route_definitions = self._extract_go_route_definitions(content, variables, framework_info)
            
            # Step 4: Process each route definition
            for route_def in route_definitions:
                try:
                    # Create framework context for template resolution
                    context = FrameworkContext(
                        framework=Framework.GO_HTTP,
                        file_path=file_path,
                        file_content=content,
                        variables=variables,
                        configuration=framework_info
                    )
                    
                    # Resolve template if needed
                    if any(marker in route_def['path'] for marker in ['%s', '%v', '%d', 'fmt.Sprintf']):
                        resolved = self.template_resolver.resolve_template(route_def['path'], context)
                        final_path = resolved.resolved_path
                        path_params = resolved.path_parameters
                        query_params = resolved.query_parameters
                        original_path = route_def['path']
                        template_metadata = resolved.metadata
                    else:
                        final_path = self._normalize_go_path(route_def['path'])
                        path_params = self._extract_go_path_params(final_path)
                        query_params = []
                        original_path = route_def['path']
                        template_metadata = {}
                    
                    # Convert HTTP method
                    http_method = self._convert_to_http_method(route_def['method'])
                    if not http_method:
                        continue
                    
                    # Check for duplicates
                    route_key = (http_method.value, final_path, file_path)
                    if route_key in self.seen_routes:
                        continue
                    self.seen_routes.add(route_key)
                    
                    # Create enhanced route info
                    route_info = self._create_enhanced_go_route_info(
                        method=http_method,
                        path=final_path,
                        original_path=original_path,
                        file_path=file_path,
                        line_number=route_def.get('line_number', 1),
                        path_params=path_params,
                        query_params=query_params,
                        variables=variables,
                        framework_info=framework_info,
                        route_def=route_def,
                        template_metadata=template_metadata,
                        content=content
                    )
                    
                    routes.append(route_info)
                    
                except Exception as e:
                    print(f"Error processing Go route: {e}")
                    continue
            
        except Exception as e:
            print(f"Error processing Go routes in {file_path}: {e}")
        
        return routes
    
    def _is_go_file(self, file_path: str, content: str) -> bool:
        """Check if file is a Go HTTP file"""
        if not file_path.endswith('.go'):
            return False
        
        # Check for HTTP-related imports and patterns
        http_indicators = [
            'import.*net/http',
            'import.*github.com/gin-gonic/gin',
            'import.*github.com/gorilla/mux',
            'import.*github.com/labstack/echo',
            'import.*github.com/gofiber/fiber',
            'http.HandleFunc',
            'http.Handle',
            'gin.Default',
            'mux.NewRouter',
            'echo.New',
            'fiber.New'
        ]
        
        return any(re.search(indicator, content, re.IGNORECASE) for indicator in http_indicators)
    
    def _extract_go_variables(self, content: str) -> Dict[str, str]:
        """Extract Go variable declarations and constants"""
        variables = {}
        
        # Extract variable declarations
        for pattern_name, pattern in self.go_patterns.items():
            if 'declaration' in pattern_name or 'short_var' in pattern_name:
                matches = pattern.findall(content)
                for match in matches:
                    if isinstance(match, tuple) and len(match) >= 2:
                        var_name, var_value = match[0], match[1]
                        variables[var_name] = var_value
        
        # Extract package-level constants
        package_const_pattern = re.compile(r'const\s*\(\s*([^)]+)\s*\)')
        const_blocks = package_const_pattern.findall(content)
        for block in const_blocks:
            const_lines = block.strip().split('\n')
            for line in const_lines:
                const_match = re.match(r'\s*(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]', line)
                if const_match:
                    var_name, var_value = const_match.groups()
                    variables[var_name] = var_value
        
        # Extract environment variable usage
        env_pattern = re.compile(r'os\.Getenv\s*\(\s*[\'"`]([A-Z_][A-Z0-9_]*)[\'"`]\s*\)')
        env_matches = env_pattern.findall(content)
        for env_var in env_matches:
            if env_var in ['API_PREFIX', 'BASE_PATH', 'SERVER_PREFIX']:
                variables[env_var] = f"${{{env_var}}}"
        
        return variables
    
    def _detect_go_framework(self, content: str) -> Dict[str, Any]:
        """Detect which Go HTTP framework is being used"""
        framework_info = {
            'framework': 'stdlib',
            'confidence': 0.0,
            'patterns': []
        }
        
        for framework_name, framework_data in self.go_frameworks.items():
            confidence = 0.0
            matched_patterns = []
            
            # Check import patterns
            for import_pattern in framework_data['import_patterns']:
                if re.search(import_pattern, content, re.IGNORECASE):
                    confidence += 3.0
                    matched_patterns.append(f"import:{import_pattern}")
            
            # Check route patterns
            for route_pattern in framework_data['route_patterns']:
                matches = route_pattern.findall(content)
                if matches:
                    confidence += 2.0 * len(matches)
                    matched_patterns.append(f"route:{route_pattern.pattern}")
            
            # Check method patterns (if they exist for this framework)
            if 'method_patterns' in framework_data:
                for method_pattern in framework_data['method_patterns']:
                    matches = method_pattern.findall(content)
                    if matches:
                        confidence += 1.0 * len(matches)
                        matched_patterns.append(f"method:{method_pattern.pattern}")
            
            if confidence > framework_info['confidence']:
                framework_info = {
                    'framework': framework_name,
                    'confidence': confidence,
                    'patterns': matched_patterns
                }
        
        return framework_info
    
    def _extract_go_route_definitions(self, content: str, variables: Dict[str, str], framework_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract route definitions from Go HTTP code"""
        routes = []
        lines = content.split('\n')
        framework = framework_info.get('framework', 'stdlib')
        
        if framework in self.go_frameworks:
            framework_data = self.go_frameworks[framework]
            
            # Extract routes using framework-specific patterns
            for pattern in framework_data['route_patterns']:
                for i, line in enumerate(lines):
                    match = pattern.search(line)
                    if match:
                        groups = match.groups()
                        
                        if len(groups) >= 2:
                            router_var = groups[0] if len(groups) > 1 else 'router'
                            path = groups[1] if len(groups) > 1 else groups[0]
                            
                            # Extract method from the same line or nearby lines
                            method = self._extract_method_from_context(lines, i, framework)
                            
                            # Handle fmt.Sprintf patterns
                            if 'fmt.Sprintf' in line:
                                sprintf_match = self.go_patterns['sprintf'].search(line)
                                if sprintf_match:
                                    path = sprintf_match.group(0)  # Full fmt.Sprintf call
                            
                            routes.append({
                                'path': path,
                                'method': method,
                                'line_number': i + 1,
                                'router_var': router_var,
                                'framework': framework,
                                'raw_line': line.strip()
                            })
        
        return routes
    
    def _extract_method_from_context(self, lines: List[str], line_index: int, framework: str) -> str:
        """Extract HTTP method from route definition context"""
        current_line = lines[line_index]
        
        # Check current line for method
        method_patterns = {
            'gin': [
                re.compile(r'\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any)\s*\('),
            ],
            'gorilla': [
                re.compile(r'\.Methods\s*\(\s*[\'"`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[\'"`]'),
                re.compile(r'\.HandleFunc.*\.Methods.*[\'"`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[\'"`]'),
            ],
            'echo': [
                re.compile(r'\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any)\s*\('),
            ],
            'fiber': [
                re.compile(r'\.(Get|Post|Put|Delete|Patch|Head|Options|All)\s*\('),
            ],
            'stdlib': [
                re.compile(r'r\.Method\s*==\s*[\'"`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[\'"`]'),
                re.compile(r'case\s+[\'"`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[\'"`]'),
            ]
        }
        
        if framework in method_patterns:
            for pattern in method_patterns[framework]:
                match = pattern.search(current_line)
                if match:
                    return match.group(1).upper()
        
        # Check surrounding lines for method
        for offset in [-2, -1, 1, 2]:
            check_index = line_index + offset
            if 0 <= check_index < len(lines):
                check_line = lines[check_index]
                if framework in method_patterns:
                    for pattern in method_patterns[framework]:
                        match = pattern.search(check_line)
                        if match:
                            return match.group(1).upper()
        
        return 'GET'  # Default method
    
    def _normalize_go_path(self, path: str) -> str:
        """Normalize Go route path"""
        # Remove quotes
        path = path.strip('\'"')
        
        # Ensure path starts with /
        if not path.startswith('/'):
            path = '/' + path
        
        # Clean up multiple slashes
        path = re.sub(r'/+', '/', path)
        
        # Remove trailing slash unless root
        if path.endswith('/') and path != '/':
            path = path[:-1]
        
        return path
    
    def _extract_go_path_params(self, path: str) -> List[str]:
        """Extract path parameters from Go route path"""
        params = []
        
        # Gorilla Mux style: {id}
        gorilla_params = re.findall(r'\{(\w+)\}', path)
        params.extend(gorilla_params)
        
        # Gin style: :id
        gin_params = re.findall(r':(\w+)', path)
        params.extend(gin_params)
        
        # Echo style: :id
        echo_params = re.findall(r':(\w+)', path)
        params.extend(echo_params)
        
        # Wildcard parameters: *filepath
        wildcard_params = re.findall(r'\*(\w+)', path)
        params.extend(wildcard_params)
        
        return list(set(params))  # Remove duplicates
    
    def _convert_to_http_method(self, method_str: str) -> Optional[HTTPMethod]:
        """Convert string method to HTTPMethod enum"""
        method_mapping = {
            'GET': HTTPMethod.GET,
            'POST': HTTPMethod.POST,
            'PUT': HTTPMethod.PUT,
            'DELETE': HTTPMethod.DELETE,
            'PATCH': HTTPMethod.PATCH,
            'HEAD': HTTPMethod.HEAD,
            'OPTIONS': HTTPMethod.OPTIONS,
            'ANY': HTTPMethod.GET,  # Default for Any
            'ALL': HTTPMethod.ALL,  # Fixed: Go ALL -> ALL enum (not GET)
        }
        
        return method_mapping.get(method_str.upper())
    
    def _create_enhanced_go_route_info(self, method: HTTPMethod, path: str, original_path: str,
                                      file_path: str, line_number: int, path_params: List[str],
                                      query_params: List[str], variables: Dict[str, str],
                                      framework_info: Dict[str, Any], route_def: Dict[str, Any],
                                      template_metadata: Dict[str, Any], content: str) -> RouteInfo:
        """Create enhanced RouteInfo with Go-specific template resolution context"""
        
        # Extract authentication info
        auth_info = self._extract_go_auth_info(content, route_def)
        
        # Create route parameters
        route_parameters = []
        
        # Add path parameters
        for param in path_params:
            route_parameters.append(RouteParameter(
                name=param,
                type="string",
                required=True,
                location="path",
                description=f"Go path parameter: {param}"
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
        
        # Enhanced metadata
        metadata = {
            'original_template': original_path if any(marker in original_path for marker in ['%s', '%v', 'fmt.Sprintf']) else None,
            'resolved_variables': {k: v for k, v in variables.items() if k in original_path},
            'path_parameters': path_params,
            'query_parameters': query_params,
            'template_resolution': any(marker in original_path for marker in ['%s', '%v', 'fmt.Sprintf']),
            'go_framework': framework_info.get('framework'),
            'framework_confidence': framework_info.get('confidence'),
            'router_variable': route_def.get('router_var'),
            'raw_definition': route_def.get('raw_line'),
            **template_metadata
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
        if any(marker in original_path for marker in ['%s', '%v', 'fmt.Sprintf']):
            route_info.original_path = original_path
        
        # Risk assessment
        route_info.risk_level = self._assess_go_risk_level(path, method.value, route_info.auth_type, framework_info)
        route_info.risk_score = self._calculate_go_risk_score(route_info, content, route_def)
        
        return route_info
    
    def _extract_go_auth_info(self, content: str, route_def: Dict[str, Any]) -> Dict[str, Any]:
        """Extract authentication information from Go content"""
        auth_info = {
            'type': AuthType.UNKNOWN,
            'required': False
        }
        
        # Check for Go auth patterns
        for auth_type, patterns in self.auth_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    auth_info['type'] = auth_type
                    auth_info['required'] = True
                    return auth_info
        
        return auth_info
    
    def _assess_go_risk_level(self, path: str, method: str, auth_type: AuthType, framework_info: Dict[str, Any]) -> RiskLevel:
        """Assess risk level for Go routes"""
        risk_score = 0
        
        # Method-based risk
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            risk_score += 2
        
        # Path-based risk
        high_risk_patterns = [
            r'/admin', r'/api/admin', r'/internal',
            r'/debug', r'/metrics', r'/health',
            r'/delete', r'/upload', r'/config'
        ]
        
        for pattern in high_risk_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                risk_score += 3
                break
        
        # Authentication risk
        if auth_type == AuthType.UNKNOWN:
            risk_score += 4
        elif auth_type in [AuthType.BASIC, AuthType.API_KEY]:
            risk_score += 1
        
        # Framework-specific risks
        if framework_info.get('framework') == 'stdlib':
            risk_score += 1  # Standard library often has less built-in security
        
        # Map score to risk level
        if risk_score >= 7:
            return RiskLevel.CRITICAL
        elif risk_score >= 5:
            return RiskLevel.HIGH
        elif risk_score >= 3:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_go_risk_score(self, route_info: RouteInfo, content: str, route_def: Dict[str, Any]) -> float:
        """Calculate detailed risk score for Go routes"""
        base_score = 0.0
        risk_factors = []
        
        # Method-based risk
        method_risks = {
            HTTPMethod.GET: 1.0,
            HTTPMethod.POST: 2.0,
            HTTPMethod.PUT: 2.5,
            HTTPMethod.DELETE: 3.0,
            HTTPMethod.PATCH: 2.0,
            HTTPMethod.HEAD: 0.5,
            HTTPMethod.OPTIONS: 0.5,
            HTTPMethod.ALL: 3.5      # Wildcard methods - high risk
        }
        base_score += method_risks.get(route_info.method, 1.0)
        
        if route_info.method in [HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.DELETE, HTTPMethod.ALL]:
            risk_factors.append(f"High-risk HTTP method: {route_info.method}")
        
        # Authentication risk
        if route_info.auth_type == AuthType.UNKNOWN:
            base_score += 3.0
            risk_factors.append("No authentication detected")
        
        # Parameter validation risk
        if route_info.parameters:
            param_count = len(route_info.parameters)
            base_score += 0.5 * param_count
            risk_factors.append("Route parameters")
        
        # Template resolution risk
        if route_info.metadata.get('template_resolution'):
            base_score += 1.0
            risk_factors.append("Dynamic route construction")
        
        # Framework-specific risks
        framework = route_info.metadata.get('go_framework')
        if framework == 'stdlib':
            base_score += 1.0
            risk_factors.append("Standard library (fewer built-in protections)")
        
        # Store risk factors
        route_info.risk_factors = risk_factors
        
        return min(base_score, 10.0)  # Cap at 10.0 