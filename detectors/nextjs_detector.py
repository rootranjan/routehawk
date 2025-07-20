"""
NextJS Route Detector for Attack Surface Discovery

Enhanced detector with comprehensive template resolution for dynamic routing,
including file-based routing patterns, API routes, and template literal support.
"""

import os
import re
import ast
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path

from .base_detector import BaseDetector
from models import RouteInfo, SecurityFinding, Framework, HTTPMethod, AuthType, RiskLevel, RouteParameter
from analyzers.template_resolver import get_template_resolver, FrameworkContext, ResolvedRoute


class NextJSDetector(BaseDetector):
    """Enhanced Next.js detector with comprehensive template resolution and dynamic routing"""
    
    def __init__(self, framework: Framework = Framework.NEXTJS):
        super().__init__(framework)
        self.seen_routes = set()  # For deduplication
        
        # Initialize template resolver
        self.template_resolver = get_template_resolver(Framework.NEXTJS)
        
        # Next.js specific patterns
        self.api_route_patterns = [
            r'/api/',
            r'/pages/api/',
            r'/app/.*/(route\.ts|route\.js)',
            r'/src/pages/api/',
            r'/src/app/.*/(route\.ts|route\.js)'
        ]
        
        # HTTP method patterns for Next.js API routes
        self.method_patterns = {
            'GET': [
                r'export\s+async\s+function\s+GET\s*\(',
                r'export\s+function\s+GET\s*\(',
                r'export\s+default\s+function.*req\.method\s*===?\s*[\'"]GET[\'"]',
                r'case\s+[\'"]GET[\'"]:'
            ],
            'POST': [
                r'export\s+async\s+function\s+POST\s*\(',
                r'export\s+function\s+POST\s*\(',
                r'export\s+default\s+function.*req\.method\s*===?\s*[\'"]POST[\'"]',
                r'case\s+[\'"]POST[\'"]:'
            ],
            'PUT': [
                r'export\s+async\s+function\s+PUT\s*\(',
                r'export\s+function\s+PUT\s*\(',
                r'export\s+default\s+function.*req\.method\s*===?\s*[\'"]PUT[\'"]',
                r'case\s+[\'"]PUT[\'"]:'
            ],
            'DELETE': [
                r'export\s+async\s+function\s+DELETE\s*\(',
                r'export\s+function\s+DELETE\s*\(',
                r'export\s+default\s+function.*req\.method\s*===?\s*[\'"]DELETE[\'"]',
                r'case\s+[\'"]DELETE[\'"]:'
            ],
            'PATCH': [
                r'export\s+async\s+function\s+PATCH\s*\(',
                r'export\s+function\s+PATCH\s*\(',
                r'export\s+default\s+function.*req\.method\s*===?\s*[\'"]PATCH[\'"]',
                r'case\s+[\'"]PATCH[\'"]:'
            ]
        }
        
        # Middleware patterns
        self.middleware_patterns = [
            r'export\s+function\s+middleware\s*\(',
            r'export\s+async\s+function\s+middleware\s*\(',
            r'middleware\.ts',
            r'middleware\.js',
            r'_middleware\.ts',
            r'_middleware\.js'
        ]
        
        # Authentication patterns specific to Next.js
        self.auth_patterns = [
            r'withAuth\(',
            r'getServerSession\(',
            r'unstable_getServerSession\(',
            r'getSession\(',
            r'useSession\(',
            r'signIn\(',
            r'signOut\(',
            r'NextAuth\(',
            r'jwt\(',
            r'session\(',
            r'authorize\(',
            r'getToken\(',
            r'withIronSession\(',
            r'iron-session',
            r'next-auth',
            r'@yourorg/auth'
        ]
        
        # Input validation patterns
        self.validation_patterns = [
            r'joi\.validate\(',
            r'yup\.validate\(',
            r'z\.parse\(',
            r'zod\.parse\(',
            r'validate\(',
            r'sanitize\(',
            r'escape\(',
            r'validator\.',
            r'express-validator',
            r'class-validator'
        ]

    def can_handle_file(self, file_path: str, content: str) -> bool:
        """Check if this detector can handle the given file"""
        if not (file_path.endswith('.ts') or file_path.endswith('.js') or file_path.endswith('.tsx') or file_path.endswith('.jsx')):
            return False
            
        # Check if it's a Next.js API route or page
        for pattern in self.api_route_patterns:
            if re.search(pattern, file_path):
                return True
                
        # Check if it's in a Next.js project structure
        nextjs_indicators = [
            'pages/',
            'app/',
            'next.config.',
            'middleware.',
            '_app.',
            '_document.',
            'api/'
        ]
        
        # Additional content-based detection for Next.js
        if any(indicator in file_path for indicator in nextjs_indicators):
            return True
        
        # Check content for Next.js specific imports or patterns
        if content:
            nextjs_content_indicators = [
                'next/router',
                'next/head',
                'next/image',
                'next/link',
                'next/app',
                'next/server',
                'NextRequest',
                'NextResponse',
                'export default function',
                'export { GET, POST'
            ]
            return any(indicator in content for indicator in nextjs_content_indicators)
        
        return False

    def detect_routes(self, file_path: str, content: str) -> List[RouteInfo]:
        """Enhanced Next.js route detection with template resolution and dynamic routing"""
        routes = []
        self.seen_routes.clear()  # Reset for each file
        
        if not self.can_handle_file(file_path, content):
            return routes
        
        try:
            # Step 1: Extract Next.js variables and configuration
            variables = self._extract_nextjs_variables(content)
            
            # Step 2: Analyze file structure for routing context
            route_context = self._analyze_nextjs_file_structure(file_path, content)
            
            # Step 3: Detect and process different route types with template resolution
            
            # API routes with template resolution
            api_routes = self._detect_enhanced_api_routes(file_path, content, variables, route_context)
            routes.extend(api_routes)
            
            # Page routes with dynamic routing
            page_routes = self._detect_enhanced_page_routes(file_path, content, variables, route_context)
            routes.extend(page_routes)
            
            # Middleware routes
            middleware_routes = self._detect_enhanced_middleware_routes(file_path, content, variables, route_context)
            routes.extend(middleware_routes)
            
        except Exception as e:
            self.logger.error(f"Error detecting routes in {file_path}: {str(e)}")
            
        return routes

    def _detect_api_routes(self, file_path: str, content: str) -> List[RouteInfo]:
        """Detect Next.js API routes"""
        routes = []
        
        # Convert file path to API route path
        api_path = self._file_path_to_api_route(file_path)
        if not api_path:
            return routes
            
        # Detect HTTP methods
        methods = self._detect_http_methods(content)
        
        for method in methods:
            route = RouteInfo(
                method=method,
                path=api_path,
                file_path=file_path,
                framework=self.framework,
                auth_required=self._check_auth_required(content),
                parameters=self._extract_parameters(content, api_path),
                description=self._extract_description(content),
                middleware=self._extract_middleware(content)
            )
            routes.append(route)
            
        # If no specific methods found, assume GET for default export
        if not methods and self._has_default_export(content):
            route = RouteInfo(
                method="GET",
                path=api_path,
                file_path=file_path,
                framework=self.framework,
                auth_required=self._check_auth_required(content),
                parameters=self._extract_parameters(content, api_path),
                description=self._extract_description(content),
                middleware=self._extract_middleware(content)
            )
            routes.append(route)
            
        return routes

    def _detect_page_routes(self, file_path: str, content: str) -> List[RouteInfo]:
        """Detect Next.js page routes"""
        routes = []
        
        # Convert file path to page route
        page_path = self._file_path_to_page_route(file_path)
        if not page_path:
            return routes
            
        # Check if it's a valid page (has default export or specific patterns)
        if self._is_valid_page(content):
            route = RouteInfo(
                method="GET",
                path=page_path,
                file_path=file_path,
                framework=self.framework,
                auth_required=self._check_auth_required(content),
                parameters=self._extract_page_parameters(content, page_path),
                description=self._extract_description(content),
                middleware=self._extract_middleware(content)
            )
            routes.append(route)
            
        return routes

    def _detect_middleware_routes(self, file_path: str, content: str) -> List[RouteInfo]:
        """Detect Next.js middleware"""
        routes = []
        
        # Check if file contains middleware
        for pattern in self.middleware_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                # Extract matcher configuration
                matcher_paths = self._extract_middleware_matcher(content)
                
                if not matcher_paths:
                    matcher_paths = ["/*"]  # Default to all paths
                    
                for path in matcher_paths:
                    route = RouteInfo(
                        method="MIDDLEWARE",
                        path=path,
                        file_path=file_path,
                        framework=self.framework,
                        auth_required=False,  # Middleware itself doesn't require auth
                        parameters=[],
                        description="Next.js Middleware",
                        middleware=[]
                    )
                    routes.append(route)
                break
                
        return routes

    def _file_path_to_api_route(self, file_path: str) -> Optional[str]:
        """Convert file path to API route path"""
        # Handle different Next.js project structures
        patterns = [
            (r'.*/pages/api/(.+)\.(ts|js)$', r'/api/\1'),
            (r'.*/src/pages/api/(.+)\.(ts|js)$', r'/api/\1'),
            (r'.*/app/(.+)/route\.(ts|js)$', r'/\1'),
            (r'.*/src/app/(.+)/route\.(ts|js)$', r'/\1')
        ]
        
        for pattern, replacement in patterns:
            match = re.search(pattern, file_path)
            if match:
                route_path = re.sub(pattern, replacement, file_path)
                # Convert [...slug] to {slug} for dynamic routes
                route_path = re.sub(r'\[\.\.\.(\w+)\]', r'{...\\1}', route_path)
                # Convert [slug] to {slug} for dynamic routes
                route_path = re.sub(r'\[(\w+)\]', r'{\\1}', route_path)
                return route_path
                
        return None

    def _file_path_to_page_route(self, file_path: str) -> Optional[str]:
        """Convert file path to page route path"""
        # Handle different Next.js page structures
        patterns = [
            (r'.*/pages/(.+)\.(ts|js|tsx|jsx)$', r'/\1'),
            (r'.*/src/pages/(.+)\.(ts|js|tsx|jsx)$', r'/\1'),
            (r'.*/app/(.+)/page\.(ts|js|tsx|jsx)$', r'/\1'),
            (r'.*/src/app/(.+)/page\.(ts|js|tsx|jsx)$', r'/\1')
        ]
        
        for pattern, replacement in patterns:
            match = re.search(pattern, file_path)
            if match:
                route_path = re.sub(pattern, replacement, file_path)
                # Convert [...slug] to {slug} for dynamic routes
                route_path = re.sub(r'\[\.\.\.(\w+)\]', r'{...\\1}', route_path)
                # Convert [slug] to {slug} for dynamic routes
                route_path = re.sub(r'\[(\w+)\]', r'{\\1}', route_path)
                # Handle index routes
                route_path = re.sub(r'/index$', '', route_path)
                if not route_path:
                    route_path = '/'
                return route_path
                
        return None

    def _detect_http_methods(self, content: str) -> List[str]:
        """Detect HTTP methods in Next.js API routes"""
        methods = []
        
        for method, patterns in self.method_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    methods.append(method)
                    break
                    
        return list(set(methods))

    def _has_default_export(self, content: str) -> bool:
        """Check if file has a default export function"""
        patterns = [
            r'export\s+default\s+function',
            r'export\s+default\s+async\s+function',
            r'export\s+{\s*\w+\s+as\s+default\s*}',
            r'module\.exports\s*=',
            r'exports\.default\s*='
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns)

    def _is_valid_page(self, content: str) -> bool:
        """Check if content represents a valid Next.js page"""
        # Check for React component patterns
        react_patterns = [
            r'export\s+default\s+function\s+\w+',
            r'export\s+default\s+\w+',
            r'function\s+\w+.*return\s*\(',
            r'const\s+\w+\s*=.*=>\s*{',
            r'React\.Component',
            r'Component\s*{',
            r'<.*>.*</.*>',  # JSX
            r'createElement\(',
            r'getStaticProps',
            r'getServerSideProps',
            r'getStaticPaths'
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE | re.DOTALL) for pattern in react_patterns)

    def _extract_middleware_matcher(self, content: str) -> List[str]:
        """Extract middleware matcher configuration"""
        paths = []
        
        # Look for matcher config
        matcher_patterns = [
            r'matcher:\s*\[(.*?)\]',
            r'matcher:\s*[\'"]([^\'"]+)[\'"]',
            r'config\.matcher\s*=\s*\[(.*?)\]',
            r'config\.matcher\s*=\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in matcher_patterns:
            matches = re.finditer(pattern, content, re.DOTALL)
            for match in matches:
                matcher_content = match.group(1)
                # Extract individual paths
                path_matches = re.findall(r'[\'"]([^\'"]+)[\'"]', matcher_content)
                paths.extend(path_matches)
                
        return paths

    def _check_auth_required(self, content: str) -> bool:
        """Check if authentication is required"""
        for pattern in self.auth_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def _extract_parameters(self, content: str, route_path: str) -> List[Dict[str, Any]]:
        """Extract route parameters"""
        parameters = []
        
        # Extract from route path (dynamic segments)
        dynamic_segments = re.findall(r'\{([^}]+)\}', route_path)
        for segment in dynamic_segments:
            param_type = "string"
            if segment.startswith("..."):
                param_type = "array"
                segment = segment[3:]
                
            parameters.append({
                "name": segment,
                "type": param_type,
                "location": "path",
                "required": True
            })
            
        # Extract query parameters from content
        query_patterns = [
            r'req\.query\.(\w+)',
            r'query\.(\w+)',
            r'searchParams\.get\([\'"](\w+)[\'"]',
            r'router\.query\.(\w+)'
        ]
        
        for pattern in query_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                param_name = match.group(1)
                if not any(p["name"] == param_name for p in parameters):
                    parameters.append({
                        "name": param_name,
                        "type": "string",
                        "location": "query",
                        "required": False
                    })
                    
        # Extract body parameters
        body_patterns = [
            r'req\.body\.(\w+)',
            r'body\.(\w+)',
            r'await\s+req\.json\(\)',
            r'await\s+request\.json\(\)'
        ]
        
        for pattern in body_patterns:
            if re.search(pattern, content):
                parameters.append({
                    "name": "body",
                    "type": "object",
                    "location": "body",
                    "required": True
                })
                break
                
        return parameters

    def _extract_page_parameters(self, content: str, route_path: str) -> List[Dict[str, Any]]:
        """Extract parameters for page routes"""
        parameters = []
        
        # Extract from route path (dynamic segments)
        dynamic_segments = re.findall(r'\{([^}]+)\}', route_path)
        for segment in dynamic_segments:
            param_type = "string"
            if segment.startswith("..."):
                param_type = "array"
                segment = segment[3:]
                
            parameters.append({
                "name": segment,
                "type": param_type,
                "location": "path",
                "required": True
            })
            
        # Extract from getServerSideProps or getStaticProps
        if re.search(r'getServerSideProps|getStaticProps', content):
            # Look for context.params usage
            param_matches = re.finditer(r'context\.params\.(\w+)', content)
            for match in param_matches:
                param_name = match.group(1)
                if not any(p["name"] == param_name for p in parameters):
                    parameters.append({
                        "name": param_name,
                        "type": "string",
                        "location": "path",
                        "required": True
                    })
                    
            # Look for context.query usage
            query_matches = re.finditer(r'context\.query\.(\w+)', content)
            for match in query_matches:
                param_name = match.group(1)
                if not any(p["name"] == param_name for p in parameters):
                    parameters.append({
                        "name": param_name,
                        "type": "string",
                        "location": "query",
                        "required": False
                    })
                    
        return parameters

    def _extract_description(self, content: str) -> str:
        """Extract route description from comments or JSDoc"""
        # Look for JSDoc comments
        jsdoc_pattern = r'/\*\*(.*?)\*/'
        jsdoc_matches = re.findall(jsdoc_pattern, content, re.DOTALL)
        
        for match in jsdoc_matches:
            # Clean up the comment
            description = re.sub(r'\*', '', match).strip()
            if description and len(description) > 10:
                return description[:200] + "..." if len(description) > 200 else description
                
        # Look for single line comments above function
        comment_pattern = r'//\s*(.+)\s*\n\s*export\s+(async\s+)?function'
        comment_matches = re.findall(comment_pattern, content)
        
        if comment_matches:
            return comment_matches[0][0].strip()
            
        return ""

    def _extract_middleware(self, content: str) -> List[str]:
        """Extract middleware information"""
        middleware = []
        
        # Common Next.js middleware patterns
        middleware_patterns = {
            'cors': r'cors\(',
            'body-parser': r'bodyParser\(',
            'cookie-parser': r'cookieParser\(',
            'compression': r'compression\(',
            'helmet': r'helmet\(',
            'rate-limit': r'rateLimit\(',
            'auth': r'withAuth\(',
            'session': r'withSession\(',
            'iron-session': r'withIronSession\(',
            'next-auth': r'NextAuth\('
        }
        
        for name, pattern in middleware_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                middleware.append(name)
                
        return middleware

    def analyze_security(self, routes: List[RouteInfo], content: str) -> List[SecurityFinding]:
        """Analyze security aspects of Next.js routes"""
        findings = []
        
        for route in routes:
            # Check for missing authentication
            if not route.auth_required and self._is_sensitive_route(route.path):
                findings.append(SecurityFinding(
                    type="Missing Authentication",
                    severity="HIGH",
                    description=f"Sensitive route {route.path} may be missing authentication",
                    file_path=route.file_path,
                    line_number=1,
                    recommendation="Add authentication middleware or checks"
                ))
                
            # Check for missing input validation
            if not self._has_input_validation(content) and route.parameters:
                findings.append(SecurityFinding(
                    type="Missing Input Validation",
                    severity="MEDIUM",
                    description=f"Route {route.path} may be missing input validation",
                    file_path=route.file_path,
                    line_number=1,
                    recommendation="Add input validation using joi, yup, or zod"
                ))
                
            # Check for potential CSRF issues
            if route.method in ['POST', 'PUT', 'DELETE', 'PATCH'] and not self._has_csrf_protection(content):
                findings.append(SecurityFinding(
                    type="Missing CSRF Protection",
                    severity="MEDIUM",
                    description=f"State-changing route {route.path} may be missing CSRF protection",
                    file_path=route.file_path,
                    line_number=1,
                    recommendation="Implement CSRF protection for state-changing operations"
                ))
                
        return findings

    def _is_sensitive_route(self, path: str) -> bool:
        """Check if route path indicates sensitive functionality"""
        sensitive_patterns = [
            r'/admin',
            r'/api/admin',
            r'/api/.*/(user|profile|account)',
            r'/api/.*/(payment|billing|transaction)',
            r'/api/.*/(auth|login|signup)',
            r'/api/.*/internal',
            r'/api/.*/private'
        ]
        
        return any(re.search(pattern, path, re.IGNORECASE) for pattern in sensitive_patterns)

    def _has_input_validation(self, content: str) -> bool:
        """Check if content has input validation"""
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in self.validation_patterns)

    def _has_csrf_protection(self, content: str) -> bool:
        """Check if content has CSRF protection"""
        csrf_patterns = [
            r'csrf',
            r'csrfToken',
            r'getToken.*csrf',
            r'verifyToken',
            r'sameOrigin',
            r'sameSite'
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in csrf_patterns)
    
    # Enhanced template resolution methods
    
    def _extract_nextjs_variables(self, content: str) -> Dict[str, str]:
        """Extract Next.js variable declarations and configuration"""
        variables = {}
        
        # Variable declaration patterns
        patterns = {
            'const_declaration': re.compile(r'const\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            'let_declaration': re.compile(r'let\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            'var_declaration': re.compile(r'var\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            'export_const': re.compile(r'export\s+const\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            'config_object': re.compile(r'export\s+const\s+config\s*=\s*\{([^}]+)\}'),
        }
        
        # Extract basic variable declarations
        for pattern_name, pattern in patterns.items():
            if pattern_name != 'config_object':
                matches = pattern.findall(content)
                for var_name, var_value in matches:
                    variables[var_name] = var_value
        
        # Extract configuration objects
        config_matches = patterns['config_object'].findall(content)
        for config_body in config_matches:
            config_lines = config_body.split(',')
            for line in config_lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().strip('\'"')
                    value = value.strip().strip('\'"').strip(',')
                    if key and value:
                        variables[f"config.{key}"] = value
        
        # Extract environment variables usage
        env_pattern = re.compile(r'process\.env\.([A-Z_][A-Z0-9_]*)')
        env_matches = env_pattern.findall(content)
        for env_var in env_matches:
            if env_var in ['API_BASE_URL', 'API_PREFIX', 'BASE_PATH', 'NEXT_PUBLIC_API_URL']:
                variables[env_var] = f"${{{env_var}}}"
        
        return variables
    
    def _analyze_nextjs_file_structure(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze Next.js file structure to determine routing context"""
        context = {
            'router_type': None,
            'is_api': False,
            'is_page': False,
            'is_middleware': False,
            'dynamic_segments': [],
            'base_path': ''
        }
        
        # Determine router type
        if '/app/' in file_path or file_path.startswith('app/'):
            context['router_type'] = 'app_router'
        elif '/pages/' in file_path or file_path.startswith('pages/'):
            context['router_type'] = 'pages_router'
        
        # Check file type
        if '/api/' in file_path or 'route.' in file_path:
            context['is_api'] = True
        elif any(pattern in file_path for pattern in ['middleware.', '_middleware.']):
            context['is_middleware'] = True
        else:
            context['is_page'] = True
        
        # Extract dynamic segments and base path
        context['base_path'], context['dynamic_segments'] = self._extract_route_path_from_file(file_path)
        
        return context
    
    def _extract_route_path_from_file(self, file_path: str) -> Tuple[str, List[str]]:
        """Extract route path and dynamic segments from file path"""
        path_obj = Path(file_path)
        dynamic_segments = []
        
        # Extract route path based on Next.js conventions
        if '/pages/' in file_path:
            route_part = file_path.split('/pages/', 1)[1]
        elif '/app/' in file_path:
            route_part = file_path.split('/app/', 1)[1]
        elif file_path.startswith('pages/'):
            route_part = file_path[6:]
        elif file_path.startswith('app/'):
            route_part = file_path[4:]
        else:
            route_part = file_path
        
        # Remove file extensions and special files
        route_part = re.sub(r'\.(js|ts|jsx|tsx)$', '', route_part)
        route_part = re.sub(r'/(route|page|layout|loading|error)$', '', route_part)
        
        # Handle index files
        if route_part.endswith('/index'):
            route_part = route_part[:-6] or '/'
        elif route_part == 'index':
            route_part = '/'
        
        # Process dynamic segments
        processed_path = route_part
        
        # Handle optional catch-all: [[...slug]]
        optional_catch_all = re.findall(r'\[\[\.\.\.([^\]]+)\]\]', processed_path)
        for param in optional_catch_all:
            dynamic_segments.append(f"...{param}?")
            processed_path = processed_path.replace(f'[[...{param}]]', f'{{{param}?}}')
        
        # Handle catch-all: [...slug]
        catch_all = re.findall(r'\[\.\.\.([^\]]+)\]', processed_path)
        for param in catch_all:
            dynamic_segments.append(f"...{param}")
            processed_path = processed_path.replace(f'[...{param}]', f'{{...{param}}}')
        
        # Handle dynamic segments: [id]
        dynamic = re.findall(r'\[([^\]]+)\]', processed_path)
        for param in dynamic:
            if not param.startswith('...'):  # Skip catch-all already processed
                dynamic_segments.append(param)
                processed_path = processed_path.replace(f'[{param}]', f'{{{param}}}')
        
        # Ensure path starts with /
        if processed_path and not processed_path.startswith('/'):
            processed_path = '/' + processed_path
        elif not processed_path:
            processed_path = '/'
        
        return processed_path, dynamic_segments
    
    def _detect_enhanced_api_routes(self, file_path: str, content: str, variables: Dict[str, str], context: Dict[str, Any]) -> List[RouteInfo]:
        """Detect API routes with enhanced template resolution"""
        routes = []
        
        if not context.get('is_api'):
            return routes
        
        # Extract HTTP method handlers
        handlers = self._extract_http_method_handlers(content)
        
        for handler in handlers:
            try:
                # Create framework context for template resolution
                framework_context = FrameworkContext(
                    framework=Framework.NEXTJS,
                    file_path=file_path,
                    file_content=content,
                    variables=variables,
                    configuration=context
                )
                
                # Get base path from file structure
                base_path = context.get('base_path', '/')
                
                # Resolve templates if needed
                if '${' in base_path:
                    resolved = self.template_resolver.resolve_template(base_path, framework_context)
                    final_path = resolved.resolved_path
                    template_metadata = resolved.metadata
                else:
                    final_path = base_path
                    template_metadata = {}
                
                # Convert HTTP method
                http_method = self._convert_method_to_enum(handler['method'])
                if not http_method:
                    continue
                
                # Check for duplicates
                route_key = (http_method.value, final_path, file_path)
                if route_key in self.seen_routes:
                    continue
                self.seen_routes.add(route_key)
                
                # Create enhanced route info
                route_info = self._create_enhanced_nextjs_route_info(
                    method=http_method,
                    path=final_path,
                    original_path=base_path,
                    file_path=file_path,
                    line_number=handler.get('line_number', 1),
                    dynamic_segments=context.get('dynamic_segments', []),
                    variables=variables,
                    context=context,
                    handler=handler,
                    template_metadata=template_metadata,
                    content=content
                )
                
                routes.append(route_info)
                
            except Exception as e:
                print(f"Error processing Next.js API handler: {e}")
                continue
        
        return routes
    
    def _detect_enhanced_page_routes(self, file_path: str, content: str, variables: Dict[str, str], context: Dict[str, Any]) -> List[RouteInfo]:
        """Detect page routes with dynamic routing support"""
        routes = []
        
        if not context.get('is_page'):
            return routes
        
        try:
            # Create framework context
            framework_context = FrameworkContext(
                framework=Framework.NEXTJS,
                file_path=file_path,
                file_content=content,
                variables=variables,
                configuration=context
            )
            
            # Get base path from file structure
            base_path = context.get('base_path', '/')
            
            # Resolve templates if needed
            if '${' in base_path:
                resolved = self.template_resolver.resolve_template(base_path, framework_context)
                final_path = resolved.resolved_path
                template_metadata = resolved.metadata
            else:
                final_path = base_path
                template_metadata = {}
            
            # Pages are typically GET requests
            http_method = HTTPMethod.GET
            
            # Check for duplicates
            route_key = (http_method.value, final_path, file_path)
            if route_key in self.seen_routes:
                return routes
            self.seen_routes.add(route_key)
            
            # Create route info for page
            route_info = self._create_enhanced_nextjs_route_info(
                method=http_method,
                path=final_path,
                original_path=base_path,
                file_path=file_path,
                line_number=1,
                dynamic_segments=context.get('dynamic_segments', []),
                variables=variables,
                context=context,
                handler={'method': 'GET', 'type': 'page_component'},
                template_metadata=template_metadata,
                content=content
            )
            
            routes.append(route_info)
            
        except Exception as e:
            print(f"Error processing Next.js page route: {e}")
        
        return routes
    
    def _detect_enhanced_middleware_routes(self, file_path: str, content: str, variables: Dict[str, str], context: Dict[str, Any]) -> List[RouteInfo]:
        """Detect middleware routes with template resolution"""
        routes = []
        
        if not context.get('is_middleware'):
            return routes
        
        # Middleware typically matches all routes
        middleware_patterns = [
            r'export\s+function\s+middleware',
            r'export\s+async\s+function\s+middleware'
        ]
        
        for pattern in middleware_patterns:
            if re.search(pattern, content):
                try:
                    route_info = self._create_enhanced_nextjs_route_info(
                        method=HTTPMethod.OPTIONS,  # Middleware intercepts all methods
                        path='/*',  # Middleware typically matches all paths
                        original_path='/*',
                        file_path=file_path,
                        line_number=1,
                        dynamic_segments=[],
                        variables=variables,
                        context=context,
                        handler={'method': 'MIDDLEWARE', 'type': 'middleware'},
                        template_metadata={},
                        content=content
                    )
                    
                    routes.append(route_info)
                    break
                    
                except Exception as e:
                    print(f"Error processing Next.js middleware: {e}")
        
        return routes
    
    def _extract_http_method_handlers(self, content: str) -> List[Dict[str, Any]]:
        """Extract HTTP method handlers from Next.js API routes"""
        handlers = []
        lines = content.split('\n')
        
        # App Router: export async function GET/POST/etc
        for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
            pattern = rf'export\s+(?:async\s+)?function\s+{method}\s*\([^)]*\)'
            for i, line in enumerate(lines):
                if re.search(pattern, line, re.IGNORECASE):
                    handlers.append({
                        'method': method,
                        'line_number': i + 1,
                        'type': 'app_router_handler',
                        'is_async': 'async' in line.lower(),
                        'signature': line.strip()
                    })
        
        # Pages Router: export default function handler
        default_handler_pattern = r'export\s+default\s+(?:async\s+)?function'
        for i, line in enumerate(lines):
            if re.search(default_handler_pattern, line, re.IGNORECASE):
                handlers.append({
                    'method': 'ALL',  # Pages Router default handler handles all methods
                    'line_number': i + 1,
                    'type': 'pages_router_handler',
                    'is_async': 'async' in line.lower(),
                    'signature': line.strip()
                })
        
        # If no handlers found, assume it's a page component
        if not handlers:
            handlers.append({
                'method': 'GET',
                'line_number': 1,
                'type': 'page_component',
                'is_async': False,
                'signature': 'Page Component'
            })
        
        return handlers
    
    def _convert_method_to_enum(self, method_str: str) -> Optional[HTTPMethod]:
        """Convert string method to HTTPMethod enum"""
        method_mapping = {
            'GET': HTTPMethod.GET,
            'POST': HTTPMethod.POST,
            'PUT': HTTPMethod.PUT,
            'DELETE': HTTPMethod.DELETE,
            'PATCH': HTTPMethod.PATCH,
            'HEAD': HTTPMethod.HEAD,
            'OPTIONS': HTTPMethod.OPTIONS,
            'ALL': HTTPMethod.ALL,  # Fixed: Pages Router ALL -> ALL enum (not GET)
        }
        
        return method_mapping.get(method_str.upper())
    
    def _create_enhanced_nextjs_route_info(self, method: HTTPMethod, path: str, original_path: str,
                                          file_path: str, line_number: int, dynamic_segments: List[str],
                                          variables: Dict[str, str], context: Dict[str, Any],
                                          handler: Dict[str, Any], template_metadata: Dict[str, Any],
                                          content: str) -> RouteInfo:
        """Create enhanced RouteInfo with Next.js-specific context"""
        
        # Extract authentication info
        auth_info = self._extract_nextjs_auth_info(content, handler)
        
        # Create route parameters from dynamic segments
        route_parameters = []
        for segment in dynamic_segments:
            param_type = "string"
            required = True
            
            if segment.startswith('...'):
                param_type = "array"
                segment = segment[3:]  # Remove ...
                if segment.endswith('?'):
                    required = False
                    segment = segment[:-1]  # Remove ?
            
            route_parameters.append(RouteParameter(
                name=segment,
                type=param_type,
                required=required,
                location="path",
                description=f"Next.js dynamic segment: {segment}"
            ))
        
        # Enhanced metadata
        metadata = {
            'original_template': original_path if '${' in original_path else None,
            'resolved_variables': {k: v for k, v in variables.items() if f'${{{k}}}' in original_path},
            'dynamic_segments': dynamic_segments,
            'template_resolution': '${' in original_path,
            'nextjs_router_type': context.get('router_type'),
            'is_api_route': context.get('is_api', False),
            'is_middleware': context.get('is_middleware', False),
            'handler_type': handler.get('type'),
            'handler_signature': handler.get('signature'),
            'is_async': handler.get('is_async', False),
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
        if '${' in original_path:
            route_info.original_path = original_path
        
        # Risk assessment
        route_info.risk_level = self._assess_nextjs_risk_level(path, method.value, route_info.auth_type, context, handler)
        route_info.risk_score = self._calculate_nextjs_risk_score(route_info, content, handler)
        
        return route_info
    
    def _extract_nextjs_auth_info(self, content: str, handler: Dict[str, Any]) -> Dict[str, Any]:
        """Extract authentication information from Next.js content"""
        auth_info = {
            'type': AuthType.UNKNOWN,
            'required': False
        }
        
        # Check for Next.js auth patterns
        nextjs_auth_patterns = {
            AuthType.SESSION: [
                r'getServerSession', r'getSession', r'useSession',
                r'next-auth', r'iron-session'
            ],
            AuthType.JWT: [
                r'jwt\.verify', r'jsonwebtoken', r'jose',
                r'verifyJwt', r'validateToken'
            ],
            AuthType.API_KEY: [
                r'api.*key', r'x-api-key', r'authorization.*bearer'
            ],
            AuthType.OAUTH: [
                r'next-auth.*oauth', r'getProviders', r'signIn.*provider'
            ],
            AuthType.CUSTOM: [
                r'withAuth', r'requireAuth', r'checkAuth', r'middleware.*auth'
            ]
        }
        
        for auth_type, patterns in nextjs_auth_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    auth_info['type'] = auth_type
                    auth_info['required'] = True
                    return auth_info
        
        return auth_info
    
    def _assess_nextjs_risk_level(self, path: str, method: str, auth_type: AuthType, 
                                 context: Dict[str, Any], handler: Dict[str, Any]) -> RiskLevel:
        """Assess risk level for Next.js routes"""
        risk_score = 0
        
        # Method-based risk
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            risk_score += 2
        
        # API vs page risk
        if context.get('is_api'):
            risk_score += 1
        
        # Path-based risk
        high_risk_patterns = [
            r'/api/admin', r'/api/internal', r'/api/auth',
            r'/admin', r'/dashboard', r'/api/upload',
            r'/api/delete', r'/api/config', r'/api/webhook'
        ]
        
        for pattern in high_risk_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                risk_score += 3
                break
        
        # Authentication risk
        if auth_type == AuthType.UNKNOWN and context.get('is_api'):
            risk_score += 4
        elif auth_type == AuthType.UNKNOWN:
            risk_score += 1  # Pages without auth less critical
        
        # Dynamic routing risk
        if context.get('dynamic_segments'):
            risk_score += 1
        
        # Map score to risk level
        if risk_score >= 7:
            return RiskLevel.CRITICAL
        elif risk_score >= 5:
            return RiskLevel.HIGH
        elif risk_score >= 3:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_nextjs_risk_score(self, route_info: RouteInfo, content: str, handler: Dict[str, Any]) -> float:
        """Calculate detailed risk score for Next.js routes"""
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
            if route_info.metadata.get('is_api_route'):
                base_score += 3.0
                risk_factors.append("Unauthenticated API endpoint")
            else:
                base_score += 1.0
                risk_factors.append("Unauthenticated page")
        
        # Dynamic routing risk
        if route_info.parameters:
            param_count = len(route_info.parameters)
            base_score += 0.5 * param_count
            risk_factors.append("Dynamic route parameters")
        
        # Template resolution risk
        if route_info.metadata.get('template_resolution'):
            base_score += 1.0
            risk_factors.append("Template variable resolution")
        
        # API route specific risks
        if route_info.metadata.get('is_api_route'):
            base_score += 1.0
            risk_factors.append("API endpoint")
        
        # Middleware risks
        if route_info.metadata.get('is_middleware'):
            base_score += 0.5
            risk_factors.append("Global middleware")
        
        # Store risk factors
        route_info.risk_factors = risk_factors
        
        return min(base_score, 10.0)  # Cap at 10.0 