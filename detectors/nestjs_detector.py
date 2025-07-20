"""
Enhanced NestJS detector for modern enterprise applications.
Supports advanced decorators, microservices, GraphQL, Swagger, and enterprise patterns.
"""

import re
import os
import logging
from typing import List, Optional, Dict, Any, Set, Tuple
from pathlib import Path

from .base_detector import BaseDetector
from models import RouteInfo, Framework, HTTPMethod, AuthType, RouteParameter, SecurityFinding, RiskLevel
from analyzers.template_resolver import get_template_resolver, FrameworkContext, ResolvedRoute


class NestJSDetector(BaseDetector):
    """
    Enhanced NestJS detector with comprehensive modern framework support.
    Supports controllers, microservices, GraphQL, WebSockets, and enterprise patterns.
    """
    
    def __init__(self, framework: Framework = Framework.NESTJS):
        super().__init__(framework)
        self.seen_routes = set()  # For deduplication
        
        # Initialize template resolver
        self.template_resolver = get_template_resolver(Framework.NESTJS)
        
        # Enhanced NestJS framework detection indicators
        self.nestjs_indicators = [
            # Core NestJS imports
            r'@nestjs/common',
            r'@nestjs/core',
            r'@nestjs/platform-express',
            r'@nestjs/platform-fastify',
            
            # NestJS decorators
            r'@Controller',
            r'@Injectable',
            r'@Module',
            r'@Get',
            r'@Post',
            r'@Put',
            r'@Delete',
            r'@Patch',
            r'@UseGuards',
            r'@UseInterceptors',
            
            # Microservices
            r'@nestjs/microservices',
            r'@MessagePattern',
            r'@EventPattern',
            r'@GrpcMethod',
            r'@GrpcStreamMethod',
            
            # GraphQL
            r'@nestjs/graphql',
            r'@Resolver',
            r'@Query',
            r'@Mutation',
            r'@Subscription',
            r'@Field',
            r'@ObjectType',
            r'@InputType',
            
            # WebSockets
            r'@nestjs/websockets',
            r'@WebSocketGateway',
            r'@SubscribeMessage',
            r'@WebSocketServer',
            
            # Swagger/OpenAPI
            r'@nestjs/swagger',
            r'@ApiProperty',
            r'@ApiOperation',
            r'@ApiResponse',
            r'@ApiTags',
            r'@ApiBearerAuth',
            
            # Enterprise patterns
            r'@nestjs/config',
            r'@nestjs/typeorm',
            r'@nestjs/mongoose',
            r'@nestjs/passport',
            r'@nestjs/jwt',
            r'@nestjs/throttler',
            r'@nestjs/cache-manager',
        ]
        
        # Comprehensive NestJS route patterns with template literal support
        self.route_patterns = [
            # Controller-level routing with decorators
            re.compile(r'@Controller\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            re.compile(r'@Controller\s*\(\s*`([^`]*)`\s*\)'),  # Template literals in controllers
            
            # Method decorators with paths
            re.compile(r'@(Get|Post|Put|Delete|Patch|Head|Options|All)\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            re.compile(r'@(Get|Post|Put|Delete|Patch|Head|Options|All)\s*\(\s*`([^`]*)`\s*\)'),  # Template literals
            
            # Route decorator (generic)
            re.compile(r'@Route\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*,\s*[\'"`](GET|POST|PUT|DELETE|PATCH)[\'"`]\s*\)'),
            
            # API versioning patterns
            re.compile(r'@Version\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            re.compile(r'@Version\s*\(\s*(\d+)\s*\)'),
            
            # Advanced routing patterns
            re.compile(r'@HttpCode\s*\(\s*(\d+)\s*\)'),
            re.compile(r'@Header\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*,\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            
            # Microservice patterns
            re.compile(r'@MessagePattern\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            re.compile(r'@EventPattern\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            re.compile(r'@GrpcMethod\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            re.compile(r'@GrpcStreamMethod\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            
            # GraphQL patterns
            re.compile(r'@Query\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            re.compile(r'@Mutation\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            re.compile(r'@Subscription\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            re.compile(r'@ResolveField\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            
            # WebSocket patterns
            re.compile(r'@SubscribeMessage\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            re.compile(r'@WebSocketGateway\s*\(\s*(\d+)\s*\)'),
            re.compile(r'@WebSocketGateway\s*\(\s*\{[^}]*port:\s*(\d+)[^}]*\}\s*\)'),
            
            # Enterprise routing patterns
            re.compile(r'@Roles\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            re.compile(r'@Permissions\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            re.compile(r'@RateLimit\s*\(\s*\{[^}]*\}\s*\)'),
            re.compile(r'@Throttle\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)'),
        ]
        
        # Enhanced TypeScript/NestJS specific patterns
        self.typescript_patterns = {
            # Class and interface patterns
            'class_declaration': re.compile(r'export\s+class\s+(\w+)Controller'),
            'resolver_declaration': re.compile(r'export\s+class\s+(\w+)Resolver'),
            'gateway_declaration': re.compile(r'export\s+class\s+(\w+)Gateway'),
            'service_declaration': re.compile(r'export\s+class\s+(\w+)Service'),
            'guard_declaration': re.compile(r'export\s+class\s+(\w+)Guard'),
            'interceptor_declaration': re.compile(r'export\s+class\s+(\w+)Interceptor'),
            'interface_declaration': re.compile(r'export\s+interface\s+(\w+)'),
            
            # TypeScript variable declarations
            'const_declaration': re.compile(r'const\s+(\w+):\s*string\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            'readonly_property': re.compile(r'readonly\s+(\w+):\s*string\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            'private_property': re.compile(r'private\s+readonly\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            
            # Enum declarations
            'enum_declaration': re.compile(r'enum\s+(\w+)\s*\{([^}]+)\}'),
            'enum_value': re.compile(r'(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            
            # Template literal patterns
            'template_literal': re.compile(r'`([^`]*\$\{[^`]*\}[^`]*)`'),
            'template_var': re.compile(r'\$\{([^}()]+)\}'),
            'template_func': re.compile(r'\$\{([^}]+)\(\)\}'),
        
            # Decorator parameter patterns
            'decorator_template': re.compile(r'@\w+\s*\(\s*`([^`]*)`\s*\)'),
            
            # Modern TypeScript patterns
            'type_alias': re.compile(r'type\s+(\w+)\s*='),
            'mapped_type': re.compile(r'type\s+(\w+)<T>\s*=\s*\{[^}]*\}'),
            'conditional_type': re.compile(r'type\s+(\w+)<T>\s*=\s*T\s+extends'),
            'utility_type': re.compile(r'(Partial|Required|Readonly|Pick|Omit|Record)<'),
            
            # Decorator factories
            'custom_decorator': re.compile(r'export\s+const\s+(\w+)\s*=\s*createParamDecorator'),
            'method_decorator': re.compile(r'export\s+function\s+(\w+)\s*\([^)]*\)\s*\{'),
        }
        
        # Comprehensive authentication patterns for NestJS
        self.auth_patterns = {
            AuthType.JWT: [
                r'@UseGuards\s*\(\s*JwtAuthGuard\s*\)',
                r'@UseGuards\s*\(\s*BearerAuthGuard\s*\)',
                r'@ApiBearerAuth',
                r'JwtStrategy',
                r'validateJWT',
                r'verifyJWT',
                r'@nestjs/jwt',
                r'@Auth\(',  # Custom JWT decorator
                r'@Authenticated',
                r'@TokenAuth',
            ],
            AuthType.API_KEY: [
                r'@UseGuards\s*\(\s*ApiKeyAuthGuard\s*\)',
                r'@ApiKey',
                r'@ApiSecurity\s*\(\s*[\'"`]api[_-]?key[\'"`]\s*\)',
                r'validateApiKey',
                r'@ApiKeyAuth',
                r'X-API-Key',
                r'api-key',
            ],
            AuthType.SESSION: [
                r'@UseGuards\s*\(\s*SessionAuthGuard\s*\)',
                r'@Session',
                r'express-session',
                r'@UseGuards\s*\(\s*AuthGuard\s*\(\s*[\'"`]local[\'"`]\s*\)\s*\)',
                r'@SessionAuth',
            ],
            AuthType.OAUTH: [
                r'@UseGuards\s*\(\s*OAuth2Guard\s*\)',
                r'@UseGuards\s*\(\s*AuthGuard\s*\(\s*[\'"`]oauth[\'"`]\s*\)\s*\)',
                r'validateOauth',
                r'passport-oauth',
                r'@OAuthAuth',
                r'@GoogleAuth',
                r'@FacebookAuth',
                r'@GitHubAuth',
            ],
            AuthType.BASIC: [
                r'@UseGuards\s*\(\s*BasicAuthGuard\s*\)',
                r'@UseGuards\s*\(\s*AuthGuard\s*\(\s*[\'"`]basic[\'"`]\s*\)\s*\)',
                r'@BasicAuth',
                r'basic-auth',
            ],
            AuthType.CUSTOM: [
                r'@UseGuards\s*\(\s*\w+AuthGuard\s*\)',
                r'@Auth\s*\(\s*[\'"`]custom[\'"`]\s*\)',
                r'@CustomAuth',
                r'@RoleAuth',
                r'@PermissionAuth',
                r'canActivate',
            ]
        }
        
        # Modern NestJS security and middleware patterns
        self.security_patterns = [
            # Rate limiting and throttling
            r'@nestjs/throttler',
            r'@Throttle\(',
            r'@RateLimit\(',
            r'ThrottlerGuard',
            
            # CORS and security headers
            r'@nestjs/cors',
            r'helmet',
            r'@UseGuards.*CorsGuard',
            
            # Input validation
            r'class-validator',
            r'class-transformer',
            r'@IsString',
            r'@IsEmail',
            r'@IsNotEmpty',
            r'@ValidateNested',
            r'@Transform',
            r'ValidationPipe',
            
            # File upload security
            r'@nestjs/platform-express',
            r'multer',
            r'@UseInterceptors.*FileInterceptor',
            r'@UploadedFile',
            r'@UploadedFiles',
            
            # Caching and performance
            r'@nestjs/cache-manager',
            r'@CacheKey',
            r'@CacheTTL',
            r'CacheInterceptor',
            
            # Security interceptors
            r'@UseInterceptors.*SecurityInterceptor',
            r'@UseInterceptors.*LoggingInterceptor',
            r'@UseInterceptors.*TransformInterceptor',
        ]
        
        # Enterprise and microservice patterns
        self.enterprise_patterns = [
            # Microservices
            r'@nestjs/microservices',
            r'ClientProxy',
            r'@Client\(',
            r'@MessagePattern',
            r'@EventPattern',
            r'Transport\.',
            
            # gRPC
            r'@GrpcMethod',
            r'@GrpcStreamMethod',
            r'@GrpcService',
            r'\.proto',
            
            # Message queues
            r'@nestjs/bull',
            r'@nestjs/event-emitter',
            r'@Process\(',
            r'@OnQueueActive',
            r'@OnQueueCompleted',
            r'@OnQueueFailed',
            
            # Database patterns
            r'@nestjs/typeorm',
            r'@nestjs/mongoose',
            r'@nestjs/prisma',
            r'@InjectRepository',
            r'@InjectModel',
            
            # Configuration and environment
            r'@nestjs/config',
            r'ConfigService',
            r'@nestjs/env',
            
            # Health checks and monitoring
            r'@nestjs/terminus',
            r'@HealthCheck',
            r'@DiskHealthIndicator',
            r'@MemoryHealthIndicator',
            r'@HttpHealthIndicator',
            
            # Swagger/OpenAPI
            r'@nestjs/swagger',
            r'@ApiProperty',
            r'@ApiOperation',
            r'@ApiResponse',
            r'@ApiTags',
            r'@ApiParam',
            r'@ApiQuery',
            r'@ApiBody',
            r'@ApiExtraModels',
            
            # Advanced enterprise patterns
            r'@nestjs/elasticsearch',
            r'@nestjs/schedule',
            r'@nestjs/serve-static',
            r'@Cron\(',
            r'@Interval\(',
            r'@Timeout\(',
        ]
        
        # GraphQL specific patterns
        self.graphql_patterns = [
            r'@nestjs/graphql',
            r'@Resolver',
            r'@Query',
            r'@Mutation',
            r'@Subscription',
            r'@Field',
            r'@ObjectType',
            r'@InputType',
            r'@InterfaceType',
            r'@UnionType',
            r'@EnumType',
            r'@Directive',
            r'@Extensions',
            r'@ResolveField',
            r'@Args',
            r'@Context',
            r'@Info',
            r'@Parent',
            r'@Root',
            
            # GraphQL enterprise patterns
            r'@nestjs/apollo',
            r'@nestjs/mercurius',
            r'GraphQLModule',
            r'ApolloDriver',
            r'MercuriusDriver',
        ]
        
        # WebSocket patterns
        self.websocket_patterns = [
            r'@nestjs/websockets',
            r'@WebSocketGateway',
            r'@SubscribeMessage',
            r'@WebSocketServer',
            r'@ConnectedSocket',
            r'@MessageBody',
            r'@OnGatewayInit',
            r'@OnGatewayConnection',
            r'@OnGatewayDisconnect',
            
            # Socket.IO patterns
            r'@nestjs/platform-socket.io',
            r'socket\.io',
            r'@MessageBody',
            r'@ConnectedSocket',
        ]
        
        # Enhanced authentication guard types for reference
        self.auth_guard_types = [
            'AuthGuard', 'JwtAuthGuard', 'LocalAuthGuard', 'BearerAuthGuard',
            'RoleGuard', 'PermissionGuard', 'CustomAuthGuard', 'OrganizationAuthGuard',
            'ApiKeyAuthGuard', 'SessionAuthGuard', 'OAuth2Guard', 'BasicAuthGuard',
            'AdminGuard', 'UserGuard', 'MerchantGuard', 'InternalServiceGuard'
        ]
        
        # API Documentation patterns (Swagger/OpenAPI)
        self.swagger_patterns = [
            '@ApiTags', '@ApiOperation', '@ApiResponse', '@ApiParam',
            '@ApiQuery', '@ApiBody', '@ApiHeader', '@ApiBearerAuth',
            '@ApiSecurity', '@ApiProperty', '@ApiHideProperty'
        ]
        
        # Advanced route method patterns
        self.route_method_patterns = [
            '@Get', '@Post', '@Put', '@Delete', '@Patch', '@Head', '@Options',
            '@All', '@HttpCode', '@Header', '@Redirect'
        ]
        
        # Middleware and interceptor patterns
        self.middleware_patterns = [
            '@UseGuards', '@UseInterceptors', '@UsePipes', '@UseFilters',
            'LoggingInterceptor', 'TransformInterceptor', 'CacheInterceptor',
            'RateLimitGuard', 'ThrottlerGuard', 'ValidationPipe', 'ParseIntPipe'
        ]
        
        # Service classification patterns
        self.service_type_patterns = {
            'core': ['core', 'platform', 'common', 'shared'],
            'web': ['web', 'frontend', 'ui', 'portal', 'admin-interface'],
            'api': ['api', 'service', 'backend', 'microservice'],
            'auth': ['auth', 'security', 'identity', 'oauth', 'sso'],
            'payment': ['payment', 'billing', 'financial', 'cashier', 'transaction'],
            'merchant': ['merchant', 'store', 'seller', 'vendor'],
            'user': ['user', 'member', 'customer', 'profile'],
            'data': ['data', 'analytics', 'reporting', 'metrics'],
            'integration': ['integration', 'connector', 'sync', 'bridge'],
            'platform': ['platform', 'infrastructure', 'commons']
        }
        
        # Technology stack patterns
        self.tech_stack_patterns = {
            'database': ['TypeORM', 'Mongoose', 'PostgreSQL', 'MongoDB', 'Redis'],
            'messaging': ['Kafka', 'SQS', 'Bull', 'RabbitMQ', 'NATS'],
            'external': ['AWS', 'Google', 'Slack', 'Shopify', 'Salesforce'],
            'protocols': ['gRPC', 'GraphQL', 'WebSocket', 'EventEmitter'],
            'documentation': ['Swagger', 'OpenAPI', 'ApiDoc']
        }
        
        # Parameter patterns
        self.param_patterns = {
            '@Param': 'path',
            '@Query': 'query',
            '@Body': 'body',
            '@Headers': 'header',
            '@Req': 'request',
            '@Res': 'response'
        }
        
        # Validation patterns
        self.validation_patterns = [
            '@IsString', '@IsNumber', '@IsEmail', '@IsOptional',
            '@IsNotEmpty', '@IsArray', '@ValidateNested', '@Type',
            '@Min', '@Max', '@Length', '@Matches'
        ]
        
        # Organization-specific package imports
        self.organization_imports = [
            '@yourorg/nestjs-configuration',
            '@yourorg/nestjs-logger',
            '@yourorg/nestjs-common',
            '@yourorg/auth',
            '@yourorg/validation'
        ]
        
        # Enhanced route decorator patterns with comprehensive HTTP methods
        self.route_decorator_patterns = {
            'GET': re.compile(r'@Get\s*\(\s*[\'"`]?([^\'"`\)]*)[\'"`]?\s*\)', re.IGNORECASE),
            'POST': re.compile(r'@Post\s*\(\s*[\'"`]?([^\'"`\)]*)[\'"`]?\s*\)', re.IGNORECASE),
            'PUT': re.compile(r'@Put\s*\(\s*[\'"`]?([^\'"`\)]*)[\'"`]?\s*\)', re.IGNORECASE),
            'DELETE': re.compile(r'@Delete\s*\(\s*[\'"`]?([^\'"`\)]*)[\'"`]?\s*\)', re.IGNORECASE),
            'PATCH': re.compile(r'@Patch\s*\(\s*[\'"`]?([^\'"`\)]*)[\'"`]?\s*\)', re.IGNORECASE),
            'HEAD': re.compile(r'@Head\s*\(\s*[\'"`]?([^\'"`\)]*)[\'"`]?\s*\)', re.IGNORECASE),
            'OPTIONS': re.compile(r'@Options\s*\(\s*[\'"`]?([^\'"`\)]*)[\'"`]?\s*\)', re.IGNORECASE),
            'ALL': re.compile(r'@All\s*\(\s*[\'"`]?([^\'"`\)]*)[\'"`]?\s*\)', re.IGNORECASE)
        }
        
        # Controller and module patterns
        self.controller_pattern = re.compile(r'@Controller\s*\(\s*[\'"`]?([^\'"`\)]*)[\'"`]?\s*\)', re.IGNORECASE)
        self.module_pattern = re.compile(r'@Module\s*\(\s*\{[^}]*\}\s*\)', re.IGNORECASE)
        
        # Enhanced authentication patterns with regex compilation
        self.auth_patterns = {
            'Public': re.compile(r'@Public\s*\(\s*\)', re.IGNORECASE),
            'UseGuards': re.compile(r'@UseGuards\s*\(\s*([^)]+)\s*\)', re.IGNORECASE),
            'Roles': re.compile(r'@Roles\s*\(\s*([^)]+)\s*\)', re.IGNORECASE),
            'RequireAuth': re.compile(r'@RequireAuth\s*\(\s*([^)]*)\s*\)', re.IGNORECASE),
            'ApiKeyAuth': re.compile(r'@ApiKeyAuth\s*\(\s*([^)]*)\s*\)', re.IGNORECASE)
        }

    def detect_routes(self, file_path: str, content: str) -> List[RouteInfo]:
        """
        Enhanced NestJS route detection with template resolution and TypeScript support
        """
        routes = []
        self.seen_routes.clear()  # Reset for each file
        
        if not self._is_nestjs_file(content):
            return routes
            
        try:
            # Step 1: Extract TypeScript variables and enums
            variables = self._extract_typescript_variables(content)
        
            # Step 2: Parse controller-level configuration
            controller_config = self._parse_controller_config(content, variables)
            
            # Step 3: Find route methods with enhanced pattern matching
            route_methods = self._find_route_methods(content, variables)
            
            # Step 4: Process each route method
            for method_info in route_methods:
                try:
                    # Create framework context for template resolution
                    context = FrameworkContext(
                        framework=Framework.NESTJS,
                        file_path=file_path,
                        file_content=content,
                        variables=variables,
                        configuration=controller_config
                    )
                    
                    # Resolve template if needed
                    if '${' in method_info['path'] or '`' in method_info['path']:
                        resolved = self.template_resolver.resolve_template(method_info['path'], context)
                        final_path = resolved.resolved_path
                        path_params = resolved.path_parameters
                        query_params = resolved.query_parameters
                        original_path = method_info['path']
                        template_metadata = resolved.metadata
                    else:
                        final_path = self._normalize_path(method_info['path'])
                        path_params = self._extract_path_params(final_path)
                        query_params = []
                        original_path = method_info['path']
                        template_metadata = {}
                    
                    # Combine controller prefix with method path
                    if controller_config.get('prefix'):
                        if controller_config['prefix'].startswith('/'):
                            full_path = controller_config['prefix'] + final_path
                        else:
                            full_path = '/' + controller_config['prefix'] + final_path
                    else:
                        full_path = final_path
                    
                    # Normalize the final path
                    full_path = self._normalize_path(full_path)
                    
                    # Convert HTTP method
                    http_method = self._convert_to_http_method(method_info['method'])
                    if not http_method:
                        continue
                    
                    # Check for duplicates
                    route_key = (http_method.value, full_path, file_path)
                    if route_key in self.seen_routes:
                        continue
                    self.seen_routes.add(route_key)
                    
                    # Create enhanced route info
                    route_info = self._create_enhanced_nestjs_route_info(
                        method=http_method,
                        path=full_path,
                        original_path=original_path,
                        file_path=file_path,
                        line_number=method_info['line_number'],
                        path_params=path_params,
                        query_params=query_params,
                        variables=variables,
                        controller_config=controller_config,
                        method_config=method_info,
                        template_metadata=template_metadata,
                        content=content
                    )
                    
                    routes.append(route_info)
                    
                except Exception as e:
                    self.logger.error(f"Error processing NestJS route method: {e}")
                    continue
            
        except Exception as e:
            self.logger.error(f"Error processing NestJS routes in {file_path}: {e}")
        
        return routes
    
    def _is_nestjs_file(self, content: str) -> bool:
        """Enhanced NestJS file detection based on enterprise patterns."""
        # NestJS indicators
        nestjs_indicators = [
            '@Controller',
            '@Get', '@Post', '@Put', '@Delete', '@Patch',
            '@Injectable',
            '@Module',
            'import.*@nestjs',
            'from.*@nestjs',
            '@UseGuards',
            '@ApiTags',
            'export.*Controller'
        ]
        
        return any(re.search(indicator, content, re.IGNORECASE) for indicator in nestjs_indicators)
    
    def _extract_controller_path(self, content: str) -> str:
        """Extract the base path from @Controller decorator."""
        match = self.controller_pattern.search(content)
        if match:
            path = match.group(1) or ''
            return f"/{path.strip('/')}" if path else ''
        return ''
    
    def _extract_controller_name(self, file_path: str) -> str:
        """Extract controller name from file path."""
        file_name = Path(file_path).stem
        # Convert kebab-case or snake_case to PascalCase
        parts = re.split(r'[-_.]', file_name)
        return ''.join(word.capitalize() for word in parts if word)
    
    def _extract_organization_packages(self, content: str) -> List[str]:
        """Extract organization-specific package usage."""
        packages = []
        for package in self.organization_imports:
            if package in content:
                packages.append(package)
        
        # Also check for internal-* packages
        internal_pattern = re.compile(r'from\s+[\'"`](internal-[^\'"`]+)[\'"`]', re.IGNORECASE)
        internal_matches = internal_pattern.findall(content)
        packages.extend(internal_matches)
        
        return packages
    
    def _find_route_handlers(self, lines: List[str]) -> List[Dict]:
        """Find all route handler methods with their decorators."""
        handlers = []
        i = 0
        
        while i < len(lines):
            line = lines[i].strip()
            
            # Look for route decorators
            method_found = None
            route_path = ''
            
            for method, pattern in self.route_decorator_patterns.items():
                match = pattern.search(line)
                if match:
                    method_found = method
                    route_path = match.group(1) or ''
                    break
            
            if method_found:
                # Collect all decorators above this route
                decorators = []
                auth_info = None
                validation_decorators = []
                
                # Look backwards for decorators
                j = i - 1
                while j >= 0 and (lines[j].strip().startswith('@') or lines[j].strip() == ''):
                    decorator_line = lines[j].strip()
                    if decorator_line.startswith('@'):
                        decorators.append(decorator_line)
                        
                        # Check for auth decorators
                        auth_info = self._parse_auth_decorator(decorator_line) or auth_info
                        
                        # Check for validation decorators
                        if any(val_pattern in decorator_line for val_pattern in self.validation_patterns):
                            validation_decorators.append(decorator_line)
                    
                    j -= 1
                
                # Look forward for the method signature
                method_signature = ''
                k = i + 1
                while k < len(lines) and not lines[k].strip().endswith('{'):
                    if 'async' in lines[k] or '(' in lines[k]:
                        method_signature += lines[k].strip() + ' '
                        break
                    k += 1
                
                # Extract parameters from method signature
                parameters = self._extract_method_parameters(method_signature)
                
                handlers.append({
                    'method': method_found,
                    'path': route_path,
                    'line_number': i + 1,
                    'decorators': decorators,
                    'auth_info': auth_info,
                    'validation_decorators': validation_decorators,
                    'parameters': parameters,
                    'method_signature': method_signature
                })
            
            i += 1
        
        return handlers
    
    def _parse_auth_decorator(self, decorator: str) -> Optional[Dict]:
        """Parse authentication decorator for auth requirements."""
        # Check for @Public() decorator (no auth required)
        if self.auth_patterns['Public'].search(decorator):
            return {'required': False, 'type': AuthType.NONE, 'middleware': []}
        
        # Check for @UseGuards decorator
        guard_match = self.auth_patterns['UseGuards'].search(decorator)
        if guard_match:
            guards = guard_match.group(1)
            
            # Determine auth type based on guard names
            auth_type = AuthType.UNKNOWN
            if any(jwt_guard in guards for jwt_guard in ['JwtAuthGuard', 'JwtGuard']):
                auth_type = AuthType.JWT
            elif any(api_guard in guards for api_guard in ['ApiKeyAuthGuard', 'ApiKeyGuard']):
                auth_type = AuthType.API_KEY
            elif 'AuthGuard' in guards:
                auth_type = AuthType.JWT  # Default JWT auth
            
            return {
                'required': True,
                'type': auth_type,
                'middleware': [guard.strip() for guard in guards.split(',')]
            }
        
        # Check for @Roles decorator
        roles_match = self.auth_patterns['Roles'].search(decorator)
        if roles_match:
            roles = roles_match.group(1)
            return {
                'required': True,
                'type': AuthType.JWT,
                'roles': [role.strip('\'"') for role in roles.split(',')]
            }
        
        return None
    
    def _extract_method_parameters(self, method_signature: str) -> List[RouteParameter]:
        """Extract parameters from method signature."""
        parameters = []
        
        # Extract parameters using regex
        param_matches = re.findall(
            r'@(Param|Query|Body|Headers)\s*\(\s*[\'"`]?([^\'"`\)]*)[\'"`]?\s*\)\s*(\w+):\s*(\w+)',
            method_signature
        )
        
        for decorator_type, param_name, var_name, param_type in param_matches:
            parameters.append(RouteParameter(
                name=param_name or var_name,
                type=param_type,
                required=decorator_type in ['Param', 'Body']
            ))
        
        return parameters
    
    def _create_route_info(self, handler: Dict, base_path: str, controller_name: str, 
                          file_path: str, organization_packages: List[str]) -> Optional[RouteInfo]:
        """Create RouteInfo object from handler data."""
        
        # Construct full path
        route_path = handler['path']
        if base_path and route_path:
            full_path = f"{base_path}/{route_path.lstrip('/')}"
        elif base_path:
            full_path = base_path
        elif route_path:
            full_path = f"/{route_path.lstrip('/')}"
        else:
            full_path = "/"
        
        # Clean up path
        full_path = re.sub(r'/+', '/', full_path)
        
        # Determine authentication with proper None handling
        auth_info = handler.get('auth_info', {})
        if auth_info is None:
            auth_info = {}
        
        auth_required = auth_info.get('required', True)  # Default to required for security
        auth_type = auth_info.get('type', AuthType.UNKNOWN)
        auth_middleware = auth_info.get('middleware', [])
        roles = auth_info.get('roles', [])
        
        # Calculate risk score
        risk_score, risk_factors = self._calculate_risk_score(
            handler['method'], full_path, auth_required, auth_type, 
            handler.get('validation_decorators', [])
        )
        
        # Enhanced detection capabilities
        feature_flags = self._detect_feature_flags(handler.get('method_signature', ''))
        database_access = self._detect_database_access(handler.get('method_signature', ''))
        service_type = self._classify_service_type(file_path, controller_name)
        
        # Read full file content for technology stack detection
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
                technology_stack = self._detect_technology_stack(file_content)
                is_multi_app = self._is_multi_app_deployment(file_path, file_content)
        except:
            technology_stack = {}
            is_multi_app = False
        
        return RouteInfo(
            method=HTTPMethod(handler['method']),
            path=full_path,
            file_path=file_path,
            line_number=handler['line_number'],
            framework=Framework.NESTJS,
            controller_name=controller_name,
            auth_required=auth_required,
            auth_type=auth_type,
            auth_middleware=auth_middleware,
            roles_required=roles,
            parameters=handler.get('parameters', []),
            validation_decorators=handler.get('validation_decorators', []),
            middleware=auth_middleware,
            risk_score=risk_score,
            risk_level=self._get_risk_level(risk_score),
            risk_factors=risk_factors,
            organization_package_usage=organization_packages,
            feature_flags=feature_flags,
            database_access=database_access
        )
    
    def _calculate_risk_score(self, method: str, path: str, auth_required: bool, 
                            auth_type: AuthType, validation_decorators: List[str]) -> tuple[float, List[str]]:
        """Enhanced risk calculation based on enterprise patterns."""
        score = 0.0
        factors = []
        
        # Enhanced method-based risk
        method_risks = {
            'POST': 0.25,    # Data creation
            'PUT': 0.3,      # Full resource replacement
            'PATCH': 0.2,    # Partial updates
            'DELETE': 0.35,  # Data deletion - highest risk
            'GET': 0.05,     # Read operations - low risk
            'HEAD': 0.0,     # Metadata only
            'OPTIONS': 0.0,  # CORS preflight
            'ALL': 0.4       # Wildcard methods - very risky
        }
        
        if method in method_risks:
            score += method_risks[method]
            if method_risks[method] > 0.1:
                factors.append(f"high_risk_method_{method.lower()}")
        
        # Enhanced path-based risk patterns from enterprise analysis
        critical_paths = {
            '/admin': 0.4,        # Admin interfaces
            '/internal': 0.35,    # Internal APIs
            '/debug': 0.4,        # Debug endpoints
            '/payment': 0.5,      # Payment processing - critical
            '/billing': 0.5,      # Billing operations - critical
            '/financial': 0.5,    # Financial services - critical
            '/cashier': 0.45,     # Cashier operations
            '/transaction': 0.4,  # Transaction handling
            '/auth': 0.35,        # Authentication endpoints
            '/oauth': 0.3,        # OAuth endpoints
            '/user': 0.25,        # User data
            '/member': 0.25,      # Member data
            '/customer': 0.25,    # Customer data
            '/profile': 0.2,      # Profile data
            '/merchant': 0.3,     # Merchant data
            '/store': 0.25,       # Store management
            '/api/gateway': 0.3,  # API gateway routes
            '/api/internal': 0.35,# Internal APIs
            '/v1/admin': 0.4,     # Versioned admin APIs
            '/v1/internal': 0.35, # Versioned internal APIs
            '/whale': 0.25,       # Extension-specific prefix
        }
        
        path_lower = path.lower()
        for risk_path, risk_value in critical_paths.items():
            if risk_path in path_lower:
                score += risk_value
                factors.append(f"critical_path_{risk_path.replace('/', '_').strip('_')}")
        
        # Enhanced authentication risk assessment
        if not auth_required:
            score += 0.45
            factors.append("no_authentication_required")
        elif auth_type == AuthType.NONE:
            score += 0.35
            factors.append("explicit_no_auth")
        elif auth_type == AuthType.UNKNOWN:
            score += 0.25
            factors.append("unknown_auth_mechanism")
        elif auth_type == AuthType.API_KEY:
            score += 0.1  # API keys less secure than JWT
            factors.append("api_key_auth_risk")
        
        # Service-specific risk patterns
        service_patterns = {
            'core': 0.3,          # Core services
            'platform': 0.25,    # Platform services
            'extension': 0.2,     # Browser extension
            'unified': 0.3,       # Unified services (payment, etc.)
            'gateway': 0.35,      # API gateways
            'proxy': 0.3,         # Proxy services
            'connector': 0.25,    # External connectors
            'sync': 0.2,          # Sync services
            'reporting': 0.15,    # Reporting services
            'analytics': 0.1,     # Analytics
        }
        
        for service_type, risk_value in service_patterns.items():
            if service_type in path_lower:
                score += risk_value
                factors.append(f"service_risk_{service_type}")
        
        # Enhanced validation risk
        if method in ['POST', 'PUT', 'PATCH'] and not validation_decorators:
            score += 0.25
            factors.append("missing_input_validation")
        
        # Multi-app deployment risk (common in enterprise)
        if '/apps/' in path_lower or 'multi-app' in path_lower:
            score += 0.15
            factors.append("multi_app_deployment_risk")
        
        # External integration risk
        external_indicators = ['shopify', 'salesforce', 'google', 'aws', 'slack']
        for indicator in external_indicators:
            if indicator in path_lower:
                score += 0.2
                factors.append(f"external_integration_{indicator}")
        
        return min(score, 1.0), factors
    
    def _get_risk_level(self, risk_score: float) -> RiskLevel:
        """Convert risk score to risk level."""
        if risk_score >= 0.7:
            return RiskLevel.HIGH
        elif risk_score >= 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _detect_feature_flags(self, method_content: str) -> List[str]:
        """Detect feature flag usage in method."""
        feature_flags = []
        
        # Common organization feature flag patterns
        feature_patterns = [
            r'featureFlag\.[\'"`]([^\'"`]+)[\'"`]',
            r'@yourorg/feature-flag.*[\'"`]([^\'"`]+)[\'"`]',
            r'isFeatureEnabled\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'feature[\'"`]:\s*[\'"`]([^\'"`]+)[\'"`]'
        ]
        
        for pattern in feature_patterns:
            matches = re.findall(pattern, method_content, re.IGNORECASE)
            feature_flags.extend(matches)
        
        return feature_flags
    
    def _detect_database_access(self, method_content: str) -> List[str]:
        """Detect database access patterns."""
        db_access = []
        
        # Common TypeORM and database patterns
        db_patterns = [
            r'@InjectRepository\(([^)]+)\)',
            r'this\.(\w+Repository)',
            r'@Query\s*\([\'"`]([^\'"`]+)[\'"`]\)',
            r'createQueryBuilder\([\'"`]([^\'"`]+)[\'"`]\)',
            r'\.find\(', r'\.save\(', r'\.update\(', r'\.delete\('
        ]
        
        for pattern in db_patterns:
            if re.search(pattern, method_content, re.IGNORECASE):
                db_access.append(pattern.replace('\\', ''))
        
        return db_access 
    
    def _classify_service_type(self, file_path: str, controller_name: str) -> str:
        """Classify service type based on enterprise patterns."""
        path_lower = file_path.lower()
        controller_lower = controller_name.lower()
        
        # Service classification based on directory structure and naming
        for service_type, patterns in self.service_type_patterns.items():
            for pattern in patterns:
                if pattern in path_lower or pattern in controller_lower:
                    return service_type
        
        # Additional enterprise-specific classifications
        if any(pattern in path_lower for pattern in ['blocks/', 'group-', 'core/']):
            return 'core'
        elif any(pattern in path_lower for pattern in ['web-platform/', 'frontend/', 'ui/']):
            return 'web'
        elif any(pattern in path_lower for pattern in ['member-service/', 'user-', 'customer-']):
            return 'user'
        elif any(pattern in path_lower for pattern in ['merchant-', 'store-', 'seller-']):
            return 'merchant'
        elif any(pattern in path_lower for pattern in ['payment', 'financial', 'billing', 'cashier']):
            return 'payment'
        elif any(pattern in path_lower for pattern in ['platform-commons/', 'commons/', 'shared/']):
            return 'platform'
        elif any(pattern in path_lower for pattern in ['gateway/', 'proxy/', 'router/']):
            return 'integration'
        else:
            return 'api'  # Default to generic API service
    
    def _detect_technology_stack(self, content: str) -> Dict[str, List[str]]:
        """Detect technology stack based on imports and usage patterns."""
        detected_tech = {category: [] for category in self.tech_stack_patterns.keys()}
        
        for category, technologies in self.tech_stack_patterns.items():
            for tech in technologies:
                if tech.lower() in content.lower():
                    detected_tech[category].append(tech)
        
        # Additional pattern detection
        if '@nestjs/' in content:
            detected_tech['framework'] = detected_tech.get('framework', []) + ['NestJS']
        if 'typeorm' in content.lower():
            detected_tech['database'] = detected_tech.get('database', []) + ['TypeORM']
        if 'swagger' in content.lower() or '@api' in content.lower():
            detected_tech['documentation'] = detected_tech.get('documentation', []) + ['Swagger/OpenAPI']
        
        # Remove empty categories
        return {k: v for k, v in detected_tech.items() if v}
    
    def _is_multi_app_deployment(self, file_path: str, content: str) -> bool:
        """Detect if this is part of a multi-app NestJS deployment."""
        multi_app_indicators = [
            'apps/', '/apps/', 'multi-app', 'microservice',
            'createMicroservice', 'microserviceOptions',
            'Transport.', 'ClientProxy', '@nestjs/microservices'
        ]
        
        return any(indicator in file_path or indicator in content 
                  for indicator in multi_app_indicators) 

    def _extract_typescript_variables(self, content: str) -> Dict[str, str]:
        """Extract TypeScript variable declarations, constants, and enums"""
        variables = {}
        
        # Extract basic variable declarations
        for pattern_name, pattern in self.typescript_patterns.items():
            if 'declaration' in pattern_name or 'property' in pattern_name:
                matches = pattern.findall(content)
                for match in matches:
                    if isinstance(match, tuple) and len(match) >= 2:
                        var_name, var_value = match[0], match[1]
                        variables[var_name] = var_value
        
        # Extract enum values
        enum_matches = self.typescript_patterns['enum_declaration'].findall(content)
        for enum_name, enum_body in enum_matches:
            enum_values = self.typescript_patterns['enum_value'].findall(enum_body)
            for value_name, value_value in enum_values:
                variables[f"{enum_name}.{value_name}"] = value_value
                variables[value_name] = value_value  # Also add short form
        
        # Extract module imports and exports
        import_patterns = [
            re.compile(r'import\s*\{\s*([^}]+)\s*\}\s*from\s*[\'"`]([^\'"`]+)[\'"`]'),
            re.compile(r'export\s*\{\s*([^}]+)\s*\}'),
        ]
        
        for pattern in import_patterns:
            matches = pattern.findall(content)
            for match in matches:
                if isinstance(match, tuple):
                    imports = match[0].split(',')
                    for imp in imports:
                        imp = imp.strip()
                        if 'as' in imp:
                            # Handle "import { original as alias }"
                            parts = imp.split(' as ')
                            if len(parts) == 2:
                                variables[parts[1].strip()] = parts[0].strip()
        
        return variables
    
    def _parse_controller_config(self, content: str, variables: Dict[str, str]) -> Dict[str, Any]:
        """Parse NestJS controller-level configuration"""
        config = {}
        
        # Find @Controller decorator
        controller_patterns = [
            re.compile(r'@Controller\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            re.compile(r'@Controller\s*\(\s*`([^`]*)`\s*\)'),  # Template literals
            re.compile(r'@Controller\s*\(\s*([A-Z_][A-Z0-9_]*)\s*\)'),  # Variables
        ]
        
        for pattern in controller_patterns:
            match = pattern.search(content)
            if match:
                prefix = match.group(1)
                
                # Resolve template variables in prefix
                if '${' in prefix:
                    context = FrameworkContext(
                        framework=Framework.NESTJS,
                        file_path="",
                        file_content=content,
                        variables=variables,
                        configuration={}
                    )
                    resolved = self.template_resolver.resolve_template(prefix, context)
                    config['prefix'] = resolved.resolved_path
                    config['original_prefix'] = prefix
                else:
                    # Check if it's a variable reference
                    if prefix in variables:
                        config['prefix'] = variables[prefix]
                        config['original_prefix'] = prefix
                    else:
                        config['prefix'] = prefix
                break
        
        # Find versioning
        version_pattern = re.compile(r'@Version\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)')
        version_match = version_pattern.search(content)
        if version_match:
            config['version'] = version_match.group(1)
        
        # Find global guards
        global_guard_pattern = re.compile(r'@UseGuards\s*\(\s*([^)]+)\s*\)')
        global_guard_match = global_guard_pattern.search(content)
        if global_guard_match:
            config['global_guards'] = global_guard_match.group(1)
        
        return config
    
    def _find_route_methods(self, content: str, variables: Dict[str, str]) -> List[Dict[str, Any]]:
        """Find all route method definitions with enhanced pattern matching"""
        methods = []
        lines = content.split('\n')
        
        # Patterns for method decorators
        method_patterns = [
            re.compile(r'@(Get|Post|Put|Delete|Patch|Head|Options|All)\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\)'),
            re.compile(r'@(Get|Post|Put|Delete|Patch|Head|Options|All)\s*\(\s*`([^`]*)`\s*\)'),  # Template literals
            re.compile(r'@(Get|Post|Put|Delete|Patch|Head|Options|All)\s*\(\s*([A-Z_][A-Z0-9_]*)\s*\)'),  # Variables
            re.compile(r'@(Get|Post|Put|Delete|Patch|Head|Options|All)\s*\(\s*\)'),  # Empty decorator
        ]
        
        for i, line in enumerate(lines):
            for pattern in method_patterns:
                match = pattern.search(line)
                if match:
                    method = match.group(1).upper()
                    path = match.group(2) if len(match.groups()) > 1 and match.group(2) else ""
                    
                    # Resolve variable references
                    if path in variables:
                        resolved_path = variables[path]
                        original_path = path
                    else:
                        resolved_path = path
                        original_path = path
                    
                    # Extract additional method configuration
                    method_config = self._extract_method_config(lines, i)
                    
                    methods.append({
                        'method': method,
                        'path': resolved_path,
                        'original_path': original_path,
                        'line_number': i + 1,
                        'config': method_config
                    })
                    break
        
        return methods

    def _extract_method_config(self, lines: List[str], line_number: int) -> Dict[str, Any]:
        """Extract configuration for a route method"""
        config = {
            'decorators': [],
            'auth_info': None,
            'parameters': [],
            'method_signature': ''
        }
        
        # Look backwards for decorators
        j = line_number - 1
        while j >= 0 and (lines[j].strip().startswith('@') or lines[j].strip() == ''):
            decorator_line = lines[j].strip()
            if decorator_line.startswith('@'):
                config['decorators'].append(decorator_line)
            j -= 1
        
        return config
    
    def _normalize_path(self, path: str) -> str:
        """Normalize a path by cleaning up slashes"""
        if not path.startswith('/'):
            path = '/' + path
        path = re.sub(r'/+', '/', path)
        if path.endswith('/') and path != '/':
            path = path[:-1]
        return path
    
    def _extract_path_params(self, path: str) -> List[str]:
        """Extract path parameters from a route path"""
        # Extract :param and {param} patterns
        params = []
        param_patterns = [
            re.compile(r':(\w+)'),  # Express-style :id
            re.compile(r'\{(\w+)\}')  # OpenAPI-style {id}
        ]
        
        for pattern in param_patterns:
            matches = pattern.findall(path)
            params.extend(matches)
        
        return params
    
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
            'ALL': HTTPMethod.ALL,  # Fixed: NestJS @All() -> ALL enum (not OPTIONS)
        }
        
        return method_mapping.get(method_str.upper())
    
    def _create_enhanced_nestjs_route_info(self, method: HTTPMethod, path: str, original_path: str, 
                                          file_path: str, line_number: int, path_params: List[str], 
                                          query_params: List[str], variables: Dict[str, str], 
                                          controller_config: Dict[str, Any], method_config: Dict[str, Any], 
                                          template_metadata: Dict[str, Any], content: str) -> RouteInfo:
        """Create enhanced RouteInfo with NestJS-specific template resolution context"""
        
        # Extract authentication info from decorators
        auth_info = self._extract_auth_from_decorators(method_config.get('decorators', []))
        
        # Create route parameters
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
            'template_resolution': '${' in original_path,
            'controller_config': controller_config,
            'decorators': method_config.get('decorators', []),
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
        
        # Enhanced risk assessment
        route_info.risk_level = self._assess_nestjs_risk_level(path, method.value, route_info.auth_type, method_config)
        route_info.risk_score = self._calculate_nestjs_risk_score(route_info, content, method_config)
        
        return route_info
    
    def _extract_auth_from_decorators(self, decorators: List[str]) -> Dict[str, Any]:
        """Extract authentication information from NestJS decorators"""
        auth_info = {
            'type': AuthType.UNKNOWN,
            'required': False
        }
        
        for decorator in decorators:
            # Check for guard decorators
            for auth_type, patterns in self.auth_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, decorator, re.IGNORECASE):
                        auth_info['type'] = auth_type
                        auth_info['required'] = True
                        return auth_info
        
        return auth_info
    
    def _assess_nestjs_risk_level(self, path: str, method: str, auth_type: AuthType, method_config: Dict[str, Any]) -> RiskLevel:
        """Assess risk level for NestJS routes"""
        risk_score = 0
        
        # Method-based risk
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            risk_score += 2
        
        # Path-based risk
        high_risk_patterns = [
            r'/admin', r'/api/internal', r'/debug', r'/config',
            r'/management', r'/actuator', r'/health', r'/metrics',
            r'/delete', r'/upload', r'/download', r'/password',
            r'/token', r'/auth', r'/login', r'/logout'
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
        
        # Decorator-based risk assessment
        decorators = method_config.get('decorators', [])
        if any('@Public' in decorator for decorator in decorators):
            risk_score += 2
        
        # Map score to risk level
        if risk_score >= 7:
            return RiskLevel.CRITICAL
        elif risk_score >= 5:
            return RiskLevel.HIGH
        elif risk_score >= 3:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_nestjs_risk_score(self, route_info: RouteInfo, content: str, method_config: Dict[str, Any]) -> float:
        """Calculate detailed risk score for NestJS routes"""
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
            risk_factors.append("No authentication required")
        
        # Parameter validation risk
        if route_info.parameters:
            param_count = len(route_info.parameters)
            base_score += 0.5 * param_count
            risk_factors.append("Unvalidated parameters")
        
        # Template resolution specific risks
        if route_info.metadata.get('template_resolution'):
            base_score += 1.0
            risk_factors.append("Dynamic route construction")
        
        # Decorator-based risk
        decorators = method_config.get('decorators', [])
        if any('@Public' in decorator for decorator in decorators):
            base_score += 2.0
            risk_factors.append("Public endpoint (no guards)")
        
        # Store risk factors
        route_info.risk_factors = risk_factors
        
        return min(base_score, 10.0)  # Cap at 10.0 