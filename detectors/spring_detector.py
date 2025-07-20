"""
Enhanced Spring Boot Detector for Modern Enterprise Applications

Supports Spring Boot 2.x/3.x, Spring WebFlux, Spring Cloud, microservices,
reactive patterns, actuator endpoints, and enterprise features.
"""

import re
import os
from typing import List, Dict, Optional, Set, Tuple, Any

from models import RouteInfo, Framework, HTTPMethod, AuthType, RiskLevel, RouteParameter, SecurityFinding
from detectors.base_detector import BaseDetector
from analyzers.template_resolver import get_template_resolver, FrameworkContext, ResolvedRoute


class SpringBootDetector(BaseDetector):
    """
    Enhanced Spring Boot detector with comprehensive modern framework support.
    Supports Spring Boot, Spring WebFlux, Spring Cloud, and enterprise patterns.
    """
    
    def __init__(self, framework: Framework = Framework.SPRING):
        super().__init__(framework)
        self.seen_routes = set()  # For deduplication
        
        # Initialize template resolver (using Go resolver as base for now)
        self.template_resolver = get_template_resolver(Framework.GO_HTTP)
        
        # Enhanced Spring Boot framework detection indicators
        self.spring_indicators = [
            # Core Spring Boot
            r'@SpringBootApplication',
            r'@RestController',
            r'@Controller',
            r'@Service',
            r'@Repository',
            r'@Component',
            r'@Configuration',
            r'@EnableAutoConfiguration',
            
            # Spring MVC
            r'@RequestMapping',
            r'@GetMapping',
            r'@PostMapping',
            r'@PutMapping',
            r'@DeleteMapping',
            r'@PatchMapping',
            r'@RequestParam',
            r'@PathVariable',
            r'@RequestBody',
            r'@ResponseBody',
            
            # Spring WebFlux (Reactive)
            r'@EnableWebFlux',
            r'WebFluxConfigurer',
            r'RouterFunction',
            r'ServerRequest',
            r'ServerResponse',
            r'Mono<',
            r'Flux<',
            r'@GetExchange',
            r'@PostExchange',
            r'@PutExchange',
            r'@DeleteExchange',
            r'@PatchExchange',
            
            # Spring Security
            r'@EnableWebSecurity',
            r'@EnableGlobalMethodSecurity',
            r'@PreAuthorize',
            r'@PostAuthorize',
            r'@Secured',
            r'@RolesAllowed',
            
            # Spring Cloud and Microservices
            r'@EnableEurekaClient',
            r'@EnableDiscoveryClient',
            r'@EnableCircuitBreaker',
            r'@EnableConfigServer',
            r'@EnableZuulProxy',
            r'@EnableGateway',
            r'@FeignClient',
            r'@LoadBalanced',
            r'@HystrixCommand',
            
            # Spring Data
            r'@EnableJpaRepositories',
            r'@EnableMongoRepositories',
            r'@EnableRedisRepositories',
            r'@Query',
            r'@Modifying',
            
            # Spring Actuator
            r'@Endpoint',
            r'@ReadOperation',
            r'@WriteOperation',
            r'@DeleteOperation',
            r'management.endpoints',
            
            # Spring Integration
            r'@EnableIntegration',
            r'@IntegrationComponentScan',
            r'@ServiceActivator',
            r'@MessageEndpoint',
            
            # Enterprise patterns
            r'spring-boot-starter',
            r'spring-cloud-starter',
            r'spring-security-oauth2',
            r'spring-kafka',
            r'spring-amqp',
        ]
        
        # Comprehensive Spring Boot annotation patterns
        self.spring_patterns = {
            # Controller annotations
            'controller': re.compile(r'@(?:Rest)?Controller(?:\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]\s*\))?'),
            'request_mapping': re.compile(r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?[\'"`]([^\'"`,]*)[\'"`]'),
            'request_mapping_props': re.compile(r'@RequestMapping\s*\(([^)]+)\)'),
            
            # HTTP method annotations
            'get_mapping': re.compile(r'@GetMapping\s*\(\s*(?:value\s*=\s*)?[\'"`]([^\'"`,]*)[\'"`]'),
            'post_mapping': re.compile(r'@PostMapping\s*\(\s*(?:value\s*=\s*)?[\'"`]([^\'"`,]*)[\'"`]'),
            'put_mapping': re.compile(r'@PutMapping\s*\(\s*(?:value\s*=\s*)?[\'"`]([^\'"`,]*)[\'"`]'),
            'delete_mapping': re.compile(r'@DeleteMapping\s*\(\s*(?:value\s*=\s*)?[\'"`]([^\'"`,]*)[\'"`]'),
            'patch_mapping': re.compile(r'@PatchMapping\s*\(\s*(?:value\s*=\s*)?[\'"`]([^\'"`,]*)[\'"`]'),
            
            # Spring WebFlux reactive patterns
            'get_exchange': re.compile(r'@GetExchange\s*\(\s*(?:value\s*=\s*)?[\'"`]([^\'"`,]*)[\'"`]'),
            'post_exchange': re.compile(r'@PostExchange\s*\(\s*(?:value\s*=\s*)?[\'"`]([^\'"`,]*)[\'"`]'),
            'put_exchange': re.compile(r'@PutExchange\s*\(\s*(?:value\s*=\s*)?[\'"`]([^\'"`,]*)[\'"`]'),
            'delete_exchange': re.compile(r'@DeleteExchange\s*\(\s*(?:value\s*=\s*)?[\'"`]([^\'"`,]*)[\'"`]'),
            'patch_exchange': re.compile(r'@PatchExchange\s*\(\s*(?:value\s*=\s*)?[\'"`]([^\'"`,]*)[\'"`]'),
            
            # Functional routing (WebFlux)
            'router_function': re.compile(r'RouterFunctions\.route\s*\(\s*RequestPredicates\.(GET|POST|PUT|DELETE|PATCH)\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
            'request_predicate': re.compile(r'RequestPredicates\.(GET|POST|PUT|DELETE|PATCH)\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
            
            # Actuator endpoints
            'endpoint': re.compile(r'@Endpoint\s*\(\s*id\s*=\s*[\'"`]([^\'"`,]*)[\'"`]'),
            'read_operation': re.compile(r'@ReadOperation'),
            'write_operation': re.compile(r'@WriteOperation'),
            'delete_operation': re.compile(r'@DeleteOperation'),
            
            # Template and property patterns
            'property_placeholder': re.compile(r'\$\{([^}]+)\}'),
            'string_concat': re.compile(r'[\'"`]([^\'"`]*)[\'"`]\s*\+\s*(\w+)'),
            'final_string': re.compile(r'(?:public\s+)?(?:private\s+)?(?:static\s+)?final\s+String\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            'constant': re.compile(r'(?:public\s+)?(?:private\s+)?static\s+final\s+String\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            
            # Microservice patterns
            'feign_client': re.compile(r'@FeignClient\s*\(\s*(?:name\s*=\s*)?[\'"`]([^\'"`,]*)[\'"`]'),
            'hystrix_command': re.compile(r'@HystrixCommand\s*\([^)]*\)'),
            'circuit_breaker': re.compile(r'@CircuitBreaker\s*\(\s*name\s*=\s*[\'"`]([^\'"`,]*)[\'"`]'),
            'retryable': re.compile(r'@Retryable'),
            'timeout': re.compile(r'@Timeout'),
            
            # Security annotations
            'secured': re.compile(r'@Secured\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
            'preauthorize': re.compile(r'@PreAuthorize\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
            'postauthorize': re.compile(r'@PostAuthorize\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
            'rolesallowed': re.compile(r'@RolesAllowed\s*\(\s*[\'"`]([^\'"`,]*)[\'"`]'),
            
            # Validation patterns
            'valid': re.compile(r'@Valid'),
            'validated': re.compile(r'@Validated'),
            
            # Enterprise integration patterns
            'message_endpoint': re.compile(r'@MessageEndpoint'),
            'service_activator': re.compile(r'@ServiceActivator\s*\(([^)]+)\)'),
            'gateway': re.compile(r'@Gateway\s*\(([^)]+)\)'),
            'event_listener': re.compile(r'@EventListener'),
            'async': re.compile(r'@Async'),
            'scheduled': re.compile(r'@Scheduled'),
            'transactional': re.compile(r'@Transactional'),
        }
        
        # Enhanced Spring configuration properties patterns
        self.config_patterns = {
            'application_properties': re.compile(r'([a-zA-Z0-9._-]+)\s*=\s*([^\n\r]+)'),
            'yaml_property': re.compile(r'^(\s*)([a-zA-Z0-9._-]+):\s*(.+)$', re.MULTILINE),
            'server_port': re.compile(r'server\.port\s*=\s*(\d+)'),
            'context_path': re.compile(r'server\.servlet\.context-path\s*=\s*([^\n\r]+)'),
            'management_port': re.compile(r'management\.server\.port\s*=\s*(\d+)'),
            'management_context': re.compile(r'management\.endpoints\.web\.base-path\s*=\s*([^\n\r]+)'),
            'eureka_instance': re.compile(r'eureka\.instance\.hostname\s*=\s*([^\n\r]+)'),
            'feign_url': re.compile(r'feign\.client\.config\.([^.]+)\.url\s*=\s*([^\n\r]+)'),
        }
        
        # Comprehensive Spring Security authentication patterns
        self.auth_patterns = {
            AuthType.JWT: [
                r'@EnableJwtAuthentication',
                r'JwtAuthenticationFilter',
                r'JwtTokenProvider',
                r'spring-security-jwt',
                r'io\.jsonwebtoken',
                r'validateJwtToken',
                r'JwtAuthenticationEntryPoint',
                r'JwtAccessDeniedHandler',
                r'@EnableResourceServer',
                r'ResourceServerConfigurerAdapter',
                r'spring-security-oauth2-jose',
                r'NimbusJwtDecoder',
            ],
            AuthType.OAUTH: [
                r'@EnableOAuth2',
                r'OAuth2AuthenticationFilter',
                r'spring-security-oauth2',
                r'@EnableResourceServer',
                r'OAuth2RestTemplate',
                r'@EnableAuthorizationServer',
                r'AuthorizationServerConfigurerAdapter',
                r'OAuth2ClientContext',
                r'@EnableOAuth2Sso',
                r'spring-security-oauth2-client',
                r'OAuth2AuthorizedClientManager',
            ],
            AuthType.SESSION: [
                r'@EnableWebSecurity',
                r'SessionAuthenticationStrategy',
                r'HttpSessionSecurityContextRepository',
                r'sessionManagement\(\)',
                r'SessionCreationPolicy',
                r'ConcurrentSessionFilter',
                r'SessionRegistry',
                r'@EnableRedisHttpSession',
                r'@EnableJdbcHttpSession',
            ],
            AuthType.API_KEY: [
                r'ApiKeyAuthenticationFilter',
                r'X-API-KEY',
                r'api.*key.*header',
                r'validateApiKey',
                r'ApiKeyAuthenticationToken',
                r'ApiKeyAuthenticationProvider',
            ],
            AuthType.BASIC: [
                r'httpBasic\(\)',
                r'BasicAuthenticationFilter',
                r'DaoAuthenticationProvider',
                r'basicAuth',
                r'BasicAuthenticationEntryPoint',
                r'PasswordEncoder',
                r'BCryptPasswordEncoder',
            ],
            AuthType.CUSTOM: [
                r'AuthenticationProvider',
                r'@EnableGlobalMethodSecurity',
                r'SecurityConfig',
                r'WebSecurityConfigurerAdapter',
                r'AuthenticationManager',
                r'UserDetailsService',
                r'CustomAuthenticationFilter',
                r'SecurityContextHolder',
                r'@PreAuthorize',
                r'@PostAuthorize',
                r'@Secured',
                r'@RolesAllowed',
            ]
        }
        
        # Modern Spring security and middleware patterns
        self.security_patterns = [
            # CORS and security headers
            r'@CrossOrigin',
            r'CorsConfigurationSource',
            r'WebMvcConfigurer.*addCorsMappings',
            r'SecurityHeaders',
            
            # CSRF protection
            r'csrf\(\)',
            r'CsrfConfigurer',
            r'CsrfTokenRepository',
            
            # Method security
            r'@EnableGlobalMethodSecurity',
            r'@PreAuthorize',
            r'@PostAuthorize',
            r'@Secured',
            r'@RolesAllowed',
            
            # Rate limiting
            r'@RateLimiter',
            r'RateLimiterRegistry',
            r'Bucket4j',
            
            # Input validation
            r'@Valid',
            r'@Validated',
            r'BindingResult',
            r'@NotNull',
            r'@NotEmpty',
            r'@NotBlank',
            r'@Size',
            r'@Email',
            r'@Pattern',
            
            # Security filters
            r'OncePerRequestFilter',
            r'GenericFilterBean',
            r'SecurityFilterChain',
            r'FilterChainProxy',
        ]
        
        # Enterprise and microservice patterns
        self.enterprise_patterns = [
            # Service discovery
            r'@EnableEurekaClient',
            r'@EnableDiscoveryClient',
            r'EurekaClient',
            r'DiscoveryClient',
            r'@LoadBalanced',
            
            # Circuit breakers and resilience
            r'@EnableCircuitBreaker',
            r'@HystrixCommand',
            r'@CircuitBreaker',
            r'@Retryable',
            r'@Timeout',
            r'@Bulkhead',
            r'Resilience4j',
            
            # API Gateway
            r'@EnableZuulProxy',
            r'@EnableGateway',
            r'RouteLocator',
            r'GatewayFilter',
            r'GlobalFilter',
            
            # Configuration management
            r'@EnableConfigServer',
            r'@RefreshScope',
            r'@ConfigurationProperties',
            r'@Value\(',
            r'Environment',
            
            # Message queues and streaming
            r'@EnableKafka',
            r'@KafkaListener',
            r'@RabbitListener',
            r'@StreamListener',
            r'@EnableBinding',
            r'@Input',
            r'@Output',
            
            # Monitoring and observability
            r'@Timed',
            r'@Counted',
            r'MeterRegistry',
            r'Micrometer',
            r'@NewSpan',
            r'@GetMapping.*actuator',
            
            # Database and caching
            r'@EnableJpaRepositories',
            r'@EnableCaching',
            r'@Cacheable',
            r'@CacheEvict',
            r'@CachePut',
            r'RedisTemplate',
            r'@EnableRedisRepositories',
            
            # Async and scheduling
            r'@EnableAsync',
            r'@Async',
            r'@EnableScheduling',
            r'@Scheduled',
            r'TaskExecutor',
            r'ThreadPoolTaskExecutor',
            
            # Enterprise integration
            r'@EnableIntegration',
            r'@ServiceActivator',
            r'@MessageEndpoint',
            r'@Gateway',
            r'IntegrationFlow',
        ]
        
        # Spring WebFlux reactive patterns
        self.reactive_patterns = [
            r'@EnableWebFlux',
            r'WebFluxConfigurer',
            r'RouterFunction',
            r'HandlerFunction',
            r'ServerRequest',
            r'ServerResponse',
            r'Mono<',
            r'Flux<',
            r'WebClient',
            r'ReactiveRedisTemplate',
            r'R2dbcRepository',
            r'ReactiveMongoRepository',
            r'WebTestClient',
            
            # Reactive security
            r'ReactiveSecurityContextHolder',
            r'ServerHttpSecurity',
            r'ReactiveAuthenticationManager',
            r'ReactiveUserDetailsService',
            
            # Reactive streaming
            r'@GetExchange',
            r'@PostExchange',
            r'@PutExchange',
            r'@DeleteExchange',
            r'@PatchExchange',
            r'HttpServiceProxyFactory',
        ]
        
        # Spring Actuator patterns
        self.actuator_patterns = [
            r'/actuator/health',
            r'/actuator/info',
            r'/actuator/metrics',
            r'/actuator/env',
            r'/actuator/configprops',
            r'/actuator/beans',
            r'/actuator/mappings',
            r'/actuator/httptrace',
            r'/actuator/loggers',
            r'/actuator/shutdown',
            r'/actuator/prometheus',
            r'@Endpoint',
            r'@ReadOperation',
            r'@WriteOperation',
            r'@DeleteOperation',
            r'@Selector',
            r'HealthIndicator',
            r'InfoContributor',
        ]
    
    def detect_routes(self, file_path: str, content: str) -> List[RouteInfo]:
        """
        Enhanced Spring Boot route detection with annotation processing and property resolution
        """
        routes = []
        self.seen_routes.clear()  # Reset for each file
        
        if not self._is_spring_boot_file(file_path, content):
            return routes
        
        try:
            # Step 1: Extract Spring configuration and constants
            variables = self._extract_spring_variables(content)
            
            # Step 2: Parse controller-level configuration
            controller_config = self._parse_controller_config(content, variables)
            
            # Step 3: Extract route method definitions
            route_methods = self._extract_spring_route_methods(content, variables)
            
            # Step 4: Process each route method
            for method_info in route_methods:
                try:
                    # Create framework context for template resolution
                    context = FrameworkContext(
                        framework=Framework.SPRING,
                        file_path=file_path,
                        file_content=content,
                        variables=variables,
                        configuration=controller_config
                    )
                    
                    # Resolve property placeholders if needed
                    if '${' in method_info['path']:
                        resolved = self.template_resolver.resolve_template(method_info['path'], context)
                        final_path = resolved.resolved_path
                        path_params = resolved.path_parameters
                        query_params = resolved.query_parameters
                        original_path = method_info['path']
                        template_metadata = resolved.metadata
                    else:
                        final_path = self._normalize_spring_path(method_info['path'])
                        path_params = self._extract_spring_path_params(final_path)
                        query_params = []
                        original_path = method_info['path']
                        template_metadata = {}
                    
                    # Combine controller path with method path
                    if controller_config.get('base_path'):
                        if controller_config['base_path'].startswith('/'):
                            full_path = controller_config['base_path'] + final_path
                        else:
                            full_path = '/' + controller_config['base_path'] + final_path
                    else:
                        full_path = final_path
                    
                    # Normalize the final path
                    full_path = self._normalize_spring_path(full_path)
                    
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
                    route_info = self._create_enhanced_spring_route_info(
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
                    print(f"Error processing Spring Boot route method: {e}")
                    continue
            
        except Exception as e:
            print(f"Error processing Spring Boot routes in {file_path}: {e}")
        
        return routes
    
    def _is_spring_boot_file(self, file_path: str, content: str) -> bool:
        """Check if file is a Spring Boot Java file"""
        if not file_path.endswith('.java'):
            return False
        
        # Check for Spring Boot indicators
        spring_indicators = [
            '@Controller',
            '@RestController',
            '@RequestMapping',
            '@GetMapping',
            '@PostMapping',
            '@PutMapping',
            '@DeleteMapping',
            '@SpringBootApplication',
            'org.springframework'
        ]
        
        return any(indicator in content for indicator in spring_indicators)
    
    def _extract_spring_variables(self, content: str) -> Dict[str, str]:
        """Extract Spring constants, final strings, and property placeholders"""
        variables = {}
        
        # Extract final String constants
        final_string_matches = self.spring_patterns['final_string'].findall(content)
        for var_name, var_value in final_string_matches:
            variables[var_name] = var_value
        
        # Extract static final constants
        constant_matches = self.spring_patterns['constant'].findall(content)
        for var_name, var_value in constant_matches:
            variables[var_name] = var_value
        
        # Extract common Spring property placeholders
        property_placeholders = [
            'server.servlet.context-path',
            'app.api.prefix',
            'api.version',
            'api.base-path',
            'management.endpoints.web.base-path'
        ]
        
        for placeholder in property_placeholders:
            # Convert to variable format
            var_name = placeholder.replace('.', '_').replace('-', '_').upper()
            variables[var_name] = f"${{{placeholder}}}"
        
        return variables
    
    def _parse_controller_config(self, content: str, variables: Dict[str, str]) -> Dict[str, Any]:
        """Parse Spring Boot controller-level configuration"""
        config = {}
        
        # Find @Controller or @RestController
        controller_match = self.spring_patterns['controller'].search(content)
        if controller_match and controller_match.group(1):
            config['controller_path'] = controller_match.group(1)
        
        # Find @RequestMapping at class level
        request_mapping_match = self.spring_patterns['request_mapping'].search(content)
        if request_mapping_match:
            base_path = request_mapping_match.group(1)
            
            # Resolve property placeholders in base path
            if '${' in base_path:
                for var_name, var_value in variables.items():
                    placeholder = f"${{{var_name.lower().replace('_', '.')}}}"
                    if placeholder in base_path:
                        base_path = base_path.replace(placeholder, var_value)
                        config['original_base_path'] = request_mapping_match.group(1)
            
            config['base_path'] = base_path
        
        # Extract additional @RequestMapping properties
        request_mapping_props = self.spring_patterns['request_mapping_props'].search(content)
        if request_mapping_props:
            props_string = request_mapping_props.group(1)
            
            # Extract produces/consumes
            if 'produces' in props_string:
                produces_match = re.search(r'produces\s*=\s*[\'"`]([^\'"`,]*)[\'"`]', props_string)
                if produces_match:
                    config['produces'] = produces_match.group(1)
            
            if 'consumes' in props_string:
                consumes_match = re.search(r'consumes\s*=\s*[\'"`]([^\'"`,]*)[\'"`]', props_string)
                if consumes_match:
                    config['consumes'] = consumes_match.group(1)
        
        return config
    
    def _extract_spring_route_methods(self, content: str, variables: Dict[str, str]) -> List[Dict[str, Any]]:
        """Extract Spring Boot route method definitions"""
        methods = []
        lines = content.split('\n')
        
        # Method mapping patterns
        method_patterns = [
            ('GET', self.spring_patterns['get_mapping']),
            ('POST', self.spring_patterns['post_mapping']),
            ('PUT', self.spring_patterns['put_mapping']),
            ('DELETE', self.spring_patterns['delete_mapping']),
            ('PATCH', self.spring_patterns['patch_mapping']),
            ('REQUEST', self.spring_patterns['request_mapping']),  # Generic mapping
        ]
        
        for i, line in enumerate(lines):
            for method_name, pattern in method_patterns:
                match = pattern.search(line)
                if match:
                    path = match.group(1) if match.group(1) else ""
                    
                    # For @RequestMapping, extract method from annotation
                    if method_name == 'REQUEST':
                        method_name = self._extract_request_mapping_method(lines, i)
                    
                    # Resolve variable references in path
                    resolved_path = path
                    for var_name, var_value in variables.items():
                        if var_name in path:
                            resolved_path = resolved_path.replace(var_name, var_value)
                    
                    # Extract method configuration
                    method_config = self._extract_spring_method_config(lines, i)
                    
                    methods.append({
                        'method': method_name,
                        'path': resolved_path,
                        'original_path': path,
                        'line_number': i + 1,
                        'config': method_config,
                        'annotation': line.strip()
                    })
                    break
        
        return methods
    
    def _extract_request_mapping_method(self, lines: List[str], line_index: int) -> str:
        """Extract HTTP method from @RequestMapping annotation"""
        current_line = lines[line_index]
        
        # Check for method in the same line
        method_match = re.search(r'method\s*=\s*RequestMethod\.(\w+)', current_line)
        if method_match:
            return method_match.group(1)
        
        # Check surrounding lines
        for offset in [-1, 1, 2]:
            check_index = line_index + offset
            if 0 <= check_index < len(lines):
                line = lines[check_index]
                method_match = re.search(r'method\s*=\s*RequestMethod\.(\w+)', line)
                if method_match:
                    return method_match.group(1)
        
        return 'GET'  # Default method
    
    def _extract_spring_method_config(self, lines: List[str], line_index: int) -> Dict[str, Any]:
        """Extract Spring method configuration (security, validation, etc.)"""
        config = {
            'security_annotations': [],
            'validation_annotations': [],
            'method_signature': ''
        }
        
        # Look backwards for annotations
        j = line_index - 1
        while j >= 0 and (lines[j].strip().startswith('@') or lines[j].strip() == ''):
            annotation_line = lines[j].strip()
            if annotation_line.startswith('@'):
                config['security_annotations'].append(annotation_line)
                
                # Check for security annotations
                if any(sec_ann in annotation_line for sec_ann in ['@Secured', '@PreAuthorize', '@RolesAllowed']):
                    config['has_security'] = True
                
                # Check for validation annotations
                if any(val_ann in annotation_line for val_ann in ['@Valid', '@Validated', '@NotNull']):
                    config['validation_annotations'].append(annotation_line)
            
            j -= 1
        
        # Look forward for method signature
        k = line_index + 1
        while k < len(lines) and not lines[k].strip().endswith('{'):
            if 'public' in lines[k] or 'private' in lines[k] or 'protected' in lines[k]:
                config['method_signature'] = lines[k].strip()
                break
            k += 1
        
        return config
    
    def _normalize_spring_path(self, path: str) -> str:
        """Normalize Spring Boot path"""
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
    
    def _extract_spring_path_params(self, path: str) -> List[str]:
        """Extract path parameters from Spring Boot route path"""
        params = []
        
        # Spring style: {id}
        spring_params = re.findall(r'\{(\w+)\}', path)
        params.extend(spring_params)
        
        # Spring PathVariable style: {id:.*}
        path_var_params = re.findall(r'\{(\w+):[^}]+\}', path)
        params.extend(path_var_params)
        
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
        }
        
        return method_mapping.get(method_str.upper())
    
    def _create_enhanced_spring_route_info(self, method: HTTPMethod, path: str, original_path: str,
                                          file_path: str, line_number: int, path_params: List[str],
                                          query_params: List[str], variables: Dict[str, str],
                                          controller_config: Dict[str, Any], method_config: Dict[str, Any],
                                          template_metadata: Dict[str, Any], content: str) -> RouteInfo:
        """Create enhanced RouteInfo with Spring Boot-specific context"""
        
        # Extract authentication info
        auth_info = self._extract_spring_auth_info(content, method_config)
        
        # Create route parameters
        route_parameters = []
        
        # Add path parameters
        for param in path_params:
            route_parameters.append(RouteParameter(
                name=param,
                type="string",
                required=True,
                location="path",
                description=f"Spring Boot path parameter: {param}"
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
            'original_template': original_path if '${' in original_path else None,
            'resolved_variables': {k: v for k, v in variables.items() if f'${{{k}}}' in original_path},
            'path_parameters': path_params,
            'query_parameters': query_params,
            'template_resolution': '${' in original_path,
            'controller_config': controller_config,
            'security_annotations': method_config.get('security_annotations', []),
            'validation_annotations': method_config.get('validation_annotations', []),
            'method_annotation': method_config.get('annotation'),
            'method_signature': method_config.get('method_signature'),
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
        route_info.risk_level = self._assess_spring_risk_level(path, method.value, route_info.auth_type, method_config)
        route_info.risk_score = self._calculate_spring_risk_score(route_info, content, method_config)
        
        return route_info
    
    def _extract_spring_auth_info(self, content: str, method_config: Dict[str, Any]) -> Dict[str, Any]:
        """Extract authentication information from Spring Boot content"""
        auth_info = {
            'type': AuthType.UNKNOWN,
            'required': False
        }
        
        # Check security annotations first
        security_annotations = method_config.get('security_annotations', [])
        if any('@Secured' in ann or '@PreAuthorize' in ann or '@RolesAllowed' in ann for ann in security_annotations):
            auth_info['required'] = True
            auth_info['type'] = AuthType.CUSTOM
        
        # Check for Spring Security patterns in content
        for auth_type, patterns in self.auth_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    auth_info['type'] = auth_type
                    auth_info['required'] = True
                    return auth_info
        
        return auth_info
    
    def _assess_spring_risk_level(self, path: str, method: str, auth_type: AuthType, method_config: Dict[str, Any]) -> RiskLevel:
        """Assess risk level for Spring Boot routes"""
        risk_score = 0
        
        # Method-based risk
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            risk_score += 2
        
        # Path-based risk
        high_risk_patterns = [
            r'/admin', r'/actuator', r'/management',
            r'/api/admin', r'/api/internal', r'/debug',
            r'/delete', r'/upload', r'/config'
        ]
        
        for pattern in high_risk_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                risk_score += 3
                break
        
        # Authentication risk
        if auth_type == AuthType.UNKNOWN:
            risk_score += 4
        elif not method_config.get('has_security', False):
            risk_score += 2  # No security annotations
        
        # Spring Boot specific risks
        if '/actuator' in path:
            risk_score += 2  # Spring Boot actuator endpoints
        
        # Map score to risk level
        if risk_score >= 7:
            return RiskLevel.CRITICAL
        elif risk_score >= 5:
            return RiskLevel.HIGH
        elif risk_score >= 3:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_spring_risk_score(self, route_info: RouteInfo, content: str, method_config: Dict[str, Any]) -> float:
        """Calculate detailed risk score for Spring Boot routes"""
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
        
        # Security annotation assessment
        security_annotations = route_info.metadata.get('security_annotations', [])
        if not security_annotations:
            base_score += 2.0
            risk_factors.append("No security annotations")
        
        # Parameter validation risk
        if route_info.parameters:
            validation_annotations = route_info.metadata.get('validation_annotations', [])
            if not validation_annotations:
                base_score += 1.0
                risk_factors.append("Unvalidated parameters")
        
        # Template resolution risk
        if route_info.metadata.get('template_resolution'):
            base_score += 1.0
            risk_factors.append("Property placeholder resolution")
        
        # Spring Boot actuator risk
        if '/actuator' in route_info.path:
            base_score += 2.0
            risk_factors.append("Spring Boot actuator endpoint")
        
        # Store risk factors
        route_info.risk_factors = risk_factors
        
        return min(base_score, 10.0)  # Cap at 10.0 