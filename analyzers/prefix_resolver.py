"""
RouteHawk Prefix Resolution System

Implements comprehensive prefix detection and resolution for enterprise microservice architectures.
Handles framework-level, service-level, and infrastructure-level prefix detection.
"""

import re
import json
import yaml
import logging
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

from models import RoutePrefix, PrefixBreakdown, Framework


class PrefixResolver:
    """
    Multi-level prefix resolution system for enterprise route detection.
    
    Handles:
    - Framework-level prefixes (NestJS @Controller, Express app.use)
    - Service-level prefixes (global prefixes, versioning)
    - Infrastructure-level prefixes (deployment configs, env vars)
    - Organization-specific patterns
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        
        # Compile regex patterns for performance
        self._compile_patterns()
        
        # Load organization-specific prefix patterns
        self.org_patterns = self.config.get('prefix_patterns', {})
        
    def _compile_patterns(self):
        """Compile regex patterns for better performance"""
        self.framework_patterns = {
            Framework.NESTJS: {
                'controller': re.compile(r'@Controller\([\'"`]([^\'"`]+)[\'"`]\)', re.MULTILINE),
                'global_prefix': re.compile(r'app\.setGlobalPrefix\([\'"`]([^\'"`]+)[\'"`]\)', re.MULTILINE),
                'versioning': re.compile(r'app\.enableVersioning\(\)', re.MULTILINE),
                'module_prefix': re.compile(r'RouterModule\.forRoot\([^,]+,\s*{\s*prefix:\s*[\'"`]([^\'"`]+)[\'"`]', re.MULTILINE)
            },
            Framework.EXPRESS: {
                'router': re.compile(r'app\.use\([\'"`]([^\'"`]+)[\'"`],\s*\w+\)', re.MULTILINE),
                'route_mount': re.compile(r'app\.use\([\'"`]([^\'"`]+)[\'"`]', re.MULTILINE),
                'router_get': re.compile(r'router\.[a-z]+\([\'"`]([^\'"`]+)[\'"`]', re.MULTILINE),
                'app_method': re.compile(r'app\.[a-z]+\([\'"`]([^\'"`]+)[\'"`]', re.MULTILINE)
            },
            Framework.GRPC: {
                'service': re.compile(r'service\s+(\w+)\s*\{', re.MULTILINE),
                'package': re.compile(r'package\s+([a-zA-Z0-9_.]+);', re.MULTILINE)
            }
        }
        
        # Variable resolution patterns
        self.variable_patterns = {
            'template_vars': re.compile(r'\$\{([^}]+)\}'),
            'env_vars': re.compile(r'process\.env\.([A-Z_]+)'),
            'config_vars': re.compile(r'config\.get\([\'"`]([^\'"`]+)[\'"`]\)')
        }
    
    async def resolve_prefix(self, service_path: str, file_path: str, framework: Framework) -> RoutePrefix:
        """
        Main entry point for prefix resolution.
        
        Args:
            service_path: Root path of the service
            file_path: Specific file being analyzed
            framework: Framework type
            
        Returns:
            RoutePrefix: Comprehensive prefix information
        """
        try:
            # Detect prefixes from multiple sources
            framework_prefixes = await self._detect_framework_prefixes(file_path, framework)
            service_prefixes = await self._detect_service_prefixes(service_path, framework)
            infrastructure_prefixes = await self._detect_infrastructure_prefixes(service_path)
            
            # Merge and resolve conflicts
            merged_prefix = self._merge_prefixes(
                framework_prefixes, 
                service_prefixes, 
                infrastructure_prefixes
            )
            
            # Apply organization-specific patterns
            enriched_prefix = self._apply_organization_patterns(merged_prefix, service_path)
            
            return enriched_prefix
            
        except Exception as e:
            self.logger.error(f"Error resolving prefix for {file_path}: {e}")
            return RoutePrefix(source="error", confidence=0.0)
    
    async def _detect_framework_prefixes(self, file_path: str, framework: Framework) -> List[str]:
        """Detect framework-level prefixes (decorators, route mounting)"""
        prefixes = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if framework == Framework.NESTJS:
                prefixes.extend(self._detect_nestjs_prefixes(content))
            elif framework == Framework.EXPRESS:
                prefixes.extend(self._detect_express_prefixes(content))
            elif framework == Framework.GRPC:
                prefixes.extend(self._detect_grpc_prefixes(content))
                
        except Exception as e:
            self.logger.debug(f"Could not read file {file_path}: {e}")
        
        return list(set(prefixes))  # Remove duplicates
    
    def _detect_nestjs_prefixes(self, content: str) -> List[str]:
        """Detect NestJS-specific prefixes"""
        prefixes = []
        
        # Controller decorators
        for match in self.framework_patterns[Framework.NESTJS]['controller'].finditer(content):
            prefix = match.group(1).strip('/"\'')
            if prefix and not prefix.startswith('$'):  # Skip template variables for now
                prefixes.append(f"/{prefix}" if not prefix.startswith('/') else prefix)
        
        # Global prefix settings
        for match in self.framework_patterns[Framework.NESTJS]['global_prefix'].finditer(content):
            prefix = match.group(1).strip('/"\'')
            if prefix:
                prefixes.append(f"/{prefix}" if not prefix.startswith('/') else prefix)
        
        # Version prefixes
        if self.framework_patterns[Framework.NESTJS]['versioning'].search(content):
            prefixes.extend(['/v1', '/v2'])  # Common version patterns
        
        return prefixes
    
    def _detect_express_prefixes(self, content: str) -> List[str]:
        """Detect Express.js-specific prefixes"""
        prefixes = []
        
        # Router mounting
        for match in self.framework_patterns[Framework.EXPRESS]['router'].finditer(content):
            prefix = match.group(1).strip('/"\'')
            if prefix and not prefix.startswith('$'):
                prefixes.append(f"/{prefix}" if not prefix.startswith('/') else prefix)
        
        # Route mounting
        for match in self.framework_patterns[Framework.EXPRESS]['route_mount'].finditer(content):
            prefix = match.group(1).strip('/"\'')
            if prefix and not prefix.startswith('$'):
                prefixes.append(f"/{prefix}" if not prefix.startswith('/') else prefix)
        
        return prefixes
    
    def _detect_grpc_prefixes(self, content: str) -> List[str]:
        """Detect gRPC-specific prefixes"""
        prefixes = []
        
        # Package names become service prefixes
        for match in self.framework_patterns[Framework.GRPC]['package'].finditer(content):
            package = match.group(1)
            # Convert package.v1 -> /package/v1
            prefix = f"/{package.replace('.', '/')}"
            prefixes.append(prefix)
        
        # Service names
        for match in self.framework_patterns[Framework.GRPC]['service'].finditer(content):
            service_name = match.group(1)
            # Convert ServiceName -> /ServiceName
            prefixes.append(f"/{service_name}")
        
        return prefixes
    
    async def _detect_service_prefixes(self, service_path: str, framework: Framework) -> List[str]:
        """Detect service-level prefixes from configuration files"""
        prefixes = []
        
        # Check package.json
        package_json_path = Path(service_path) / 'package.json'
        if package_json_path.exists():
            prefixes.extend(self._parse_package_json_prefixes(package_json_path))
        
        # Check main application files
        main_files = self._find_main_files(service_path, framework)
        for main_file in main_files:
            prefixes.extend(await self._parse_main_file_prefixes(main_file, framework))
        
        # Check environment files
        env_prefixes = self._parse_env_prefixes(service_path)
        prefixes.extend(env_prefixes)
        
        return list(set(prefixes))
    
    def _parse_package_json_prefixes(self, package_json_path: Path) -> List[str]:
        """Extract prefixes from package.json configuration"""
        prefixes = []
        
        try:
            with open(package_json_path, 'r') as f:
                package_data = json.load(f)
            
            # Service name becomes prefix
            name = package_data.get('name', '')
            if name:
                # Extract service name from package name
                service_name = name.split('/')[-1]  # Handle @org/service-name
                if service_name.endswith('-service'):
                    service_name = service_name[:-8]  # Remove -service suffix
                
                prefixes.append(f"/{service_name}")
            
            # Check for custom prefix configuration
            config = package_data.get('routehawk', {})
            if 'prefix' in config:
                prefixes.append(config['prefix'])
            
            # Analyze scripts for multi-app patterns
            scripts = package_data.get('scripts', {})
            for script_name, script_command in scripts.items():
                if script_name.startswith('start:dev:'):
                    app_name = script_name.replace('start:dev:', '')
                    prefixes.append(f"/api/{app_name}")
                    
        except Exception as e:
            self.logger.debug(f"Could not parse package.json at {package_json_path}: {e}")
        
        return prefixes
    
    def _find_main_files(self, service_path: str, framework: Framework) -> List[str]:
        """Find main application files for different frameworks"""
        main_files = []
        service_dir = Path(service_path)
        
        if framework == Framework.NESTJS:
            candidates = ['src/main.ts', 'main.ts', 'src/app.module.ts', 'apps/*/src/main.ts']
        elif framework == Framework.EXPRESS:
            candidates = ['src/app.js', 'app.js', 'src/server.js', 'server.js', 'src/index.js', 'index.js']
        else:
            candidates = ['src/main.*', 'main.*', 'app.*', 'server.*']
        
        for pattern in candidates:
            if '*' in pattern:
                # Handle glob patterns
                for file_path in service_dir.glob(pattern):
                    if file_path.is_file():
                        main_files.append(str(file_path))
            else:
                file_path = service_dir / pattern
                if file_path.exists() and file_path.is_file():
                    main_files.append(str(file_path))
        
        return main_files
    
    async def _parse_main_file_prefixes(self, main_file: str, framework: Framework) -> List[str]:
        """Parse main application files for global prefixes"""
        prefixes = []
        
        try:
            with open(main_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if framework == Framework.NESTJS:
                # Global prefix
                global_prefix_pattern = re.compile(r'app\.setGlobalPrefix\([\'"`]([^\'"`]+)[\'"`]\)')
                for match in global_prefix_pattern.finditer(content):
                    prefix = match.group(1)
                    prefixes.append(f"/{prefix}" if not prefix.startswith('/') else prefix)
                
                # Versioning
                if 'app.enableVersioning()' in content:
                    prefixes.extend(['/v1', '/v2'])
            
            elif framework == Framework.EXPRESS:
                # App-level prefixes
                app_prefix_pattern = re.compile(r'app\.use\([\'"`]([^\'"`]+)[\'"`]')
                for match in app_prefix_pattern.finditer(content):
                    prefix = match.group(1)
                    if not prefix.startswith('$'):  # Skip template variables
                        prefixes.append(f"/{prefix}" if not prefix.startswith('/') else prefix)
                        
        except Exception as e:
            self.logger.debug(f"Could not parse main file {main_file}: {e}")
        
        return prefixes
    
    def _parse_env_prefixes(self, service_path: str) -> List[str]:
        """Parse environment files for prefix configuration"""
        prefixes = []
        service_dir = Path(service_path)
        
        # Check common env files
        env_files = ['.env', '.env.local', '.env.development', '.env.production']
        
        for env_file_name in env_files:
            env_file = service_dir / env_file_name
            if env_file.exists():
                try:
                    with open(env_file, 'r') as f:
                        content = f.read()
                    
                    # Look for prefix-related environment variables
                    prefix_vars = [
                        'API_PREFIX', 'SERVICE_PREFIX', 'BASE_PATH', 
                        'ROUTE_PREFIX', 'APP_PREFIX', 'SERVER_PREFIX'
                    ]
                    
                    for var in prefix_vars:
                        pattern = re.compile(f'{var}=([^\n]+)')
                        match = pattern.search(content)
                        if match:
                            prefix = match.group(1).strip('\'"')
                            prefixes.append(f"/{prefix}" if not prefix.startswith('/') else prefix)
                            
                except Exception as e:
                    self.logger.debug(f"Could not parse env file {env_file}: {e}")
        
        return prefixes
    
    async def _detect_infrastructure_prefixes(self, service_path: str) -> List[str]:
        """Detect infrastructure-level prefixes from deployment configs"""
        prefixes = []
        service_dir = Path(service_path)
        
        # Check Docker configuration
        dockerfile_path = service_dir / 'Dockerfile'
        if dockerfile_path.exists():
            prefixes.extend(self._parse_dockerfile_prefixes(dockerfile_path))
        
        # Check docker-compose files
        compose_files = list(service_dir.glob('docker-compose*.yml')) + list(service_dir.glob('docker-compose*.yaml'))
        for compose_file in compose_files:
            prefixes.extend(self._parse_docker_compose_prefixes(compose_file))
        
        # Check Kubernetes manifests
        k8s_files = list(service_dir.glob('k8s/*.yaml')) + list(service_dir.glob('k8s/*.yml'))
        for k8s_file in k8s_files:
            prefixes.extend(self._parse_k8s_prefixes(k8s_file))
        
        return list(set(prefixes))
    
    def _parse_dockerfile_prefixes(self, dockerfile_path: Path) -> List[str]:
        """Parse Dockerfile for prefix-related environment variables"""
        prefixes = []
        
        try:
            with open(dockerfile_path, 'r') as f:
                content = f.read()
            
            # Look for ENV declarations with prefix-related variables
            env_pattern = re.compile(r'ENV\s+(API_PREFIX|SERVICE_PREFIX|BASE_PATH)\s+([^\n]+)')
            for match in env_pattern.finditer(content):
                prefix = match.group(2).strip('\'"')
                prefixes.append(f"/{prefix}" if not prefix.startswith('/') else prefix)
                
        except Exception as e:
            self.logger.debug(f"Could not parse Dockerfile {dockerfile_path}: {e}")
        
        return prefixes
    
    def _parse_docker_compose_prefixes(self, compose_file: Path) -> List[str]:
        """Parse docker-compose files for prefix configuration"""
        prefixes = []
        
        try:
            with open(compose_file, 'r') as f:
                compose_data = yaml.safe_load(f)
            
            # Check environment variables in services
            services = compose_data.get('services', {})
            for service_name, service_config in services.items():
                environment = service_config.get('environment', {})
                
                # Handle both dict and list formats
                if isinstance(environment, dict):
                    env_vars = environment
                elif isinstance(environment, list):
                    env_vars = {}
                    for env_item in environment:
                        if '=' in env_item:
                            key, value = env_item.split('=', 1)
                            env_vars[key] = value
                else:
                    continue
                
                # Look for prefix-related variables
                for var_name, var_value in env_vars.items():
                    if any(prefix_var in var_name.upper() for prefix_var in ['PREFIX', 'BASE_PATH']):
                        prefix = str(var_value).strip('\'"')
                        prefixes.append(f"/{prefix}" if not prefix.startswith('/') else prefix)
                        
        except Exception as e:
            self.logger.debug(f"Could not parse docker-compose file {compose_file}: {e}")
        
        return prefixes
    
    def _parse_k8s_prefixes(self, k8s_file: Path) -> List[str]:
        """Parse Kubernetes manifests for prefix configuration"""
        prefixes = []
        
        try:
            with open(k8s_file, 'r') as f:
                # Handle multiple YAML documents
                for doc in yaml.safe_load_all(f):
                    if not doc:
                        continue
                    
                    # Check Ingress resources
                    if doc.get('kind') == 'Ingress':
                        spec = doc.get('spec', {})
                        rules = spec.get('rules', [])
                        
                        for rule in rules:
                            http = rule.get('http', {})
                            paths = http.get('paths', [])
                            
                            for path_item in paths:
                                path = path_item.get('path', '')
                                if path and path != '/':
                                    prefixes.append(path)
                    
                    # Check environment variables in Deployments
                    elif doc.get('kind') == 'Deployment':
                        spec = doc.get('spec', {})
                        template = spec.get('template', {})
                        pod_spec = template.get('spec', {})
                        containers = pod_spec.get('containers', [])
                        
                        for container in containers:
                            env = container.get('env', [])
                            for env_var in env:
                                name = env_var.get('name', '')
                                value = env_var.get('value', '')
                                
                                if any(prefix_var in name.upper() for prefix_var in ['PREFIX', 'BASE_PATH']):
                                    if value:
                                        prefix = str(value).strip('\'"')
                                        prefixes.append(f"/{prefix}" if not prefix.startswith('/') else prefix)
                                        
        except Exception as e:
            self.logger.debug(f"Could not parse Kubernetes file {k8s_file}: {e}")
        
        return prefixes
    
    def _merge_prefixes(self, framework_prefixes: List[str], service_prefixes: List[str], 
                       infrastructure_prefixes: List[str]) -> RoutePrefix:
        """Merge prefixes from different sources and resolve conflicts"""
        
        all_prefixes = framework_prefixes + service_prefixes + infrastructure_prefixes
        unique_prefixes = list(set(all_prefixes))
        
        # Build full prefix by combining different levels
        full_prefix_parts = []
        
        # Infrastructure level (lowest precedence)
        if infrastructure_prefixes:
            full_prefix_parts.extend(infrastructure_prefixes[:1])  # Take first one
        
        # Service level (medium precedence)
        if service_prefixes:
            full_prefix_parts.extend(service_prefixes[:1])  # Take first one
        
        # Framework level (highest precedence)
        if framework_prefixes:
            full_prefix_parts.extend(framework_prefixes[:1])  # Take first one
        
        # Construct full prefix
        full_prefix = '/'.join(part.strip('/') for part in full_prefix_parts if part.strip('/'))
        if full_prefix and not full_prefix.startswith('/'):
            full_prefix = f"/{full_prefix}"
        
        # Detect conflicts
        conflicts = []
        if len(unique_prefixes) > len(set(p.strip('/') for p in unique_prefixes)):
            conflicts = [f"Multiple prefixes detected: {unique_prefixes}"]
        
        # Calculate confidence based on source consistency
        confidence = self._calculate_confidence(framework_prefixes, service_prefixes, infrastructure_prefixes)
        
        return RoutePrefix(
            framework=framework_prefixes,
            service=service_prefixes,
            infrastructure=infrastructure_prefixes,
            full=full_prefix,
            source="detected",
            confidence=confidence,
            conflicts=conflicts
        )
    
    def _calculate_confidence(self, framework_prefixes: List[str], service_prefixes: List[str], 
                             infrastructure_prefixes: List[str]) -> float:
        """Calculate confidence score based on prefix consistency"""
        
        total_sources = sum([
            1 if framework_prefixes else 0,
            1 if service_prefixes else 0,
            1 if infrastructure_prefixes else 0
        ])
        
        if total_sources == 0:
            return 0.0
        
        # High confidence if multiple sources agree
        all_prefixes = framework_prefixes + service_prefixes + infrastructure_prefixes
        unique_prefixes = set(p.strip('/') for p in all_prefixes)
        
        if len(unique_prefixes) == 1 and total_sources > 1:
            return 0.9  # High confidence - multiple sources agree
        elif len(unique_prefixes) <= 2 and total_sources > 1:
            return 0.7  # Good confidence - mostly consistent
        elif framework_prefixes:
            return 0.6  # Medium confidence - at least framework detection
        else:
            return 0.4  # Low confidence - only service/infra detection
    
    def _apply_organization_patterns(self, prefix: RoutePrefix, service_path: str) -> RoutePrefix:
        """Apply organization-specific patterns and enhancements"""
        
        # Get organization patterns from config
        org_patterns = self.org_patterns.get('service_categories', {})
        
        # Try to classify service and apply appropriate prefixes
        service_name = Path(service_path).name.lower()
        
        for category, config in org_patterns.items():
            patterns = config.get('prefixes', [])
            confidence_boost = config.get('confidence', 0.0)
            
            # Check if service matches this category
            if any(pattern in service_name for pattern in config.get('service_patterns', [])):
                # Add category-specific prefixes
                if not prefix.service:
                    prefix.service = patterns[:1]  # Take first pattern
                    prefix.confidence = max(prefix.confidence, confidence_boost)
                    prefix.source = "organization_pattern"
        
        return prefix
    
    def resolve_route_path(self, original_path: str, prefix: RoutePrefix, file_path: str = None) -> Tuple[str, PrefixBreakdown]:
        """
        Resolve full route path and provide detailed breakdown.
        
        Args:
            original_path: Original route path (e.g., '/users/:id')
            prefix: Resolved prefix information
            file_path: Optional file path for extracting local variables
            
        Returns:
            Tuple of (full_path, prefix_breakdown)
        """
        
        # Handle template variables in original path with file-specific resolution
        file_content = None
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_content = f.read()
            except Exception as e:
                self.logger.debug(f"Could not read file for variable resolution {file_path}: {e}")
        
        resolved_path = self._resolve_template_variables(original_path, file_content)
        
        # Build full path
        if prefix.full:
            full_path = f"{prefix.full.rstrip('/')}/{resolved_path.lstrip('/')}"
        else:
            full_path = resolved_path
        
        # Clean up path
        full_path = re.sub(r'/+', '/', full_path)  # Remove duplicate slashes
        
        # Create breakdown
        breakdown = PrefixBreakdown(
            infrastructure='/'.join(prefix.infrastructure) if prefix.infrastructure else '',
            service='/'.join(prefix.service) if prefix.service else '',
            api='/'.join(prefix.framework) if prefix.framework else '',
            route=resolved_path
        )
        
        return full_path, breakdown
    
    def _resolve_template_variables(self, path: str, file_content: str = None) -> str:
        """Resolve common template variables in route paths using file-specific definitions"""
        
        # If we have file content, try to extract local variable definitions
        local_variables = {}
        if file_content:
            local_variables = self._extract_local_variables(file_content)
        
        # Combine local variables with common variable resolutions
        variable_resolutions = {
            '${prefix}': '/api',
            '${PREFIX}': '/api',
            '${apiPrefix}': '/api',
            '${API_PREFIX}': '/api',
            '${version}': '/v1',
            '${VERSION}': '/v1',
            '${env}': '',  # Usually empty in resolved paths
            '${ENV}': '',
            '${misPrefix}': '/sbgo-merchant-platform-information-service',
            '${webPrefix}': '/demo/web/merchant',
            **local_variables  # File-specific variables take precedence
        }
        
        resolved_path = path
        for variable, replacement in variable_resolutions.items():
            resolved_path = resolved_path.replace(variable, replacement)
        
        return resolved_path
    
    def _extract_local_variables(self, file_content: str) -> Dict[str, str]:
        """Extract local variable definitions from JavaScript/TypeScript file content"""
        variables = {}
        
        # Pattern to match: const variableName = 'value' or const variableName = "/value"
        variable_patterns = [
            re.compile(r'const\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            re.compile(r'let\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            re.compile(r'var\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
        ]
        
        for pattern in variable_patterns:
            matches = pattern.findall(file_content)
            for var_name, var_value in matches:
                # Only capture variables that look like prefixes (contain common prefix keywords)
                if any(keyword in var_name.lower() for keyword in ['prefix', 'path', 'base', 'route']):
                    variables[f'${{{var_name}}}'] = var_value
                    self.logger.debug(f"Extracted local variable: ${{{var_name}}} = {var_value}")
        
        return variables 