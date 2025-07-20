#!/usr/bin/env python3
"""
RouteHawk Attack Surface Discovery Tool

Main scanner script for discovering and analyzing API routes and security vulnerabilities
across modern web applications and microservices.
"""

import os
import sys

# Ensure local modules can be imported
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

import time
import json
import uuid
import logging
import argparse
import asyncio
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from models import (
    ScanResult, ServiceInfo, RouteInfo, Framework, 
    RiskLevel, ScanConfig, GitLabIntegration,
    ComparisonConfig, ComparisonFilter, ComparisonResult
)
from detectors.nestjs_detector import NestJSDetector
from detectors.express_detector import ExpressDetector
from detectors.nextjs_detector import NextJSDetector
from detectors.go_detector import GoDetector
from detectors.python_detector import PythonDetector
from detectors.spring_detector import SpringBootDetector
from detectors.grpc_detector import GRPCDetector
from analyzers.ai_analyzer import AIAnalyzer
from analyzers.risk_scorer import RiskScorer
from analyzers.prefix_resolver import PrefixResolver
from analyzers.organization_patterns import OrganizationPatternAnalyzer
from analyzers.directory_comparator import DirectoryComparator
from analyzers.route_comparator import RouteComparator
from analyzers.git_operations import GitConfig, AuthMethod
from analyzers.remote_repository import RemoteRepository, RepositoryInfo, RepositoryPlatform
from analyzers.enhanced_route_comparator import EnhancedRouteComparator, BatchComparisonResult
from analyzers.batch_operations import BatchOperationsManager, BatchJob, BatchJobResult
from reports.json_exporter import JSONExporter
from reports.html_exporter import HTMLExporter
from reports.sarif_exporter import SARIFExporter
from reports.csv_exporter import CSVExporter
from analyzers.performance_optimizer import (
    PerformanceOptimizer, RepositoryMetrics, ScanStrategy, RepositorySize, PerformanceMetrics, IntelligentCache
)
from config.enterprise_config import ConfigurationManager, get_config_manager, get_enterprise_config

console = Console()

class AttackSurfaceScanner:
    """Main scanner class for discovering attack surface across modern codebases."""
    
    def __init__(self, config: ScanConfig, config_manager = None):
        self.config = config
        self.console = console
        self.logger = self._setup_logging()
        self.config_manager = config_manager
        
        # Initialize detectors
        self.detectors = self._initialize_detectors()
        
        # Initialize analyzers with configuration manager
        self.ai_analyzer = AIAnalyzer() if config.use_ai_analysis else None
        self.risk_scorer = RiskScorer(config_manager=config_manager)
        
        # Initialize prefix resolver
        self.prefix_resolver = None
        if config.resolve_prefixes:
            prefix_config = self._load_prefix_config()
            self.prefix_resolver = PrefixResolver(prefix_config)
        
        # Initialize exporters
        self.exporters = self._initialize_exporters()
        
        # Initialize performance optimizer (Phase 4)
        self.performance_optimizer = PerformanceOptimizer(config)
        self.repository_metrics = None
        
        # Global deduplication set for deterministic scanning
        self.global_seen_routes = set()
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'routes_found': 0,
            'high_risk_routes': 0,
            'services_found': 0,
            'scan_start_time': None,
            'scan_end_time': None
        }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger('attack_surface_scanner')
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def _initialize_detectors(self) -> List:
        """Initialize framework detectors based on configuration."""
        detectors = []
        
        # Convert string framework values back to enums for comparison
        framework_values = []
        for fw in self.config.frameworks:
            if isinstance(fw, str):
                # Convert string to enum
                try:
                    framework_values.append(Framework(fw))
                except ValueError:
                    self.logger.warning(f"Unknown framework string: {fw}")
                    continue
            else:
                framework_values.append(fw)
        
        # TypeScript/JavaScript frameworks
        if Framework.NESTJS in framework_values:
            detectors.append(NestJSDetector())
        if Framework.EXPRESS in framework_values:
            detectors.append(ExpressDetector())
        if Framework.NEXTJS in framework_values:
            detectors.append(NextJSDetector())
        
        # Backend frameworks
        if Framework.GO_HTTP in framework_values:
            detectors.append(GoDetector())
        if Framework.SPRING in framework_values:
            detectors.append(SpringBootDetector())
        
        # Python frameworks (all map to PythonDetector)
        python_frameworks = {Framework.FASTAPI, Framework.DJANGO, Framework.FLASK}
        if any(fw in framework_values for fw in python_frameworks):
            detectors.append(PythonDetector())
        
        # Infrastructure and other
        if Framework.GRPC in framework_values:
            detectors.append(GRPCDetector())
        
        self.logger.info(f"Initialized {len(detectors)} detectors")
        return detectors
    
    def _initialize_exporters(self) -> Dict:
        """Initialize report exporters."""
        exporters = {}
        
        for format_type in self.config.output_formats:
            if format_type == 'json':
                exporters['json'] = JSONExporter()
            elif format_type == 'html':
                exporters['html'] = HTMLExporter()
            elif format_type == 'sarif':
                exporters['sarif'] = SARIFExporter()
            elif format_type == 'csv':
                exporters['csv'] = CSVExporter()
        
        return exporters
    
    def _load_prefix_config(self) -> Dict[str, Any]:
        """Load prefix resolution configuration."""
        import yaml
        
        # Default config path
        default_config_path = Path(__file__).parent / 'config' / 'prefix_patterns.yaml'
        
        # Use custom config if provided, otherwise use default
        config_path = Path(self.config.prefix_config_path) if self.config.prefix_config_path else default_config_path
        
        try:
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                self.logger.debug(f"Loaded prefix config from {config_path}")
                return config
            else:
                self.logger.warning(f"Prefix config file not found: {config_path}")
                return {}
        except Exception as e:
            self.logger.error(f"Error loading prefix config: {e}")
            return {}
    
    async def scan_repository(self) -> ScanResult:
        """
        Scan the entire repository for API routes and security issues with adaptive performance optimization.
        
        Returns:
            ScanResult containing all discovered routes and analysis
        """
        self.stats['scan_start_time'] = time.time()
        
        # Clear global deduplication set for fresh scan
        self.global_seen_routes.clear()
        
        # Phase 4: Analyze repository for optimal scanning strategy
        console.print("[yellow]🔍 Analyzing repository for optimal scanning strategy...[/yellow]")
        self.repository_metrics = self.performance_optimizer.analyze_repository(self.config.repo_path)
        
        console.print(f"[cyan]📊 Repository Analysis:[/cyan]")
        console.print(f"  • Size: {self.repository_metrics.relevant_files:,} relevant files ({self.repository_metrics.size_category.value})")
        console.print(f"  • Strategy: {self.repository_metrics.recommended_strategy.value}")
        console.print(f"  • Workers: {self.repository_metrics.recommended_workers}")
        console.print(f"  • Estimated time: {self.repository_metrics.estimated_scan_time:.1f}s")
        
        # Start performance monitoring
        self.performance_optimizer.start_performance_monitoring()
        
        with console.status("[bold blue]Scanning repository...") as status:
            # Phase 4: Use optimized file discovery
            status.update("[bold blue]Discovering files (optimized)...")
            files_to_scan = self.performance_optimizer.optimize_file_discovery(
                self.config.repo_path, 
                self.config.include_patterns, 
                self.config.exclude_patterns
            )
            
            # Phase 4: Use adaptive scanning strategy
            status.update(f"[bold blue]Analyzing routes ({self.repository_metrics.recommended_strategy.value})...")
            services = await self._scan_files_adaptive(files_to_scan)
            
            # Perform AI analysis if enabled
            if self.ai_analyzer:
                status.update("[bold blue]Running AI analysis...")
                services = self._enhance_with_ai_analysis(services)
            
            # Calculate risk scores
            status.update("[bold blue]Calculating risk scores...")
            services = self._calculate_risk_scores(services)
            
            # Generate scan result
            status.update("[bold blue]Generating results...")
            
        # Stop performance monitoring
        self.performance_optimizer.stop_performance_monitoring()
        
        self.stats['scan_end_time'] = time.time()
        scan_result = self._generate_scan_result(services)
        self._log_scan_summary(scan_result)
        
        # Phase 4: Display performance report
        performance_report = self.performance_optimizer.get_performance_report()
        self._display_performance_report(performance_report)
        
        return scan_result
    
    def _discover_files(self) -> List[str]:
        """Discover all files to scan based on include/exclude patterns."""
        files = []
        repo_path = Path(self.config.repo_path)
        
        # Use gitignore patterns if available
        gitignore_patterns = self._load_gitignore_patterns()
        
        for include_pattern in self.config.include_patterns:
            for file_path in repo_path.rglob(include_pattern):
                if file_path.is_file():
                    rel_path = str(file_path.relative_to(repo_path))
                    
                    # Check exclude patterns
                    if self._should_exclude_file(rel_path, gitignore_patterns):
                        continue
                    
                    files.append(str(file_path))
        
        self.logger.info(f"Discovered {len(files)} files to scan")
        return files
    
    def _load_gitignore_patterns(self) -> List[str]:
        """Load .gitignore patterns for filtering."""
        gitignore_path = Path(self.config.repo_path) / '.gitignore'
        patterns = []
        
        if gitignore_path.exists():
            with open(gitignore_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        patterns.append(line)
        
        return patterns
    
    def _should_exclude_file(self, file_path: str, gitignore_patterns: List[str]) -> bool:
        """Check if file should be excluded based on patterns."""
        import fnmatch
        
        # Check explicit exclude patterns
        for pattern in self.config.exclude_patterns:
            if fnmatch.fnmatch(file_path, pattern) or pattern in file_path:
                return True
        
        # Check gitignore patterns
        for pattern in gitignore_patterns:
            if fnmatch.fnmatch(file_path, pattern):
                return True
        
        return False
    
    async def _scan_files_adaptive(self, files: List[str]) -> List[ServiceInfo]:
        """
        Scan files using adaptive strategy based on repository size.
        Phase 4: Intelligent caching, memory optimization, and parallel processing.
        """
        services = {}
        strategy = self.repository_metrics.recommended_strategy
        max_workers = self.repository_metrics.recommended_workers
        chunk_size = self.repository_metrics.chunk_size
        
        self.logger.info(f"Using {strategy.value} strategy with {max_workers} workers, chunk size {chunk_size}")
        
        if strategy == ScanStrategy.FAST_SEQUENTIAL:
            # Small repos: Sequential scanning with basic caching
            services = await self._scan_sequential_with_cache(files)
            
        elif strategy == ScanStrategy.BALANCED_PARALLEL:
            # Medium repos: Balanced parallel processing
            services = await self._scan_balanced_parallel(files, max_workers)
            
        else:  # OPTIMIZED_CHUNKS
            # Large repos: Chunked processing with aggressive caching
            services = await self._scan_chunked_with_cache(files, max_workers, chunk_size)
        
        # Update performance metrics
        self.performance_optimizer.metrics.files_processed = len(files)
        self.performance_optimizer.metrics.strategy_used = strategy
        
        return list(services.values())
    
    async def _scan_sequential_with_cache(self, files: List[str]) -> Dict[str, ServiceInfo]:
        """Sequential scanning with intelligent caching for small repositories"""
        services = {}
        cache_hits = 0
        cache_misses = 0
        
        for i, file_path in enumerate(files):
            if i % 500 == 0:
                self.logger.info(f"Sequential scan progress: {i}/{len(files)} files")
            
            # Check cache first
            file_hash = self.performance_optimizer.calculate_file_hash(file_path)
            cached_routes = self.performance_optimizer.cache.get_cached_routes(file_path, file_hash)
            
            if cached_routes:
                file_routes = cached_routes
                cache_hits += 1
            else:
                file_routes = self._scan_single_file(file_path)
                cache_misses += 1
                
                # Cache the results
                if file_routes:
                    try:
                        framework = self._detect_primary_framework(file_path)
                        file_size = os.path.getsize(file_path)
                        self.performance_optimizer.cache.cache_routes(
                            file_path, file_hash, file_routes, framework, file_size
                        )
                    except Exception:
                        # Silently continue if caching fails - the scan is more important than caching
                        pass
            
            # Process routes
            if file_routes:
                self._add_routes_to_services(services, file_path, file_routes)
        
        # Update cache metrics
        self.performance_optimizer.metrics.cache_hits = cache_hits
        self.performance_optimizer.metrics.cache_misses = cache_misses
        
        return services
    
    async def _scan_balanced_parallel(self, files: List[str], max_workers: int) -> Dict[str, ServiceInfo]:
        """Balanced parallel scanning for medium repositories"""
        services = {}
        cache_hits = 0
        cache_misses = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_file = {}
            for file_path in files:
                file_hash = self.performance_optimizer.calculate_file_hash(file_path)
                cached_routes = self.performance_optimizer.cache.get_cached_routes(file_path, file_hash)
                
                if cached_routes:
                    # Use cached result
                    if cached_routes:
                        self._add_routes_to_services(services, file_path, cached_routes)
                    cache_hits += 1
                else:
                    # Submit for processing
                    future = executor.submit(self._scan_single_file, file_path)
                    future_to_file[future] = (file_path, file_hash)
                    cache_misses += 1
            
            # Collect results
            processed = 0
            for future in as_completed(future_to_file):
                file_path, file_hash = future_to_file[future]
                try:
                    file_routes = future.result()
                    
                    if file_routes:
                        # Cache results
                        framework = self._detect_primary_framework(file_path)
                        file_size = os.path.getsize(file_path)
                        self.performance_optimizer.cache.cache_routes(
                            file_path, file_hash, file_routes, framework, file_size
                        )
                        
                        # Add to services
                        self._add_routes_to_services(services, file_path, file_routes)
                    
                    processed += 1
                    if processed % 1000 == 0:
                        self.logger.info(f"Parallel scan progress: {processed}/{len(future_to_file)} files")
                        
                except Exception as e:
                    self.logger.error(f"Error scanning {file_path}: {e}")
        
        # Update cache metrics
        self.performance_optimizer.metrics.cache_hits = cache_hits
        self.performance_optimizer.metrics.cache_misses = cache_misses
        
        return services
    
    async def _scan_chunked_with_cache(self, files: List[str], max_workers: int, 
                                      chunk_size: int) -> Dict[str, ServiceInfo]:
        """Chunked scanning with aggressive caching for large repositories"""
        services = {}
        total_cache_hits = 0
        total_cache_misses = 0
        
        # Process files in chunks to manage memory
        for chunk_start in range(0, len(files), chunk_size):
            chunk_end = min(chunk_start + chunk_size, len(files))
            file_chunk = files[chunk_start:chunk_end]
            
            self.logger.info(f"Processing chunk {chunk_start//chunk_size + 1}/{(len(files) + chunk_size - 1)//chunk_size}: files {chunk_start}-{chunk_end}")
            
            # Scan chunk
            chunk_services, cache_hits, cache_misses = await self._scan_chunk_parallel(file_chunk, max_workers)
            
            # Merge results
            for service_name, service_info in chunk_services.items():
                if service_name in services:
                    services[service_name].routes.extend(service_info.routes)
                else:
                    services[service_name] = service_info
            
            total_cache_hits += cache_hits
            total_cache_misses += cache_misses
            
            # Memory cleanup after each chunk
            import gc
            gc.collect()
        
        # Update cache metrics
        self.performance_optimizer.metrics.cache_hits = total_cache_hits
        self.performance_optimizer.metrics.cache_misses = total_cache_misses
        
        return services
    
    async def _scan_chunk_parallel(self, file_chunk: List[str], max_workers: int) -> Tuple[Dict[str, ServiceInfo], int, int]:
        """Scan a chunk of files in parallel"""
        services = {}
        cache_hits = 0
        cache_misses = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {}
            
            for file_path in file_chunk:
                file_hash = self.performance_optimizer.calculate_file_hash(file_path)
                cached_routes = self.performance_optimizer.cache.get_cached_routes(file_path, file_hash)
                
                if cached_routes:
                    if cached_routes:
                        self._add_routes_to_services(services, file_path, cached_routes)
                    cache_hits += 1
                else:
                    future = executor.submit(self._scan_single_file, file_path)
                    future_to_file[future] = (file_path, file_hash)
                    cache_misses += 1
            
            # Collect results
            for future in as_completed(future_to_file):
                file_path, file_hash = future_to_file[future]
                try:
                    file_routes = future.result()
                    
                    if file_routes:
                        # Cache results
                        framework = self._detect_primary_framework(file_path)
                        file_size = os.path.getsize(file_path)
                        self.performance_optimizer.cache.cache_routes(
                            file_path, file_hash, file_routes, framework, file_size
                        )
                        
                        # Add to services
                        self._add_routes_to_services(services, file_path, file_routes)
                        
                except Exception as e:
                    self.logger.error(f"Error scanning {file_path}: {e}")
        
        return services, cache_hits, cache_misses
    
    def _add_routes_to_services(self, services: Dict[str, ServiceInfo], file_path: str, 
                               file_routes: List[RouteInfo]):
        """Helper method to add routes to services with deduplication"""
        if file_routes:
            service_name = self._get_service_name(file_path)
            if service_name not in services:
                service_path = self._get_service_path(file_path)
                framework = self._detect_primary_framework(file_path)
                service_classification = self._classify_service_type(service_name, service_path, file_path)
                
                services[service_name] = ServiceInfo(
                    name=service_name,
                    path=service_path,
                    framework=framework,
                    routes=[],
                    service_type=service_classification['type'],
                    business_criticality=service_classification['criticality'],
                    technology_stack=service_classification['tech_stack']
                )
            
            # Add routes with global deterministic deduplication
            for route in file_routes:
                route_key = (route.method.value if hasattr(route.method, 'value') else str(route.method), route.path, route.file_path)
                if route_key not in self.global_seen_routes:
                    self.global_seen_routes.add(route_key)
                    services[service_name].routes.append(route)
    
    def _scan_single_file(self, file_path: str) -> List[RouteInfo]:
        """Scan a single file for routes."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            routes = []
            
            # Try each detector
            for detector in self.detectors:
                if detector.can_handle_file(file_path, content):
                    file_routes = detector.detect_routes(file_path, content)
                    routes.extend(file_routes)
            
            return routes
            
        except Exception as e:
            self.logger.warning(f"Could not read file {file_path}: {e}")
            return []
    
    def _get_service_name(self, file_path: str) -> str:
        """Extract service name from file path."""
        for detector in self.detectors:
            service_name = detector.extract_service_name(file_path)
            if service_name:
                return service_name
        
        # Fallback: use directory containing the file
        return Path(file_path).parent.name
    
    def _get_service_path(self, file_path: str) -> str:
        """Get service root path."""
        path_parts = Path(file_path).parts
        repo_parts = Path(self.config.repo_path).parts
        
        # Find relative path from repo root
        if len(path_parts) > len(repo_parts):
            rel_parts = path_parts[len(repo_parts):]
            # Return path up to src or apps directory
            for i, part in enumerate(rel_parts):
                if part in ['src', 'apps']:
                    return '/'.join(rel_parts[:i+1])
            
            # Fallback: return first few directories
            return '/'.join(rel_parts[:2])
        
        return str(Path(file_path).parent)
    
    def _classify_service_type(self, service_name: str, service_path: str, file_path: str) -> Dict[str, Any]:
        """Classify service based on enterprise patterns from the analysis."""
        service_lower = service_name.lower()
        path_lower = service_path.lower()
        
        # Enterprise service type patterns based on the analysis
        service_patterns = {
            'core': {
                'keywords': ['core', 'platform', 'group-core', 'common', 'shared', 'blocks'],
                'paths': ['blocks/group-core', 'platform-commons', 'core/'],
                'criticality': 'critical'
            },
            'web': {
                'keywords': ['web', 'frontend', 'ui', 'portal', 'admin-interface', 'needle', 'westeros'],
                'paths': ['web-platform/', 'frontend/', 'ui/', 'admin/'],
                'criticality': 'high'
            },
            'payment': {
                'keywords': ['payment', 'billing', 'financial', 'cashier', 'transaction', 'unified-pay', 'pay'],
                'paths': ['financial-services/', 'merchant-checkout/', 'payment/'],
                'criticality': 'critical'
            },
            'merchant': {
                'keywords': ['merchant', 'store', 'seller', 'vendor', 'sbgo', 'shopify'],
                'paths': ['merchant-applications/', 'merchant-checkout/', 'blocks/group-merchant/'],
                'criticality': 'high'
            },
            'user': {
                'keywords': ['user', 'customer', 'member', 'profile', 'coral', 'auth', 'identity'],
                'paths': ['member-service/', 'user/', 'customer/', 'auth/'],
                'criticality': 'high'
            },
            'data': {
                'keywords': ['data', 'analytics', 'reporting', 'metrics', 'search', 'orca'],
                'paths': ['blocks/search/', 'analytics/', 'reporting/'],
                'criticality': 'medium'
            },
            'integration': {
                'keywords': ['integration', 'connector', 'sync', 'webhook', 'gateway', 'proxy', 'bridge'],
                'paths': ['integration/', 'connector/', 'gateway/', 'proxy/'],
                'criticality': 'medium'
            },
            'platform': {
                'keywords': ['platform', 'infrastructure', 'commons', 'developer-portal', 'mcp'],
                'paths': ['platform-commons/', 'infrastructure/', 'commons/'],
                'criticality': 'medium'
            },
            'notification': {
                'keywords': ['notification', 'message', 'email', 'sms', 'communication'],
                'paths': ['notification/', 'messaging/', 'communication/'],
                'criticality': 'medium'
            },
            'translation': {
                'keywords': ['translation', 'language', 'locale', 'i18n', 'localization'],
                'paths': ['translation/', 'i18n/', 'locale/'],
                'criticality': 'low'
            }
        }
        
        # Determine service type
        detected_type = 'general'
        detected_criticality = 'low'
        
        for service_type, patterns in service_patterns.items():
            # Check keywords in service name
            if any(keyword in service_lower for keyword in patterns['keywords']):
                detected_type = service_type
                detected_criticality = patterns['criticality']
                break
            
            # Check path patterns
            if any(path_pattern in path_lower for path_pattern in patterns['paths']):
                detected_type = service_type
                detected_criticality = patterns['criticality']
                break
        
        # Detect technology stack
        tech_stack = self._detect_service_technology_stack(file_path, service_path)
        
        # Adjust criticality based on technology stack
        if any(tech in tech_stack for tech in ['postgresql', 'mongodb', 'redis']):
            if detected_criticality == 'low':
                detected_criticality = 'medium'
        
        if any(tech in tech_stack for tech in ['kafka', 'payment-gateway', 'external-api']):
            if detected_criticality in ['low', 'medium']:
                detected_criticality = 'high'
        
        return {
            'type': detected_type,
            'criticality': detected_criticality,
            'tech_stack': tech_stack
        }
    
    def _detect_service_technology_stack(self, file_path: str, service_path: str) -> List[str]:
        """Detect technology stack used by the service."""
        tech_stack = []
        
        # Check for package.json to detect Node.js technologies
        service_root = Path(self.config.repo_path) / service_path
        package_json_path = service_root / 'package.json'
        
        if package_json_path.exists():
            try:
                with open(package_json_path, 'r') as f:
                    package_data = json.load(f)
                    
                dependencies = {
                    **package_data.get('dependencies', {}),
                    **package_data.get('devDependencies', {})
                }
                
                # Database technologies
                if '@nestjs/typeorm' in dependencies or 'typeorm' in dependencies:
                    tech_stack.append('TypeORM')
                if 'mongoose' in dependencies:
                    tech_stack.append('MongoDB')
                if 'ioredis' in dependencies or 'redis' in dependencies:
                    tech_stack.append('Redis')
                if 'pg' in dependencies or 'postgresql' in dependencies:
                    tech_stack.append('PostgreSQL')
                
                # Messaging systems
                if 'kafkajs' in dependencies:
                    tech_stack.append('Kafka')
                if 'bull' in dependencies:
                    tech_stack.append('Bull Queue')
                if 'aws-sdk' in dependencies:
                    tech_stack.append('AWS')
                
                # External integrations
                if 'shopify' in str(dependencies).lower():
                    tech_stack.append('Shopify API')
                if 'google' in str(dependencies).lower():
                    tech_stack.append('Google APIs')
                if 'slack' in str(dependencies).lower():
                    tech_stack.append('Slack API')
                
                # gRPC and protocols
                if '@grpc/grpc-js' in dependencies or 'grpc' in dependencies:
                    tech_stack.append('gRPC')
                if 'graphql' in dependencies:
                    tech_stack.append('GraphQL')
                if 'socket.io' in dependencies:
                    tech_stack.append('WebSockets')
                
                # Documentation
                if '@nestjs/swagger' in dependencies or 'swagger' in dependencies:
                    tech_stack.append('Swagger/OpenAPI')
                    
            except Exception as e:
                self.logger.debug(f"Could not read package.json at {package_json_path}: {e}")
        
        # Check for other technology indicators
        if file_path.endswith('.proto'):
            tech_stack.append('Protocol Buffers')
        if file_path.endswith('.go'):
            tech_stack.append('Go HTTP')
        if file_path.endswith('.py'):
            tech_stack.extend(['Python', 'FastAPI/Django'])
        
        # Check for Docker
        dockerfile_path = service_root / 'Dockerfile'
        if dockerfile_path.exists():
            tech_stack.append('Docker')
        
        return list(set(tech_stack))  # Remove duplicates
    
    async def _apply_prefix_resolution(self, routes: List[RouteInfo], service_path: str, framework: Framework) -> List[RouteInfo]:
        """Apply prefix resolution to routes."""
        if not self.prefix_resolver:
            return routes
        
        try:
            # Resolve prefix for this service
            prefix_info = await self.prefix_resolver.resolve_prefix(service_path, routes[0].file_path if routes else "", framework)
            
            # Apply prefix resolution to each route
            resolved_routes = []
            for route in routes:
                # Store original path
                route.original_path = route.path
                
                # Resolve full path and breakdown
                full_path, breakdown = self.prefix_resolver.resolve_route_path(route.path, prefix_info, route.file_path)
                
                # Update route with prefix information
                route.full_path = full_path
                route.prefix_info = prefix_info
                route.prefix_breakdown = breakdown
                
                resolved_routes.append(route)
            
            return resolved_routes
            
        except Exception as e:
            self.logger.error(f"Error applying prefix resolution: {e}")
            return routes
    
    def _detect_primary_framework(self, file_path: str) -> Framework:
        """Detect primary framework for the service."""
        # Check for package.json to determine framework
        service_path = self._get_service_path(file_path)
        package_json_path = Path(self.config.repo_path) / service_path / 'package.json'
        
        if package_json_path.exists():
            try:
                with open(package_json_path, 'r') as f:
                    package_data = json.load(f)
                    
                dependencies = {
                    **package_data.get('dependencies', {}),
                    **package_data.get('devDependencies', {})
                }
                
                if '@nestjs/core' in dependencies:
                    return Framework.NESTJS
                elif 'express' in dependencies:
                    return Framework.EXPRESS
                elif 'next' in dependencies:
                    return Framework.NEXTJS
                    
            except Exception as e:
                self.logger.debug(f"Could not read package.json at {package_json_path}: {e}")
        
        # Fallback based on file extension
        if file_path.endswith('.go'):
            return Framework.GO_HTTP
        elif file_path.endswith('.py'):
            return Framework.FASTAPI
        elif file_path.endswith(('.ts', '.js')):
            return Framework.EXPRESS
        elif file_path.endswith('.proto'):
            return Framework.GRPC
        
        return Framework.UNKNOWN
    
    def _enhance_with_ai_analysis(self, services: List[ServiceInfo]) -> List[ServiceInfo]:
        """Enhance route analysis using AI."""
        if not self.ai_analyzer:
            return services
        
        for service in services:
            for route in service.routes:
                try:
                    ai_analysis = self.ai_analyzer.analyze_route(route)
                    if ai_analysis:
                        # Enhance route with AI insights
                        route.security_findings.extend(ai_analysis.security_insights)
                        # Update risk score if AI provides better assessment
                        if ai_analysis.confidence_score > 0.7:
                            route.risk_score = max(route.risk_score, ai_analysis.risk_score)
                            route.risk_level = self._get_risk_level(route.risk_score)
                            
                except Exception as e:
                    self.logger.warning(f"AI analysis failed for route {route.path}: {e}")
        
        return services
    
    def _calculate_risk_scores(self, services: List[ServiceInfo]) -> List[ServiceInfo]:
        """Calculate risk scores for all routes."""
        for service in services:
            for route in service.routes:
                risk_score, risk_factors = self.risk_scorer.calculate_risk(route)
                route.risk_score = risk_score
                route.risk_level = self._get_risk_level(risk_score)
                route.risk_factors.extend(risk_factors)
                
                if route.risk_level == RiskLevel.HIGH:
                    self.stats['high_risk_routes'] += 1
        
        return services
    
    def _get_risk_level(self, risk_score: float) -> RiskLevel:
        """Convert risk score to risk level."""
        if risk_score >= 0.7:
            return RiskLevel.HIGH
        elif risk_score >= 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _generate_scan_result(self, services: List[ServiceInfo]) -> ScanResult:
        """Generate final scan result."""
        all_routes = []
        for service in services:
            all_routes.extend(service.routes)
        
        # Calculate statistics
        routes_by_framework = {}
        routes_by_method = {}
        routes_by_risk = {}
        
        for route in all_routes:
            # Framework stats
            framework = route.framework.value if hasattr(route.framework, 'value') else str(route.framework)
            routes_by_framework[framework] = routes_by_framework.get(framework, 0) + 1
            
                        # Method stats
            method = route.method.value if hasattr(route.method, 'value') else str(route.method)
            routes_by_method[method] = routes_by_method.get(method, 0) + 1
            
            # Risk stats
            risk = route.risk_level.value if hasattr(route.risk_level, 'value') else str(route.risk_level)
            routes_by_risk[risk] = routes_by_risk.get(risk, 0) + 1
        
        # Organization-specific insights
        organization_services = []
        internal_services = []
        business_services = []
        
        for service in services:
            service_name_lower = service.name.lower()
            service_path_lower = service.path.lower()
            
            # Categorize organization services
            if any(pattern in service_name_lower for pattern in ['user', 'auth', 'payment', 'admin']):
                organization_services.append(service.name)
            elif any(pattern in service_path_lower for pattern in ['internal', 'core', 'common']):
                internal_services.append(service.name)
            elif any(pattern in service_path_lower for pattern in ['api', 'service']):
                business_services.append(service.name)
        
        scan_duration = self.stats['scan_end_time'] - self.stats['scan_start_time']
        
        return ScanResult(
            routes=all_routes,  # Add the routes to the result
            scan_id=str(uuid.uuid4()),
            repository_path=self.config.repo_path,
            services=services,
            total_routes=len(all_routes),
            routes_by_framework=routes_by_framework,
            routes_by_method=routes_by_method,
            routes_by_risk=routes_by_risk,
            high_risk_routes=routes_by_risk.get('HIGH', 0),
            medium_risk_routes=routes_by_risk.get('MEDIUM', 0),
            low_risk_routes=routes_by_risk.get('LOW', 0),
            unauthenticated_routes=len([r for r in all_routes if not r.auth_required]),
            organization_services=organization_services,
            internal_services=internal_services,
            business_services=business_services,
            scan_duration_seconds=scan_duration,
            files_analyzed=self.stats['files_scanned']
        )
    
    async def scan_prefixes_only(self):
        """Scan repository for prefix information only."""
        if not self.prefix_resolver:
            console.print("[red]Prefix resolution is not enabled. Use --resolve-prefixes flag.[/red]")
            return
        
        console.print(Panel(
            "[bold blue]🔍 RouteHawk Prefix Discovery Mode[/bold blue]\n"
            "[cyan]Discovering prefix patterns across services...[/cyan]"
        ))
        
        with console.status("[bold blue]Analyzing service prefixes...") as status:
            # Discover all relevant files
            files_to_scan = self._discover_files()
            
            # Group files by service
            services_prefixes = {}
            
            for file_path in files_to_scan:
                service_name = self._get_service_name(file_path)
                service_path = self._get_service_path(file_path)
                framework = self._detect_primary_framework(file_path)
                
                if service_name not in services_prefixes:
                    try:
                        prefix_info = await self.prefix_resolver.resolve_prefix(service_path, file_path, framework)
                        services_prefixes[service_name] = {
                            'service_path': service_path,
                            'framework': framework.value if hasattr(framework, 'value') else str(framework),
                            'prefix_info': prefix_info,
                            'files_analyzed': []
                        }
                    except Exception as e:
                        self.logger.error(f"Error resolving prefix for {service_name}: {e}")
                        continue
                
                services_prefixes[service_name]['files_analyzed'].append(file_path)
        
        # Display results
        self._display_prefix_results(services_prefixes)
    
    def _display_prefix_results(self, prefix_summary: Dict[str, Any]):
        """Display prefix resolution results in a formatted table"""
        console.print(f"\n[bold green]✅ Prefix Discovery Complete![/bold green]")
        
        if prefix_summary.get('services_with_prefixes', 0) > 0:
            console.print(f"\n[cyan]📊 Services with prefixes: {prefix_summary['services_with_prefixes']}[/cyan]")
            console.print(f"[cyan]🔗 Unique prefixes found: {len(prefix_summary.get('unique_prefixes', []))}[/cyan]")
            console.print(f"[cyan]⚠️  Conflicts detected: {prefix_summary.get('conflict_count', 0)}[/cyan]")
            console.print(f"[cyan]📈 Average confidence: {prefix_summary.get('average_confidence', 0):.2f}[/cyan]")
            
            if prefix_summary.get('unique_prefixes'):
                console.print(f"\n[bold]🔗 Discovered Prefixes:[/bold]")
                for prefix in prefix_summary['unique_prefixes']:
                    console.print(f"  • {prefix}")
        else:
            console.print("[yellow]No prefixes found in the scanned repository.[/yellow]")

    def _display_terminal_output(self, scan_result):
        """Display scan results in a clean terminal format with method, path, and file"""
        from rich.table import Table
        
        # Small RouteHawk logo for results
        console.print(f"\n[bold red]🦅 RouteHawk Security Results 🦅[/bold red]")
        console.print(f"[cyan]📊 Total Routes: {scan_result.total_routes}[/cyan]")
        console.print(f"[cyan]🚨 High Risk: {scan_result.high_risk_routes}[/cyan]")
        console.print(f"[cyan]🏢 Services: {len(scan_result.services)}[/cyan]\n")
        
        # Create table
        table = Table(show_header=True, header_style="bold magenta", show_lines=True)
        table.add_column("Method", style="cyan", min_width=8)
        table.add_column("Route", style="green", min_width=40)
        table.add_column("File", style="yellow", min_width=30)
        table.add_column("Risk", style="red", min_width=8)
        
        # Add routes to table
        route_count = 0
        max_routes = 100  # Limit for terminal display
        
        # Handle both dictionary and list formats for services
        if hasattr(scan_result.services, 'items'):
            # Dictionary format: {service_name: service_info}
            services_iter = scan_result.services.items()
        else:
            # List format: [service_info, service_info, ...]
            services_iter = [(service.name if hasattr(service, 'name') else f"service_{i}", service) 
                           for i, service in enumerate(scan_result.services)]
        
        for service_name, service in services_iter:
            for route in service.routes:
                if route_count >= max_routes:
                    break
                
                # Use resolved path if available, otherwise original path
                display_path = route.full_path or route.path
                
                # Truncate long paths for terminal display
                if len(display_path) > 60:
                    display_path = display_path[:57] + "..."
                
                # Truncate file path
                file_display = route.file_path
                if len(file_display) > 50:
                    file_display = "..." + file_display[-47:]
                
                # Color code risk levels
                risk_level_str = route.risk_level.value if hasattr(route.risk_level, 'value') else str(route.risk_level)
                method_str = route.method.value if hasattr(route.method, 'value') else str(route.method)
                risk_style = {
                    "CRITICAL": "bold red",
                    "HIGH": "red", 
                    "MEDIUM": "yellow",
                    "LOW": "green"
                }.get(risk_level_str.upper(), "white")
                
                table.add_row(
                    method_str,
                    display_path,
                    file_display,
                    f"[{risk_style}]{risk_level_str.upper()}[/{risk_style}]"
                )
                route_count += 1
            
            if route_count >= max_routes:
                break
        
        console.print(table)
        
        if scan_result.total_routes > max_routes:
            console.print(f"\n[yellow]📝 Showing first {max_routes} routes. Total: {scan_result.total_routes}[/yellow]")
            console.print(f"[yellow]💾 Use --output-format csv or json to export all routes.[/yellow]")
    
    def _log_scan_summary(self, scan_result: ScanResult):
        """Log scan summary to console."""
        self.console.print("\n" + "="*60)
        self.console.print("[bold green]Attack Surface Scan Complete![/bold green]")
        self.console.print("="*60)
        
        # Create summary table
        table = Table(title="Scan Summary")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")
        
        table.add_row("Total Routes", str(scan_result.total_routes))
        table.add_row("High Risk Routes", str(scan_result.high_risk_routes))
        table.add_row("Medium Risk Routes", str(scan_result.medium_risk_routes))
        table.add_row("Low Risk Routes", str(scan_result.low_risk_routes))
        table.add_row("Unauthenticated Routes", str(scan_result.unauthenticated_routes))
        table.add_row("Services Found", str(len(scan_result.services)))
        table.add_row("Files Analyzed", str(scan_result.files_analyzed))
        table.add_row("Scan Duration", f"{scan_result.scan_duration_seconds:.2f}s")
        
        self.console.print(table)
        
        # Show risk distribution
        if scan_result.high_risk_routes > 0:
            self.console.print(f"\n[bold red]⚠️  Found {scan_result.high_risk_routes} high-risk routes![/bold red]")
        
        self.console.print(f"\n[bold blue]📊 Framework Distribution:[/bold blue]")
        for framework, count in scan_result.routes_by_framework.items():
            self.console.print(f"  • {framework}: {count} routes")
    
    def export_results(self, scan_result: ScanResult):
        """Export scan results in configured formats."""
        output_dir = Path(self.config.output_directory)
        output_dir.mkdir(exist_ok=True)
        
        # Extract repository name for unique filenames
        repo_name = self._extract_repo_name(self.config.repo_path)
        
        for format_type, exporter in self.exporters.items():
            try:
                output_file = output_dir / f"routehawk_report_{repo_name}.{format_type}"
                exporter.export(scan_result, str(output_file))
                self.console.print(f"[green]✓[/green] Exported {format_type.upper()} report: {output_file}")
            except Exception as e:
                self.logger.error(f"Failed to export {format_type} report: {e}")

    def _extract_repo_name(self, repo_path: str) -> str:
        """Extract and sanitize repository name from path for use in filenames."""
        import re
        
        # Get the last directory name from the path
        repo_name = Path(repo_path).name
        
        # If it's empty (root path), use parent directory
        if not repo_name or repo_name == '/':
            repo_name = Path(repo_path).parent.name
        
        # Sanitize for filename usage
        # Replace spaces, special characters with hyphens
        repo_name = re.sub(r'[^\w\-_.]', '-', repo_name)
        # Remove multiple consecutive hyphens
        repo_name = re.sub(r'-+', '-', repo_name)
        # Remove leading/trailing hyphens
        repo_name = repo_name.strip('-')
        
        # Fallback if sanitization results in empty string
        if not repo_name:
            repo_name = 'unknown-repo'
            
        return repo_name

    def _display_performance_report(self, performance_report: Dict[str, Any]):
        """Display performance optimization report"""
        console.print("\n" + "="*60)
        console.print("[bold green]📊 Performance Optimization Report[/bold green]")
        console.print("="*60)
        
        # Scan performance
        duration = performance_report['scan_duration_seconds']
        files_per_sec = performance_report['processing_rate_files_per_second']
        
        console.print(f"[cyan]Scan Performance:[/cyan]")
        console.print(f"  • Duration: {duration:.2f}s")
        console.print(f"  • Files processed: {performance_report['files_processed']:,}")
        console.print(f"  • Processing rate: {files_per_sec:.1f} files/sec")
        
        # Cache performance
        cache_perf = performance_report['cache_performance']
        console.print(f"\n[cyan]Cache Performance:[/cyan]")
        console.print(f"  • Hit rate: {cache_perf['hit_rate_percent']:.1f}%")
        console.print(f"  • Cache hits: {cache_perf['cache_hits']:,}")
        console.print(f"  • Cache misses: {cache_perf['cache_misses']:,}")
        console.print(f"  • Cache entries: {cache_perf.get('total_entries', 0):,}")
        
        # System performance
        sys_perf = performance_report['system_performance']
        console.print(f"\n[cyan]System Performance:[/cyan]")
        console.print(f"  • Peak memory: {sys_perf['peak_memory_mb']:.1f} MB")
        console.print(f"  • CPU usage: {sys_perf['cpu_usage_percent']:.1f}%")
        console.print(f"  • Strategy used: {sys_perf['strategy_used']}")
        
        # Performance targets
        targets = performance_report['performance_targets']
        target_status = "✅ MET" if targets['target_met'] else "⚠️ MISSED"
        console.print(f"\n[cyan]Performance Target:[/cyan] {target_status}")
        
        if not targets['target_met']:
            files = performance_report['files_processed']
            if files < 1000:
                console.print(f"  • Target: < 30s, Actual: {duration:.1f}s")
            elif files < 10000:
                console.print(f"  • Target: < 2min, Actual: {duration:.1f}s")
            else:
                console.print(f"  • Target: < 10min, Actual: {duration:.1f}s")

    async def _scan_files(self, files: List[str]) -> List[ServiceInfo]:
        """
        Original scan files method for backward compatibility.
        Routes to adaptive scanning if performance optimizer is available.
        """
        if hasattr(self, 'performance_optimizer') and self.repository_metrics:
            # Use adaptive scanning (Phase 4)
            return await self._scan_files_adaptive(files)
        else:
            # Fallback to original method
            return await self._scan_files_original(files)
    
    async def _scan_files_original(self, files: List[str]) -> List[ServiceInfo]:
        """Original scanning method for backward compatibility"""
        services = {}
        
        # Use thread pool for parallel processing
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_file = {
                executor.submit(self._scan_single_file, file_path): file_path 
                for file_path in files
            }
            
            # Collect all results first, then process deterministically
            file_results = {}
            processed = 0
            
            # Wait for all futures to complete and collect results
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    file_routes = future.result()
                    file_results[file_path] = file_routes
                    
                    processed += 1
                    
                    # Log progress every 1000 files
                    if processed % 1000 == 0:
                        self.logger.info(f"Processed {processed}/{len(files)} files, collected results")
                    
                except Exception as e:
                    self.logger.error(f"Error scanning {file_path}: {e}")
                    file_results[file_path] = []
                    processed += 1
            
            # Now process results in deterministic order (sorted by file path)
            processed_routes = 0
            for file_path in sorted(file_results.keys()):
                file_routes = file_results[file_path]
                
                if file_routes:
                    service_name = self._get_service_name(file_path)
                    if service_name not in services:
                        service_path = self._get_service_path(file_path)
                        framework = self._detect_primary_framework(file_path)
                        service_classification = self._classify_service_type(service_name, service_path, file_path)
                        
                        services[service_name] = ServiceInfo(
                            name=service_name,
                            path=service_path,
                            framework=framework,
                            routes=[],
                            service_type=service_classification['type'],
                            business_criticality=service_classification['criticality'],
                            technology_stack=service_classification['tech_stack']
                        )
                    
                    # Apply prefix resolution if enabled
                    if self.prefix_resolver:
                        service_path = self._get_service_path(file_path)
                        framework = self._detect_primary_framework(file_path)
                        file_routes = await self._apply_prefix_resolution(file_routes, service_path, framework)
                    
                    # Add routes with global deterministic deduplication
                    for route in file_routes:
                        route_key = (route.method.value if hasattr(route.method, 'value') else str(route.method), route.path, route.file_path)
                        # Check if route already exists globally
                        if route_key not in self.global_seen_routes:
                            self.global_seen_routes.add(route_key)
                            services[service_name].routes.append(route)
                            processed_routes += 1
                        else:
                            self.logger.debug(f"Duplicate route detected: {route_key}")
                
                self.stats['files_scanned'] += 1
            
            self.stats['routes_found'] = processed_routes
            
            # Log final processing summary
            if processed_routes > 0:
                self.logger.info(f"Processed {len(files)} files, found {processed_routes} unique routes across {len(services)} services")
        
        self.stats['services_found'] = len(services)
        return list(services.values())

def auto_detect_frameworks(repo_path: str) -> List[Framework]:
    """
    Automatically detect frameworks used in the repository.
    """
    frameworks = set()
    repo_path = Path(repo_path)
    
    # Check for common framework indicators
    framework_indicators = {
        # Node.js/JavaScript frameworks
        'package.json': ['nestjs', 'express', 'next'],
        'tsconfig.json': ['nestjs'],
        'nest-cli.json': ['nestjs'],
        
        # Python frameworks
        'requirements.txt': ['fastapi', 'django', 'flask'],
        'pyproject.toml': ['fastapi', 'django', 'flask'],
        'setup.py': ['fastapi', 'django', 'flask'],
        'Pipfile': ['fastapi', 'django', 'flask'],
        'manage.py': ['django'],
        
        # Go frameworks
        'go.mod': ['gin', 'gorilla', 'http'],
        'go.sum': ['gin', 'gorilla', 'http'],
        
        # Java frameworks
        'pom.xml': ['spring'],
        'build.gradle': ['spring'],
    }
    
    # Check files for framework indicators
    for file_pattern, framework_keywords in framework_indicators.items():
        for file_path in repo_path.rglob(file_pattern):
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore').lower()
                
                if file_pattern == 'package.json':
                    # Parse package.json specifically
                    try:
                        package_data = json.loads(file_path.read_text())
                        dependencies = {**package_data.get('dependencies', {}), 
                                      **package_data.get('devDependencies', {})}
                        
                        if any(dep.startswith('@nestjs') for dep in dependencies):
                            frameworks.add(Framework.NESTJS)
                        if 'express' in dependencies:
                            frameworks.add(Framework.EXPRESS)
                        if 'next' in dependencies or 'nextjs' in dependencies:
                            frameworks.add(Framework.NEXTJS)
                    except json.JSONDecodeError:
                        pass
                
                elif 'django' in content:
                    frameworks.add(Framework.DJANGO)
                elif 'fastapi' in content:
                    frameworks.add(Framework.FASTAPI)
                elif 'flask' in content:
                    frameworks.add(Framework.FLASK)
                elif 'gin-gonic' in content or 'gin' in content:
                    frameworks.add(Framework.GIN)
                elif 'gorilla/mux' in content:
                    frameworks.add(Framework.GORILLA_MUX)
                elif 'net/http' in content or 'http.Handle' in content:
                    frameworks.add(Framework.GO_HTTP)
                elif 'spring-boot' in content or 'springframework' in content:
                    frameworks.add(Framework.SPRING_BOOT)
                    
            except Exception:
                continue
    
    # Check for specific file patterns that indicate frameworks
    
    # Express.js - look for app.get, app.post, etc.
    for js_file in repo_path.rglob("*.js"):
        try:
            content = js_file.read_text(encoding='utf-8', errors='ignore')
            if ('app.get(' in content or 'app.post(' in content or 
                'router.get(' in content or 'router.post(' in content):
                frameworks.add(Framework.EXPRESS)
                break
        except Exception:
            continue
    
    # NestJS - look for @Controller, @Get decorators
    for ts_file in repo_path.rglob("*.ts"):
        try:
            content = ts_file.read_text(encoding='utf-8', errors='ignore')
            if ('@Controller' in content or '@Get(' in content or '@Post(' in content):
                frameworks.add(Framework.NESTJS)
                break
        except Exception:
            continue
    
    # FastAPI - look for @app.get, FastAPI() patterns
    for py_file in repo_path.rglob("*.py"):
        try:
            content = py_file.read_text(encoding='utf-8', errors='ignore')
            if ('FastAPI()' in content or '@app.get(' in content or 
                'from fastapi import' in content):
                frameworks.add(Framework.FASTAPI)
                break
            elif ('from django' in content or 'django.urls' in content):
                frameworks.add(Framework.DJANGO)
                break
            elif ('from flask import' in content or 'Flask(__name__)' in content):
                frameworks.add(Framework.FLASK)
                break
        except Exception:
            continue
    
    # Go HTTP - look for http.HandleFunc patterns
    for go_file in repo_path.rglob("*.go"):
        try:
            content = go_file.read_text(encoding='utf-8', errors='ignore')
            if ('http.HandleFunc' in content or 'http.Handle(' in content):
                frameworks.add(Framework.GO_HTTP)
                break
            elif 'gin.Default()' in content or 'gin.New()' in content:
                frameworks.add(Framework.GIN)
                break
            elif 'mux.NewRouter()' in content:
                frameworks.add(Framework.GORILLA_MUX)
                break
        except Exception:
            continue
    
    # If no frameworks detected, return common ones for broad scanning
    if not frameworks:
        return [Framework.EXPRESS, Framework.NESTJS, Framework.FASTAPI, Framework.GO_HTTP]
    
    return list(frameworks)

async def _run_async_scan(config: ScanConfig, prefixes_only: bool, verbose: bool, output_format: str):
    # Handle prefixes-only mode
    if prefixes_only:
        scanner = AttackSurfaceScanner(config)
        await scanner.scan_prefixes_only()
        return
    
    # Handle auto-detection of frameworks
    if not config.frameworks:  # Auto-detect mode
        console.print("[yellow]🔍 Auto-detecting frameworks...[/yellow]")
        auto_detected = auto_detect_frameworks(config.repo_path)
        config.frameworks = auto_detected if auto_detected else [Framework.EXPRESS]  # Default fallback
        console.print(f"[green]✓[/green] Detected frameworks: {', '.join([f.value if hasattr(f, 'value') else str(f) for f in config.frameworks])}")

    # Full scan mode
    scanner = AttackSurfaceScanner(config)
    scan_result = await scanner.scan_repository()
    
    # Handle terminal output format
    if output_format == 'terminal':
        scanner._display_terminal_output(scan_result)
    else:
        scanner.export_results(scan_result)
    
    # Exit with appropriate code
    if scan_result.high_risk_routes > 0:
        console.print(f"\n[bold red]⚠️  {scan_result.high_risk_routes} high-risk routes found![/bold red]")
        console.print("[yellow]Review the generated reports for security recommendations.[/yellow]")
        sys.exit(1)
    else:
        console.print(f"\n[bold green]✅ Scan completed successfully![/bold green]")
        console.print(f"[cyan]Found {scan_result.total_routes} routes across {len(scan_result.services)} services.[/cyan]")

async def _run_directory_comparison(config: ScanConfig, comparison_config: ComparisonConfig, output_format: str, verbose: bool):
    """
    Run a directory comparison between two directories.
    """
    try:
        console.print(f"\n[cyan]Starting directory comparison...[/cyan]")
        
        # Create scanner instance for directory comparison
        scanner = AttackSurfaceScanner(config)
        
        # Create directory comparator
        comparator = DirectoryComparator(scanner)
        
        # Run the comparison
        with console.status("[spinner]Comparing directories..."):
            comparison_result = comparator.compare_directories(
                comparison_config.source,
                comparison_config.target,
                comparison_config
            )
        
        # Display results
        _display_comparison_results(comparison_result, console)
        
        # Export results
        if output_format != 'terminal':
            await _export_comparison_results(comparison_result, config.output_directory, output_format)
        
    except Exception as e:
        console.print(f"[bold red]Error during directory comparison: {e}[/bold red]")
        if verbose:
            console.print_exception()
        raise

def _parse_filter_string(filter_str: str, console) -> ComparisonFilter:
    """
    Parse filter string into ComparisonFilter object.
    
    Format: "framework=express,nestjs;method=POST,PUT;path=/api/*"
    """
    filters = ComparisonFilter()
    
    try:
        # Split by semicolon for different filter types
        filter_parts = filter_str.split(';')
        
        for part in filter_parts:
            if '=' not in part:
                continue
                
            key, value = part.split('=', 1)
            key = key.strip().lower()
            values = [v.strip() for v in value.split(',')]
            
            if key == 'framework':
                framework_map = {
                    'express': Framework.EXPRESS,
                    'nestjs': Framework.NESTJS,
                    'nextjs': Framework.NEXTJS,
                    'go': Framework.GO_HTTP,
                    'fastapi': Framework.FASTAPI,
                    'flask': Framework.FLASK,
                    'django': Framework.DJANGO,
                    'spring': Framework.SPRING_BOOT,
                    'grpc': Framework.GRPC
                }
                filters.frameworks = [framework_map[v] for v in values if v in framework_map]
                
            elif key == 'method':
                from models import HTTPMethod
                method_map = {
                    'get': HTTPMethod.GET,
                    'post': HTTPMethod.POST,
                    'put': HTTPMethod.PUT,
                    'delete': HTTPMethod.DELETE,
                    'patch': HTTPMethod.PATCH,
                    'options': HTTPMethod.OPTIONS,
                    'head': HTTPMethod.HEAD,
                    'all': HTTPMethod.ALL
                }
                filters.methods = [method_map[v.lower()] for v in values if v.lower() in method_map]
                
            elif key == 'path':
                filters.paths = values
                
            elif key == 'file_path':
                filters.file_paths = values
                
            elif key == 'original_path':
                filters.original_paths = values
                
    except Exception as e:
        console.print(f"[yellow]Warning: Error parsing filter string '{filter_str}': {e}[/yellow]")
    
    return filters

def _display_comparison_results(result: ComparisonResult, console):
    """Display comparison results in terminal."""
    
    stats = result.get_summary_stats()
    
    # Main summary
    console.print(Panel(
        f"[bold green]Directory Comparison Summary[/bold green]\n"
        f"[cyan]Source:[/cyan] {result.source_version}\n"
        f"[cyan]Target:[/cyan] {result.target_version}\n"
        f"[cyan]Comparison Type:[/cyan] {result.comparison_type}\n"
        f"[cyan]Total Changes:[/cyan] {stats['total_route_changes']}"
    ))
    
    # Route changes breakdown
    if stats['total_route_changes'] > 0:
        table = Table(title="Route Changes")
        table.add_column("Change Type", style="cyan")
        table.add_column("Count", justify="right", style="green")
        
        for change_type, count in stats['route_changes'].items():
            if count > 0:
                table.add_row(change_type.title(), str(count))
        
        console.print(table)
        
        # Show detailed route listings for each change type
        _display_detailed_route_changes(result.changes, console)
        
        # Show high-risk changes summary
        high_risk_changes = [c for c in result.changes if c.risk_impact == RiskLevel.HIGH]
        if high_risk_changes:
            console.print(f"\n[bold red]⚠️  {len(high_risk_changes)} HIGH RISK changes detected![/bold red]")
            for change in high_risk_changes[:5]:  # Show first 5
                route = change.new_route or change.old_route
                # Safe string conversion for method and risk_level
                method_str = str(route.method)
                console.print(f"  [red]• {change.change_type}[/red] {method_str} {route.path}")
            if len(high_risk_changes) > 5:
                console.print(f"  [dim]... and {len(high_risk_changes) - 5} more[/dim]")
    
    # File changes breakdown
    if stats['total_file_changes'] > 0:
        file_table = Table(title="File Changes")
        file_table.add_column("Change Type", style="cyan")
        file_table.add_column("Count", justify="right", style="green")
        
        for change_type, count in stats['file_changes'].items():
            if count > 0:
                file_table.add_row(change_type.title(), str(count))
        
        console.print(file_table)
    
    # Errors
    if result.errors:
        console.print(f"\n[bold red]Errors encountered:[/bold red]")
        for error in result.errors:
            console.print(f"  [red]• {error}[/red]")

async def _export_comparison_results(result: ComparisonResult, output_dir: str, output_format: str):
    """Export comparison results to files."""
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"directory_comparison_{timestamp}.{output_format}"
    file_path = output_path / filename
    
    try:
        if output_format == 'json':
            import json
            data = {
                'comparison_summary': result.get_summary_stats(),
                'changes': [
                    {
                        'change_type': change.change_type,
                        'risk_impact': change.risk_impact.value,
                        'route_signature': change.get_route_signature(),
                        'change_details': change.change_details,
                        'old_route': change.old_route.__dict__ if change.old_route else None,
                        'new_route': change.new_route.__dict__ if change.new_route else None
                    }
                    for change in result.changes
                ],
                'file_changes': [
                    {
                        'file_path': fc.file_path,
                        'change_type': fc.change_type,
                        'size_change': fc.size_change
                    }
                    for fc in result.file_changes
                ]
            }
            
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
                
        elif output_format == 'csv':
            import csv
            with open(file_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Change Type', 'Risk Impact', 'Method', 'Path', 'File Path', 'Details'])
                
                for change in result.changes:
                    route = change.new_route or change.old_route
                    method = str(route.method) if route else 'N/A'
                    path = route.path if route else 'N/A'
                    file_path_str = route.file_path if route else 'N/A'
                    details = str(change.change_details) if change.change_details else ''
                    
                    writer.writerow([
                        change.change_type,
                        str(change.risk_impact),
                        method,
                        path,
                        file_path_str,
                        details
                    ])
        
        console.print(f"[green]✓[/green] Comparison report exported: {file_path}")
        
    except Exception as e:
        console.print(f"[red]Error exporting results: {e}[/red]")

def _display_batch_results(batch_result: BatchComparisonResult, console):
    """Display results from a batch comparison operation"""
    console.print("\n╭─────────────────────────────────────────────────────────────╮")
    console.print("│ 🌐 Remote Repository Batch Analysis Summary                │")
    console.print("╰─────────────────────────────────────────────────────────────╯")
    
    # Summary statistics
    total_comparisons = len(batch_result.comparisons)
    total_changes = sum(len(comp.changes) for comp in batch_result.comparisons)
    
    console.print(f"[cyan]Total Comparisons:[/cyan] {total_comparisons}")
    console.print(f"[cyan]Total Route Changes:[/cyan] {total_changes}")
    
    if batch_result.errors:
        console.print(f"[red]Errors:[/red] {len(batch_result.errors)}")
        for error in batch_result.errors[:3]:  # Show first 3 errors
            console.print(f"  [red]•[/red] {error}")
    
    # Display individual comparisons
    if batch_result.comparisons:
        console.print("\n[bold]Individual Comparisons:[/bold]")
        for i, comp in enumerate(batch_result.comparisons[:5]):  # Show first 5
            changes_count = len(comp.changes)
            console.print(f"  {i+1}. {changes_count} route changes")
    
    # Performance metrics
    if batch_result.performance_metrics:
        duration = batch_result.performance_metrics.get('total_duration', 0)
        console.print(f"\n[cyan]Analysis Duration:[/cyan] {duration:.2f}s")

def _display_batch_job_results(batch_result: BatchJobResult, console):
    """Display results from a batch job execution"""
    console.print("\n╭─────────────────────────────────────────────────────────────╮")
    console.print("│ 📦 Batch Repository Analysis Results                       │")
    console.print("╰─────────────────────────────────────────────────────────────╯")
    
    # Job status
    status_color = "green" if batch_result.status == "success" else "yellow" if batch_result.status == "partial" else "red"
    console.print(f"[cyan]Job ID:[/cyan] {batch_result.job_id}")
    console.print(f"[cyan]Status:[/cyan] [{status_color}]{batch_result.status.upper()}[/{status_color}]")
    console.print(f"[cyan]Job Type:[/cyan] {batch_result.job_type}")
    
    # Repository statistics
    console.print(f"\n[bold]Repository Statistics:[/bold]")
    console.print(f"[cyan]Processed Successfully:[/cyan] {batch_result.repositories_processed}")
    console.print(f"[cyan]Failed:[/cyan] {batch_result.repositories_failed}")
    console.print(f"[cyan]Total Comparisons:[/cyan] {batch_result.total_comparisons}")
    
    # Route changes
    console.print(f"\n[bold]Route Changes:[/bold]")
    console.print(f"[cyan]Total Changes:[/cyan] {batch_result.total_route_changes}")
    console.print(f"[cyan]High Risk Changes:[/cyan] {batch_result.high_risk_changes}")
    
    # Timing information
    if batch_result.started_at and batch_result.completed_at:
        duration = (batch_result.completed_at - batch_result.started_at).total_seconds()
        console.print(f"\n[cyan]Duration:[/cyan] {duration:.2f}s")
    
    # Errors
    if batch_result.errors:
        console.print(f"\n[red]Errors ({len(batch_result.errors)}):[/red]")
        for error in batch_result.errors[:3]:  # Show first 3 errors
            console.print(f"  [red]•[/red] {error}")

def _display_enterprise_report(report_data: Dict[str, Any], console):
    """Display enterprise-grade report summary"""
    console.print("\n╭─────────────────────────────────────────────────────────────╮")
    console.print("│ 🏢 Enterprise Security Report                              │")
    console.print("╰─────────────────────────────────────────────────────────────╯")
    
    # Executive summary
    exec_summary = report_data.get('executive_summary', {})
    console.print(f"\n[bold]Executive Summary:[/bold]")
    console.print(f"[cyan]Repositories Analyzed:[/cyan] {exec_summary.get('repositories_analyzed', 0)}")
    console.print(f"[cyan]Total Comparisons:[/cyan] {exec_summary.get('total_comparisons', 0)}")
    console.print(f"[cyan]Total Route Changes:[/cyan] {exec_summary.get('total_route_changes', 0)}")
    console.print(f"[cyan]High Risk Changes:[/cyan] {exec_summary.get('high_risk_changes', 0)}")
    
    # Security score
    security_score = exec_summary.get('security_score', 0)
    score_color = "green" if security_score >= 80 else "yellow" if security_score >= 60 else "red"
    console.print(f"[cyan]Security Score:[/cyan] [{score_color}]{security_score}/100[/{score_color}]")
    
    # Key findings
    key_findings = exec_summary.get('key_findings', [])
    if key_findings:
        console.print(f"\n[bold]Key Findings:[/bold]")
        for finding in key_findings[:3]:  # Show first 3 findings
            console.print(f"  [yellow]•[/yellow] {finding}")
    
    # Risk analysis
    risk_analysis = report_data.get('risk_analysis', {})
    risk_dist = risk_analysis.get('risk_distribution', {}).get('percentages', {})
    if risk_dist:
        console.print(f"\n[bold]Risk Distribution:[/bold]")
        for risk_level, percentage in risk_dist.items():
            color = "red" if risk_level == "HIGH" else "yellow" if risk_level == "MEDIUM" else "green"
            console.print(f"  [{color}]{risk_level}:[/{color}] {percentage:.1f}%")

async def _run_git_comparison(config: ScanConfig, comparison_config: ComparisonConfig, comparison_type: str, output_format: str, verbose: bool):
    """
    Run a git comparison between two git references (tags or branches).
    """
    try:
        console.print(f"\n[cyan]Starting {comparison_type} comparison...[/cyan]")
        
        # Create scanner instance for git comparison
        scanner = AttackSurfaceScanner(config)
        
        # Create route comparator (uses git operations)
        route_comparator = RouteComparator(scanner)
        
        # Run the appropriate comparison based on type
        with console.status(f"[spinner]Comparing {comparison_type}..."):
            if comparison_type == "tags":
                comparison_result = route_comparator.compare_tags(
                    config.repo_path,
                    comparison_config.source,
                    comparison_config.target,
                    comparison_config
                )
            elif comparison_type == "branches":
                comparison_result = route_comparator.compare_branches(
                    config.repo_path,
                    comparison_config.source,
                    comparison_config.target,
                    comparison_config
                )
            elif comparison_type == "against_tag":
                comparison_result = route_comparator.compare_against_tag(
                    config.repo_path,
                    comparison_config.source,
                    comparison_config
                )
            else:
                raise ValueError(f"Unknown comparison type: {comparison_type}")
        
        # Display results
        _display_comparison_results(comparison_result, console)
        
        # Export results
        if output_format != 'terminal':
            await _export_comparison_results(comparison_result, config.output_directory, output_format)
        
    except Exception as e:
        console.print(f"[bold red]Error during {comparison_type} comparison: {e}[/bold red]")
        if verbose:
            console.print_exception()
        raise

@click.command()
@click.option('--repo-path', help='Path to repository to scan')
@click.option('--output-dir', default='./reports', 
              help='Directory to save output files (not used for terminal format)')
@click.option('--frameworks', default='auto', help='Frameworks to scan (nestjs,express,go,python,grpc,all,auto)')
@click.option('--risk-threshold', type=click.Choice(['low', 'medium', 'high']), 
              default='medium', help='Minimum risk level to report')
@click.option('--use-ai/--no-ai', default=True, help='Use AI analysis')
@click.option('--organization-patterns/--no-organization-patterns', default=True, 
              help='Use organization-specific patterns')
@click.option('--resolve-prefixes/--no-resolve-prefixes', default=False, 
              help='Enable comprehensive prefix resolution')
@click.option('--prefix-config', help='Path to custom prefix configuration file')
@click.option('--prefixes-only', is_flag=True, help='Output detected prefixes only (no full scan)')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output')
# Directory comparison options (Phase 1)
@click.option('--compare-dir', help='Compare against another directory (local directory comparison)')
@click.option('--include-file-changes/--no-file-changes', default=True, 
              help='Include file-level changes in comparison results')
@click.option('--filter-by', help='Filter comparison results (e.g., "framework=express;method=POST,PUT")')
@click.option('--diff-algorithm', type=click.Choice(['strict', 'fuzzy', 'hybrid']), 
              default='hybrid', help='Algorithm for detecting route differences')

# Git comparison options (Phase 2)
@click.option('--compare-tags', help='Compare two git tags (e.g., "v1.0.0,v2.0.0")')
@click.option('--compare-against-tag', help='Compare current state against a git tag (e.g., "v1.0.0")')
@click.option('--compare-branches', help='Compare two git branches (e.g., "main,develop")')
@click.option('--auth-method', type=click.Choice(['auto', 'ssh', 'token', 'oauth', 'none']),
              default='auto', help='Authentication method for git operations')
@click.option('--git-token', help='Git access token for private repositories')
@click.option('--ssh-key', help='Path to SSH private key for git authentication')
@click.option('--git-username', help='Git username for token authentication')

# Remote repository options (Phase 3)
@click.option('--remote-repo', help='Remote repository URL for analysis (supports GitHub, GitLab, Bitbucket)')
@click.option('--discover-releases', type=int, help='Auto-discover and compare N latest releases (default: 3)')
@click.option('--batch-repos', help='File containing list of repositories for batch analysis')
@click.option('--release-progression', help='Analyze release progression for comma-separated tags (e.g., "v1.0.0,v1.1.0,v2.0.0")')
@click.option('--auto-discovery/--no-auto-discovery', default=False, 
              help='Enable automatic discovery of tags and branches')
@click.option('--batch-workers', type=int, default=3, 
              help='Number of parallel workers for batch operations')
@click.option('--enterprise-report', type=click.Choice(['executive', 'comprehensive', 'security']),
              help='Generate enterprise-grade report')

# Advanced comparison options (Phase 4)
@click.option('--diff-algorithm', 
              type=click.Choice(['simple', 'hybrid', 'semantic', 'structural', 'performance']),
              default='hybrid',
              help='Diff algorithm for route comparison (default: hybrid)')
@click.option('--filter-by', 
              help='Advanced filtering: "framework=express,nestjs;path=/api/*,/admin/*;method=POST,PUT"')
@click.option('--include-file-changes/--no-file-changes', 
              default=False,
              help='Include detailed file-level change tracking')
@click.option('--risk-analysis/--no-risk-analysis', 
              default=True,
              help='Include risk impact analysis for route changes')
@click.option('--similarity-threshold', 
              type=float, 
              default=0.8,
              help='Similarity threshold for change detection (0.0-1.0)')
@click.option('--output-format', 
              type=click.Choice(['terminal', 'json', 'csv', 'sarif', 'html']),
              multiple=True,
              default=['terminal'],
              help='Output format(s) for results')

# Performance optimization options (Phase 4)
@click.option('--performance-mode', 
              type=click.Choice(['auto', 'fast', 'balanced', 'memory-optimized']),
              default='auto',
              help='Performance optimization mode (default: auto-detect based on repo size)')
@click.option('--cache-enabled/--no-cache', 
              default=True,
              help='Enable intelligent caching for faster re-scans')
@click.option('--cache-cleanup', 
              type=int,
              help='Clean cache entries older than N days (default: 30)')
@click.option('--max-memory', 
              type=int,
              default=1024,
              help='Maximum memory usage in MB (default: 1024)')
@click.option('--performance-report/--no-performance-report', 
              default=True,
              help='Display detailed performance report after scan')
@click.option('--chunk-size', 
              type=int,
              help='File processing chunk size for large repositories (auto-calculated if not specified)')
@click.option('--max-workers', 
              type=int,
              help='Maximum parallel workers (auto-calculated if not specified)')
@click.option('--progress-mode', 
              type=click.Choice(['simple', 'enhanced', 'quiet']),
              default='enhanced',
              help='Progress reporting mode (default: enhanced)')

# Configuration management options (Phase 6)
@click.option('--config', 
              help='Path to configuration file (YAML or JSON)')
@click.option('--config-generate', 
              help='Generate example configuration file at specified path')
@click.option('--config-validate', 
              help='Validate configuration file and exit')
@click.option('--custom-risk-rules', 
              help='Path to custom risk rules file')
@click.option('--organization-config', 
              help='Path to organization-specific configuration')

def main(repo_path, output_dir, frameworks, risk_threshold, 
         use_ai, organization_patterns, resolve_prefixes, prefix_config, prefixes_only, verbose,
         diff_algorithm, filter_by, include_file_changes, risk_analysis, similarity_threshold, output_format,
         compare_dir, compare_tags, compare_against_tag, compare_branches, auth_method, git_token, ssh_key, git_username,
         remote_repo, discover_releases, batch_repos, release_progression, auto_discovery, batch_workers, enterprise_report,
         performance_mode, cache_enabled, cache_cleanup, max_memory, performance_report, chunk_size, max_workers, progress_mode,
         config, config_generate, config_validate, custom_risk_rules, organization_config):
    """
    RouteHawk Attack Surface Discovery Tool
    
    Scan your repository for API routes and security vulnerabilities.
    """
    
    # Setup logging level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Phase 6: Configuration Management
    try:
        # Handle configuration generation
        if config_generate:
            console.print(f"[green]📄 Generating example configuration file: {config_generate}[/green]")
            config_manager = ConfigurationManager()
            if config_generate.endswith('-enterprise.yaml') or 'enterprise' in config_generate:
                # Copy comprehensive enterprise example
                import shutil
                enterprise_example = Path(__file__).parent / "config" / "examples" / "enterprise-config.yaml"
                shutil.copy(enterprise_example, config_generate)
            else:
                # Generate simple example
                config_manager.create_example_config(config_generate)
            console.print(f"[green]✅ Configuration file created successfully[/green]")
            return
        
        # Handle configuration validation
        if config_validate:
            console.print(f"[cyan]🔍 Validating configuration file: {config_validate}[/cyan]")
            try:
                config_manager = ConfigurationManager([config_validate])
                console.print(f"[green]✅ Configuration file is valid[/green]")
                # Show configuration summary
                config_data = config_manager.config
                console.print(f"\n[bold]Configuration Summary:[/bold]")
                console.print(f"Organization: {config_data.organization.organization_name}")
                console.print(f"Security Baseline: {config_data.organization.security_baseline}")
                console.print(f"Enabled Frameworks: {', '.join(config_data.frameworks.enabled_frameworks)}")
                console.print(f"Custom Risk Rules: {len(config_data.custom_risk_rules)}")
                return
            except Exception as e:
                console.print(f"[red]❌ Configuration validation failed: {e}[/red]")
                sys.exit(1)
        
        # Load configuration from files
        config_paths = []
        if config:
            config_paths.append(config)
        if organization_config:
            config_paths.append(organization_config)
        if custom_risk_rules:
            config_paths.append(custom_risk_rules)
        
        # Initialize configuration manager
        config_manager = get_config_manager(config_paths if config_paths else None)
        enterprise_config = config_manager.config
        
        # Override CLI parameters with configuration if not explicitly set
        # This allows configuration files to provide defaults while CLI takes precedence
        if not frameworks or frameworks == 'auto':
            if enterprise_config.frameworks.enabled_frameworks:
                frameworks = ','.join(enterprise_config.frameworks.enabled_frameworks)
        
        if risk_threshold == 'medium':  # Default value
            risk_threshold = enterprise_config.security.default_risk_threshold
        
        if use_ai is True:  # Default value
            use_ai = enterprise_config.security.enable_ai_analysis
        
        if max_memory == 1024:  # Default value
            max_memory = enterprise_config.performance.memory_limit_mb
        
        if not output_format or output_format == ('terminal',):
            output_format = tuple(enterprise_config.output.default_formats)
        
        console.print(f"[dim]📋 Configuration loaded: {len(config_manager.config_paths)} file(s), {len(enterprise_config.custom_risk_rules)} custom rules[/dim]")
        
    except Exception as e:
        console.print(f"[yellow]⚠️  Configuration warning: {e}[/yellow]")
        # Continue with default configuration
        config_manager = ConfigurationManager([])
        enterprise_config = config_manager.config
    
    # Validate repo-path is provided unless it's a configuration-only command
    if not repo_path and not (config_generate or config_validate):
        console.print("[red]❌ Error: --repo-path is required for scanning operations[/red]")
        console.print("[dim]Use --config-generate or --config-validate for configuration-only operations[/dim]")
        sys.exit(1)
    
    # Phase 4: Handle cache cleanup if requested
    if cache_cleanup:
        console.print(f"[yellow]🧹 Cleaning cache entries older than {cache_cleanup} days...[/yellow]")
        cache = IntelligentCache()
        cache.cleanup_old_entries(cache_cleanup)
        console.print("[green]✅ Cache cleanup completed[/green]")
        return
    
    # Phase 4: Configure performance settings
    performance_config = {
        'mode': performance_mode,
        'cache_enabled': cache_enabled,
        'max_memory_mb': max_memory,
        'chunk_size': chunk_size,
        'max_workers': max_workers,
        'progress_mode': progress_mode,
        'performance_report': performance_report
    }
    
    # Parse frameworks
    if frameworks == 'all':
        selected_frameworks = list(Framework)
    elif frameworks == 'auto':
        selected_frameworks = []  # Will auto-detect
    else:
        framework_map = {
            'nestjs': Framework.NESTJS,
            'express': Framework.EXPRESS,
            'nextjs': Framework.NEXTJS,
            'go': Framework.GO_HTTP,
            'fastapi': Framework.FASTAPI,
            'grpc': Framework.GRPC,
            'infrastructure': Framework.INFRASTRUCTURE
        }
        selected_frameworks = []
        for fw in frameworks.split(','):
            fw = fw.strip().lower()
            if fw in framework_map:
                selected_frameworks.append(framework_map[fw])
            else:
                console.print(f"[red]Unknown framework: {fw}[/red]")
                sys.exit(1)

    # Parse output format (handle both single format and multiple formats)
    if isinstance(output_format, (list, tuple)):
        output_formats = [fmt.lower() for fmt in output_format]
    else:
        output_formats = [output_format.lower()]
    
    # Extract primary format for backward compatibility with single-format functions
    primary_format = output_formats[0] if output_formats else 'terminal'
    
    # Create scan configuration
    config = ScanConfig(
        repo_path=repo_path,
        frameworks=selected_frameworks,
        use_ai_analysis=use_ai,
        risk_threshold=RiskLevel(risk_threshold.upper()),
        organization_patterns=organization_patterns,
        resolve_prefixes=resolve_prefixes,
        prefix_config_path=prefix_config,
        prefixes_only=prefixes_only,
        output_formats=output_formats,
        output_directory=output_dir,
        # Performance configuration
        performance_mode=performance_config['mode'],
        cache_enabled=performance_config['cache_enabled'],
        max_memory_mb=performance_config['max_memory_mb'],
        chunk_size=performance_config['chunk_size'],
        max_workers=performance_config['max_workers'],
        progress_mode=performance_config['progress_mode'],
        performance_report=performance_config['performance_report']
    )
    
    # Display frameworks info (needed for both regular scan and directory comparison)
    frameworks_display = "Auto-detecting..." if not config.frameworks else ', '.join([f.value if hasattr(f, 'value') else str(f) for f in config.frameworks]).title()
    
    # Handle directory comparison mode (Phase 1)
    if compare_dir:
        console.print(Panel(
            f"[bold blue]🔍 Directory Comparison Mode[/bold blue]\n"
            f"[cyan]Source:[/cyan] {repo_path}\n"
            f"[cyan]Target:[/cyan] {compare_dir}\n"
            f"[cyan]Frameworks:[/cyan] {frameworks_display}\n"
            f"[cyan]Include File Changes:[/cyan] {'Yes' if include_file_changes else 'No'}\n"
            f"[cyan]Diff Algorithm:[/cyan] {diff_algorithm.title()}"
        ))
        
        try:
            # Parse filters if provided
            comparison_filters = None
            if filter_by:
                comparison_filters = _parse_filter_string(filter_by, console)
            
            # Create comparison configuration
            comparison_config = ComparisonConfig(
                comparison_type="directories",
                source=repo_path,
                target=compare_dir,
                filters=comparison_filters,
                diff_algorithm=diff_algorithm,
                include_file_changes=include_file_changes,
                include_risk_analysis=True
            )
            
            # Run directory comparison (use first format for backward compatibility)
            asyncio.run(_run_directory_comparison(config, comparison_config, primary_format, verbose))
            return
            
        except Exception as e:
            console.print(f"\n[bold red]Error during directory comparison: {e}[/bold red]")
            if verbose:
                console.print_exception()
            sys.exit(1)
    
    # Handle git tag comparison (Phase 2)
    if compare_tags:
        tags = compare_tags.split(',')
        if len(tags) != 2:
            console.print("[bold red]Error: --compare-tags requires exactly two tags (e.g., 'v1.0.0,v2.0.0')[/bold red]")
            sys.exit(1)
        
        source_tag, target_tag = [tag.strip() for tag in tags]
        
        console.print(Panel(
            f"[bold blue]🏷️  Git Tag Comparison Mode[/bold blue]\n"
            f"[cyan]Repository:[/cyan] {repo_path}\n"
            f"[cyan]Source Tag:[/cyan] {source_tag}\n"
            f"[cyan]Target Tag:[/cyan] {target_tag}\n"
            f"[cyan]Frameworks:[/cyan] {frameworks_display}\n"
            f"[cyan]Auth Method:[/cyan] {auth_method.title()}"
        ))
        
        try:
            # Parse filters if provided
            comparison_filters = None
            if filter_by:
                comparison_filters = _parse_filter_string(filter_by, console)
            
            # Create git comparison configuration
            git_comparison_config = ComparisonConfig(
                comparison_type="tags",
                source=source_tag,
                target=target_tag,
                filters=comparison_filters,
                diff_algorithm=diff_algorithm,
                include_file_changes=include_file_changes,
                include_risk_analysis=True,
                auth_method=auth_method
            )
            
            # Run git tag comparison (use first format for backward compatibility)
            asyncio.run(_run_git_comparison(config, git_comparison_config, "tags", primary_format, verbose))
            return
            
        except Exception as e:
            console.print(f"\n[bold red]Error during git tag comparison: {e}[/bold red]")
            if verbose:
                console.print_exception()
            sys.exit(1)
    
    # Handle git branch comparison (Phase 2)  
    if compare_branches:
        branches = compare_branches.split(',')
        if len(branches) != 2:
            console.print("[bold red]Error: --compare-branches requires exactly two branches (e.g., 'main,develop')[/bold red]")
            sys.exit(1)
        
        source_branch, target_branch = [branch.strip() for branch in branches]
        
        console.print(Panel(
            f"[bold blue]🌿 Git Branch Comparison Mode[/bold blue]\n"
            f"[cyan]Repository:[/cyan] {repo_path}\n"
            f"[cyan]Source Branch:[/cyan] {source_branch}\n"
            f"[cyan]Target Branch:[/cyan] {target_branch}\n"
            f"[cyan]Frameworks:[/cyan] {frameworks_display}\n"
            f"[cyan]Auth Method:[/cyan] {auth_method.title()}"
        ))
        
        try:
            # Parse filters if provided
            comparison_filters = None
            if filter_by:
                comparison_filters = _parse_filter_string(filter_by, console)
            
            # Create git comparison configuration
            git_comparison_config = ComparisonConfig(
                comparison_type="branches",
                source=source_branch,
                target=target_branch,
                filters=comparison_filters,
                diff_algorithm=diff_algorithm,
                include_file_changes=include_file_changes,
                include_risk_analysis=True,
                auth_method=auth_method
            )
            
            # Run git branch comparison
            asyncio.run(_run_git_comparison(config, git_comparison_config, "branches", primary_format, verbose))
            return
            
        except Exception as e:
            console.print(f"\n[bold red]Error during git branch comparison: {e}[/bold red]")
            if verbose:
                console.print_exception()
            sys.exit(1)
    
    # Handle git against-tag comparison (Phase 2)
    if compare_against_tag:
        console.print(Panel(
            f"[bold blue]📊 Git Against-Tag Comparison Mode[/bold blue]\n"
            f"[cyan]Repository:[/cyan] {repo_path}\n"
            f"[cyan]Base Tag:[/cyan] {compare_against_tag}\n"
            f"[cyan]Target:[/cyan] Current State\n"
            f"[cyan]Frameworks:[/cyan] {frameworks_display}\n"
            f"[cyan]Auth Method:[/cyan] {auth_method.title()}"
        ))
        
        try:
            # Parse filters if provided
            comparison_filters = None
            if filter_by:
                comparison_filters = _parse_filter_string(filter_by, console)
            
            # Create git comparison configuration
            git_comparison_config = ComparisonConfig(
                comparison_type="against_tag",
                source=compare_against_tag,
                target="current",
                filters=comparison_filters,
                diff_algorithm=diff_algorithm,
                include_file_changes=include_file_changes,
                include_risk_analysis=True,
                auth_method=auth_method
            )
            
            # Run git against-tag comparison
            asyncio.run(_run_git_comparison(config, git_comparison_config, "against_tag", primary_format, verbose))
            return
            
        except Exception as e:
            console.print(f"\n[bold red]Error during git against-tag comparison: {e}[/bold red]")
            if verbose:
                console.print_exception()
            sys.exit(1)
    
    # Handle remote repository analysis (Phase 3)
    if remote_repo:
        console.print(Panel(
            f"[bold blue]🌐 Remote Repository Analysis Mode[/bold blue]\n"
            f"[cyan]Repository:[/cyan] {remote_repo}\n"
            f"[cyan]Frameworks:[/cyan] {frameworks_display}\n"
            f"[cyan]Auto Discovery:[/cyan] {'Enabled' if auto_discovery else 'Disabled'}\n"
            f"[cyan]Auth Method:[/cyan] {auth_method.title()}"
        ))
        
        try:
            # Set up authentication config
            auth_config = {}
            if git_token:
                if 'github.com' in remote_repo:
                    auth_config['github_token'] = git_token
                    if git_username:
                        auth_config['github_username'] = git_username
                elif 'gitlab.com' in remote_repo:
                    auth_config['gitlab_token'] = git_token
                    if git_username:
                        auth_config['gitlab_username'] = git_username
            
            # Create enhanced comparator
            enhanced_comparator = EnhancedRouteComparator(AttackSurfaceScanner(config, config_manager), auth_config)
            
            if discover_releases:
                # Auto-discover and compare latest releases
                console.print(f"\n[cyan]Auto-discovering {discover_releases} latest releases...[/cyan]")
                
                comparison_config = ComparisonConfig(
                    comparison_type="auto_discovery",
                    source="auto",
                    target="auto",
                    diff_algorithm=diff_algorithm,
                    include_file_changes=include_file_changes,
                    include_risk_analysis=True,
                    auth_method=auth_method
                )
                
                batch_result = enhanced_comparator.discover_and_compare_latest_tags(
                    remote_repo, discover_releases, comparison_config
                )
                
                # Display results
                _display_batch_results(batch_result, console)
                
            elif release_progression:
                # Analyze release progression
                tags = [tag.strip() for tag in release_progression.split(',')]
                
                console.print(f"\n[cyan]Analyzing release progression: {' → '.join(tags)}[/cyan]")
                
                comparison_config = ComparisonConfig(
                    comparison_type="progression",
                    source="auto",
                    target="auto",
                    diff_algorithm=diff_algorithm,
                    include_file_changes=include_file_changes,
                    include_risk_analysis=True,
                    auth_method=auth_method
                )
                
                batch_result = enhanced_comparator.compare_release_progression(
                    remote_repo, tags, comparison_config
                )
                
                # Display results
                _display_batch_results(batch_result, console)
                
            else:
                console.print("[yellow]No specific remote analysis operation specified. Use --discover-releases or --release-progression[/yellow]")
            
            return
            
        except Exception as e:
            console.print(f"\n[bold red]Error during remote repository analysis: {e}[/bold red]")
            if verbose:
                console.print_exception()
            sys.exit(1)
    
    # Handle batch repository analysis (Phase 3)
    if batch_repos:
        console.print(Panel(
            f"[bold blue]📦 Batch Repository Analysis Mode[/bold blue]\n"
            f"[cyan]Repository List:[/cyan] {batch_repos}\n"
            f"[cyan]Parallel Workers:[/cyan] {batch_workers}\n"
            f"[cyan]Frameworks:[/cyan] {frameworks_display}\n"
            f"[cyan]Enterprise Report:[/cyan] {enterprise_report or 'None'}"
        ))
        
        try:
            # Read repository list
            with open(batch_repos, 'r') as f:
                repositories = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            console.print(f"\n[cyan]Starting batch analysis of {len(repositories)} repositories...[/cyan]")
            
            # Set up authentication config
            auth_config = {}
            if git_token:
                auth_config['github_token'] = git_token
                auth_config['gitlab_token'] = git_token
                if git_username:
                    auth_config['github_username'] = git_username
                    auth_config['gitlab_username'] = git_username
            
            # Create batch operations manager
            batch_manager = BatchOperationsManager(AttackSurfaceScanner(config), auth_config)
            
            # Create comparison config
            comparison_config = ComparisonConfig(
                comparison_type="batch_analysis",
                source="auto",
                target="auto",
                diff_algorithm=diff_algorithm,
                include_file_changes=include_file_changes,
                include_risk_analysis=True,
                auth_method=auth_method
            )
            
            if auto_discovery:
                # Use auto-discovery for all repositories
                batch_result = batch_manager.discover_and_analyze_releases(
                    repositories, discover_releases or 3, comparison_config
                )
            else:
                # Create and execute multi-repository job
                job = batch_manager.create_multi_repository_job(
                    repositories, "latest_tags", comparison_config
                )
                batch_result = batch_manager.execute_multi_repository_analysis(job)
            
            # Display batch results
            _display_batch_job_results(batch_result, console)
            
            # Generate enterprise report if requested
            if enterprise_report:
                enterprise_report_data = batch_manager.generate_enterprise_report(
                    [batch_result], enterprise_report
                )
                _display_enterprise_report(enterprise_report_data, console)
                
                # Export enterprise report
                if output_dir:
                    report_path = Path(output_dir) / f"enterprise_report_{enterprise_report}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    with open(report_path, 'w') as f:
                        json.dump(enterprise_report_data, f, indent=2, default=str)
                    console.print(f"\n[green]Enterprise report exported to: {report_path}[/green]")
            
            return
            
        except Exception as e:
            console.print(f"\n[bold red]Error during batch repository analysis: {e}[/bold red]")
            if verbose:
                console.print_exception()
            sys.exit(1)
    
    # Display scan banner with RouteHawk logo
    # RouteHawk ASCII Art Logo  
    hawk_logo = """
[bold yellow]                                  /^^^\\                            [/bold yellow]
[bold yellow]                                 / o o \\                           [/bold yellow]
[bold yellow]                                 \\  v  /                            [/bold yellow]
[bold red]                                  \\ - /                             [/bold red]
[bold white]                                   \\|/                              [/bold white]
[bold white]                                 __/|\\__                           [/bold white]
[bold cyan]                                /       \\                          [/bold cyan]
[bold cyan]                               /_________\\                         [/bold cyan]

[bold red]                               🦅 RouteHawk 🦅                         [/bold red]
[dim]                         API Attack Surface Discovery               [/dim]
[bold green]                     Developed by Ranjan Kumar (@rootranjan)                   [/bold green]
"""
    
    console.print(hawk_logo)
    
    console.print(Panel(
        f"[bold blue]🔒 RouteHawk Attack Surface Discovery Tool[/bold blue]\n"
        f"[cyan]Scanning:[/cyan] {repo_path}\n"
        f"[cyan]Frameworks:[/cyan] {frameworks_display}\n"
        f"[cyan]AI Analysis:[/cyan] {'Enabled' if use_ai else 'Disabled'}"
    ))
    
    # Quick framework detection preview
    if not prefixes_only:
        console.print(f"\n[dim]🔍 Performing initial framework detection...[/dim]")
    
    # Run async operations
    try:
        asyncio.run(_run_async_scan(config, prefixes_only, verbose, primary_format))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]Error during scan: {e}[/bold red]")
        if verbose:
            console.print_exception()
        sys.exit(1)

def _display_detailed_route_changes(changes: List, console):
    """Display detailed route changes with up to 20 routes per category."""
    from rich.table import Table
    from models import RiskLevel
    
    # Group changes by type
    change_groups = {
        'ADDED': [c for c in changes if c.change_type == 'ADDED'],
        'REMOVED': [c for c in changes if c.change_type == 'REMOVED'], 
        'MODIFIED': [c for c in changes if c.change_type == 'MODIFIED']
    }
    
    for change_type, change_list in change_groups.items():
        if not change_list:
            continue
            
        # Color coding for different change types
        color_map = {
            'ADDED': 'green',
            'REMOVED': 'red', 
            'MODIFIED': 'yellow'
        }
        color = color_map.get(change_type, 'white')
        
        console.print(f"\n[bold {color}]{change_type} Routes ({len(change_list)} total):[/bold {color}]")
        
        # Create detailed table for this change type
        detail_table = Table(show_header=True, header_style=f"bold {color}")
        detail_table.add_column("Method", style="cyan", min_width=8)
        detail_table.add_column("Path", style="white", min_width=40) 
        detail_table.add_column("File", style="dim", min_width=30)
        detail_table.add_column("Risk", style="red", min_width=8)
        
        # Show up to 20 routes for this change type
        display_count = min(20, len(change_list))
        for i in range(display_count):
            change = change_list[i]
            route = change.new_route or change.old_route
            
            if route:
                # Safe string conversion
                method_str = str(route.method)
                path_str = route.path or "/"
                file_str = route.file_path or "unknown"
                risk_str = str(change.risk_impact)
                
                # Truncate long paths for display
                if len(path_str) > 60:
                    path_str = path_str[:57] + "..."
                if len(file_str) > 50:
                    file_str = "..." + file_str[-47:]
                
                # Risk level color coding
                risk_color = {
                    'HIGH': 'red',
                    'MEDIUM': 'yellow', 
                    'LOW': 'green'
                }.get(risk_str.upper(), 'white')
                
                detail_table.add_row(
                    method_str,
                    path_str,
                    file_str,
                    f"[{risk_color}]{risk_str}[/{risk_color}]"
                )
        
        console.print(detail_table)
        
        # Show count if there are more routes
        if len(change_list) > 20:
            console.print(f"[dim]... and {len(change_list) - 20} more {change_type.lower()} routes[/dim]")

if __name__ == "__main__":
    main() 