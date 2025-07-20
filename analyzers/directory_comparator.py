#!/usr/bin/env python3
"""
Directory Comparator for RouteHawk

Compares routes between two local directories without requiring git operations.
Useful for comparing different versions of code, different branches that have been
checked out separately, or comparing against backup/archived versions.
"""

import os
import logging
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple, Any
from datetime import datetime

from models import (
    RouteInfo, ComparisonResult, RouteChange, FileChange, 
    ComparisonConfig, RiskLevel, ScanResult
)

class DirectoryComparator:
    """
    Compare routes between two local directories.
    
    This comparator scans both directories independently and then analyzes
    the differences in discovered routes.
    """
    
    def __init__(self, scanner):
        """
        Initialize the directory comparator.
        
        Args:
            scanner: AttackSurfaceScanner instance for route detection
        """
        self.scanner = scanner
        self.logger = logging.getLogger(__name__)
    
    def compare_directories(self, source_dir: str, target_dir: str, 
                          config: ComparisonConfig) -> ComparisonResult:
        """
        Compare routes between two local directories.
        
        Args:
            source_dir: Path to source directory  
            target_dir: Path to target directory
            config: Comparison configuration
            
        Returns:
            ComparisonResult with detailed analysis
        """
        self.logger.info(f"Comparing directories: {source_dir} -> {target_dir}")
        
        try:
            # Validate directories exist
            source_path = Path(source_dir)
            target_path = Path(target_dir)
            
            if not source_path.exists():
                raise ValueError(f"Source directory does not exist: {source_dir}")
            if not target_path.exists():
                raise ValueError(f"Target directory does not exist: {target_dir}")
            
            # Scan both directories
            source_routes = self._scan_directory(source_path, "source")
            target_routes = self._scan_directory(target_path, "target")
            
            # Filter out invalid routes (file paths mistaken as API routes)
            source_routes = self._filter_valid_routes(source_routes, str(source_path))
            target_routes = self._filter_valid_routes(target_routes, str(target_path))
            
            # Apply filters if specified
            if config.filters:
                source_routes = self._apply_advanced_filtering(source_routes, config)
                target_routes = self._apply_advanced_filtering(target_routes, config)
            
            # Compare routes
            route_changes = self._compare_routes(source_routes, target_routes, config)
            
            # Get file changes if requested
            file_changes = []
            if config.include_file_changes:
                file_changes = self._analyze_file_changes(source_path, target_path)
            
            # Create comparison result
            result = ComparisonResult(
                source_version=str(source_path),
                target_version=str(target_path),
                comparison_type="directories",
                changes=route_changes,
                file_changes=file_changes,
                scan_metadata={
                    'source_routes_count': len(source_routes),
                    'target_routes_count': len(target_routes),
                    'filters_applied': config.filters is not None,
                    'diff_algorithm': config.diff_algorithm
                }
            )
            
            self.logger.info(f"Directory comparison completed: {len(route_changes)} route changes found")
            return result
            
        except Exception as e:
            self.logger.error(f"Error comparing directories: {e}")
            return ComparisonResult(
                source_version=str(source_dir),
                target_version=str(target_dir),
                comparison_type="directories",
                errors=[str(e)]
            )

    async def _scan_directory_async(self, directory: Path, version_name: str) -> List[RouteInfo]:
        """
        Async version of directory scanning for CLI context.
        """
        self.logger.info(f"Scanning {version_name} directory: {directory}")
        
        try:
            # Create a fresh scanner instance to avoid state contamination
            from routehawk import AttackSurfaceScanner
            from models import ScanConfig
            
            # Create a fresh config for this directory scan
            fresh_config = ScanConfig(
                repo_path=str(directory),
                frameworks=self.scanner.config.frameworks,
                use_ai_analysis=self.scanner.config.use_ai_analysis,
                risk_threshold=self.scanner.config.risk_threshold,
                resolve_prefixes=self.scanner.config.resolve_prefixes,
                prefix_config_path=self.scanner.config.prefix_config_path,
                output_formats=self.scanner.config.output_formats,
                output_directory=self.scanner.config.output_directory,
                organization_patterns=self.scanner.config.organization_patterns,
                prefixes_only=self.scanner.config.prefixes_only
            )
            
            # Create fresh scanner instance
            fresh_scanner = AttackSurfaceScanner(fresh_config)
            
            # Run the scan asynchronously
            scan_result = await fresh_scanner.scan_repository()
            
            # Extract routes from scan result
            if hasattr(scan_result, 'routes'):
                return scan_result.routes
            else:
                return []
                
        except Exception as e:
            self.logger.error(f"Error scanning {version_name} directory: {e}")
            return []

    def _scan_directory(self, directory: Path, version_name: str) -> List[RouteInfo]:
        """
        Scan a directory for routes using a fresh scanner instance.
        
        Args:
            directory: Directory path to scan
            version_name: Human-readable version name for logging
            
        Returns:
            List of discovered routes
        """
        self.logger.info(f"Scanning {version_name} directory: {directory}")
        
        try:
            # Create a fresh scanner instance to avoid state contamination
            from routehawk import AttackSurfaceScanner
            from models import ScanConfig
            
            # Create a fresh config for this directory scan
            fresh_config = ScanConfig(
                repo_path=str(directory),
                frameworks=self.scanner.config.frameworks,
                use_ai_analysis=self.scanner.config.use_ai_analysis,
                risk_threshold=self.scanner.config.risk_threshold,
                resolve_prefixes=self.scanner.config.resolve_prefixes,
                prefix_config_path=self.scanner.config.prefix_config_path,
                output_formats=self.scanner.config.output_formats,
                output_directory=self.scanner.config.output_directory,
                organization_patterns=self.scanner.config.organization_patterns,
                prefixes_only=self.scanner.config.prefixes_only
            )
            
            # Create fresh scanner instance
            fresh_scanner = AttackSurfaceScanner(fresh_config)
            
            # Run the scan - simplified approach using asyncio.run in a thread
            import asyncio
            import threading
            from concurrent.futures import ThreadPoolExecutor
            
            def run_scan_in_thread():
                """Run async scan in a separate thread to avoid context issues"""
                try:
                    return asyncio.run(fresh_scanner.scan_repository())
                except Exception as e:
                    self.logger.error(f"Thread scan error: {e}")
                    return None
            
            # Use ThreadPoolExecutor to run the async scan
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(run_scan_in_thread)
                scan_result = future.result(timeout=300)  # 5 minute timeout
            
            # Extract routes from scan result
            if scan_result and hasattr(scan_result, 'routes') and scan_result.routes:
                self.logger.info(f"Scan completed for {version_name}: {len(scan_result.routes)} routes found")
                return scan_result.routes
            else:
                self.logger.warning(f"No routes found in {version_name} directory")
                return []
                
        except Exception as e:
            self.logger.error(f"Error scanning {version_name} directory: {e}")
            import traceback
            self.logger.error(f"Full traceback: {traceback.format_exc()}")
            return []
    
    def _apply_filters(self, routes: List[RouteInfo], filters) -> List[RouteInfo]:
        """
        Apply comparison filters to route list.
        
        Args:
            routes: List of routes to filter
            filters: ComparisonFilter configuration
            
        Returns:
            Filtered list of routes
        """
        filtered_routes = routes
        
        # Filter by frameworks
        if filters.frameworks:
            filtered_routes = [r for r in filtered_routes 
                             if r.framework in filters.frameworks]
        
        # Filter by HTTP methods
        if filters.methods:
            filtered_routes = [r for r in filtered_routes 
                             if r.method in filters.methods]
        
        # Filter by path patterns (simple string matching for now)
        if filters.paths:
            import fnmatch
            filtered_routes = [r for r in filtered_routes 
                             if any(fnmatch.fnmatch(r.path, pattern) 
                                   for pattern in filters.paths)]
        
        # Filter by file path patterns
        if filters.file_paths:
            import fnmatch
            filtered_routes = [r for r in filtered_routes 
                             if any(fnmatch.fnmatch(r.file_path, pattern) 
                                   for pattern in filters.file_paths)]
        
        # Filter by original path patterns
        if filters.original_paths and hasattr(r, 'original_path'):
            import fnmatch
            filtered_routes = [r for r in filtered_routes 
                             if r.original_path and any(fnmatch.fnmatch(r.original_path, pattern) 
                                                       for pattern in filters.original_paths)]
        
        self.logger.debug(f"Applied filters: {len(routes)} -> {len(filtered_routes)} routes")
        return filtered_routes
    
    def _compare_routes(self, source_routes: List[RouteInfo], 
                       target_routes: List[RouteInfo], 
                       config: ComparisonConfig) -> List[RouteChange]:
        """
        Compare two sets of routes and identify changes using advanced diff algorithms.
        
        Args:
            source_routes: Routes from source directory
            target_routes: Routes from target directory  
            config: Comparison configuration
            
        Returns:
            List of route changes
        """
        self.logger.debug(f"Comparing routes: {len(source_routes)} source vs {len(target_routes)} target")
        
        # Use advanced diff algorithms if specified
        if hasattr(config, 'diff_algorithm') and config.diff_algorithm in ['hybrid', 'semantic', 'structural', 'performance']:
            return self._use_advanced_diff_algorithms(source_routes, target_routes, config)
        
        # Fallback to simple comparison for backward compatibility
        changes = []
        
        # Create lookup dictionaries for efficient comparison
        source_dict = {self._get_route_key(route): route for route in source_routes}
        target_dict = {self._get_route_key(route): route for route in target_routes}
        
        self.logger.debug(f"Source route keys: {list(source_dict.keys())}")
        self.logger.debug(f"Target route keys: {list(target_dict.keys())}")
        
        source_keys = set(source_dict.keys())
        target_keys = set(target_dict.keys())
        
        # Find added routes (in target but not in source)
        added_keys = target_keys - source_keys
        self.logger.debug(f"Added route keys: {added_keys}")
        for key in added_keys:
            route = target_dict[key]
            risk_impact = self._assess_change_risk("ADDED", None, route)
            changes.append(RouteChange(
                change_type="ADDED",
                new_route=route,
                risk_impact=risk_impact,
                change_details={'reason': 'Route added in target directory'}
            ))
        
        # Find removed routes (in source but not in target)  
        removed_keys = source_keys - target_keys
        self.logger.debug(f"Removed route keys: {removed_keys}")
        for key in removed_keys:
            route = source_dict[key]
            risk_impact = self._assess_change_risk("REMOVED", route, None)
            changes.append(RouteChange(
                change_type="REMOVED",
                old_route=route,
                risk_impact=risk_impact,
                change_details={'reason': 'Route removed from target directory'}
            ))
        
        # Find potentially modified routes (same key, different details)
        common_keys = source_keys & target_keys
        self.logger.debug(f"Common route keys: {common_keys}")
        for key in common_keys:
            source_route = source_dict[key]
            target_route = target_dict[key]
            
            if self._routes_differ(source_route, target_route):
                risk_impact = self._assess_change_risk("MODIFIED", source_route, target_route)
                differences = self._analyze_route_differences(source_route, target_route)
                changes.append(RouteChange(
                    change_type="MODIFIED",
                    old_route=source_route,
                    new_route=target_route,
                    risk_impact=risk_impact,
                    change_details=differences
                ))
        
        self.logger.debug(f"Route comparison complete: {len(changes)} changes found")
        return changes
    
    def _use_advanced_diff_algorithms(self, source_routes: List[RouteInfo], 
                                     target_routes: List[RouteInfo], 
                                     config: ComparisonConfig) -> List[RouteChange]:
        """
        Use advanced diff algorithms for route comparison.
        
        Args:
            source_routes: Routes from source directory
            target_routes: Routes from target directory  
            config: Comparison configuration
            
        Returns:
            List of route changes using advanced algorithms
        """
        try:
            from .diff_algorithms import AdvancedDiffEngine, DiffAlgorithm
            
            # Map diff algorithm from config
            algorithm_map = {
                'hybrid': DiffAlgorithm.HYBRID,
                'semantic': DiffAlgorithm.SEMANTIC,
                'structural': DiffAlgorithm.STRUCTURAL,
                'performance': DiffAlgorithm.PERFORMANCE,
                'simple': DiffAlgorithm.SIMPLE
            }
            
            algorithm = algorithm_map.get(config.diff_algorithm, DiffAlgorithm.HYBRID)
            
            # Create and use advanced diff engine
            diff_engine = AdvancedDiffEngine(algorithm)
            changes = diff_engine.compare_routes(source_routes, target_routes)
            
            # Log algorithm metrics
            if diff_engine.metrics:
                self.logger.info(f"Advanced diff metrics: {diff_engine.metrics}")
            
            # Convert to RouteChange format expected by the system
            converted_changes = []
            for change in changes:
                # Safe access to risk level
                risk_impact = RiskLevel.LOW
                if hasattr(change, 'risk_impact'):
                    if hasattr(change.risk_impact, 'value'):
                        risk_impact = change.risk_impact
                    else:
                        # Handle string risk levels
                        risk_map = {'LOW': RiskLevel.LOW, 'MEDIUM': RiskLevel.MEDIUM, 'HIGH': RiskLevel.HIGH}
                        risk_impact = risk_map.get(str(change.risk_impact).upper(), RiskLevel.LOW)
                
                route_change = RouteChange(
                    change_type=change.change_type.upper(),
                    old_route=getattr(change, 'old_route', None),
                    new_route=getattr(change, 'new_route', None),
                    risk_impact=risk_impact,
                    change_details={
                        'algorithm': algorithm.value,
                        'confidence': getattr(change, 'confidence', 0.8),
                        'description': getattr(change, 'description', '')
                    }
                )
                converted_changes.append(route_change)
            
            return converted_changes
            
        except ImportError as e:
            self.logger.warning(f"Advanced diff algorithms not available: {e}")
            # Fallback to simple comparison
            return self._simple_route_comparison(source_routes, target_routes, config)
        except Exception as e:
            self.logger.error(f"Error in advanced diff algorithms: {e}")
            # Fallback to simple comparison
            return self._simple_route_comparison(source_routes, target_routes, config)
    
    def _simple_route_comparison(self, source_routes: List[RouteInfo], 
                                target_routes: List[RouteInfo], 
                                config: ComparisonConfig) -> List[RouteChange]:
        """
        Simple route comparison for fallback scenarios.
        
        Args:
            source_routes: Routes from source directory
            target_routes: Routes from target directory  
            config: Comparison configuration
            
        Returns:
            List of route changes using simple comparison
        """
        changes = []
        
        # Create lookup dictionaries for efficient comparison
        source_dict = {self._get_route_key(route): route for route in source_routes}
        target_dict = {self._get_route_key(route): route for route in target_routes}
        
        source_keys = set(source_dict.keys())
        target_keys = set(target_dict.keys())
        
        # Find added routes
        added_keys = target_keys - source_keys
        for key in added_keys:
            route = target_dict[key]
            risk_impact = self._assess_change_risk("ADDED", None, route)
            changes.append(RouteChange(
                change_type="ADDED",
                new_route=route,
                risk_impact=risk_impact,
                change_details={'reason': 'Route added in target directory'}
            ))
        
        # Find removed routes
        removed_keys = source_keys - target_keys
        for key in removed_keys:
            route = source_dict[key]
            risk_impact = self._assess_change_risk("REMOVED", route, None)
            changes.append(RouteChange(
                change_type="REMOVED",
                old_route=route,
                risk_impact=risk_impact,
                change_details={'reason': 'Route removed from source directory'}
            ))
        
        return changes
    
    def _apply_advanced_filtering(self, routes: List[RouteInfo], 
                                 config: ComparisonConfig) -> List[RouteInfo]:
        """
        Apply advanced filtering to routes using the new filtering engine.
        
        Args:
            routes: Routes to filter
            config: Comparison configuration with filters
            
        Returns:
            Filtered routes
        """
        try:
            from .advanced_filtering import AdvancedFilterEngine
            
            # Check if advanced filtering is requested
            if not hasattr(config, 'filters') or not config.filters:
                return routes
            
            filter_engine = AdvancedFilterEngine()
            
            # Parse filter string from config
            filter_string = getattr(config.filters, 'filter_string', '')
            if filter_string:
                criteria = filter_engine.parse_filter_string(filter_string)
                filtered_routes = filter_engine.apply_filters(routes, criteria)
                
                # Log filtering statistics
                stats = filter_engine.get_filter_statistics(routes, criteria)
                self.logger.info(f"Advanced filtering: {stats['filtered_routes']}/{stats['total_routes']} routes ({stats['filter_rate']:.1f}%)")
                
                return filtered_routes
            
            return routes
            
        except ImportError as e:
            self.logger.warning(f"Advanced filtering not available: {e}")
            # Fallback to existing filtering
            return self._apply_filters(routes, config)
        except Exception as e:
            self.logger.error(f"Error in advanced filtering: {e}")
            # Fallback to existing filtering
            return self._apply_filters(routes, config)
    
    def _get_route_key(self, route: RouteInfo) -> str:
        """
        Generate a unique key for route comparison.
        
        Args:
            route: Route to generate key for
            
        Returns:
            Unique string key for the route
        """
        method = route.method.value if hasattr(route.method, 'value') else str(route.method)
        
        # Clean and normalize the route path
        cleaned_path = self._normalize_route_path(route.path, route.file_path)
        
        # For directory comparison, we want to compare routes by method and cleaned path only
        # File path differences are expected between directories
        return f"{method}:{cleaned_path}"
    
    def _normalize_route_path(self, route_path: str, file_path: str) -> str:
        """
        Normalize route path for comparison, handling cases where file paths 
        are incorrectly assigned to route.path.
        
        Args:
            route_path: The route path (may be corrupted with file path)
            file_path: The actual file path
            
        Returns:
            Normalized route path suitable for comparison
        """
        import os
        from pathlib import Path
        
        # If route_path looks like a file path (contains directory separators and file extensions),
        # it's likely corrupted - try to extract a meaningful API path or mark as invalid
        if ('/' in route_path and 
            (route_path.endswith('.js') or route_path.endswith('.ts') or 
             route_path.endswith('.py') or route_path.endswith('.go') or
             'src/' in route_path or 'scripts/' in route_path or 'utils/' in route_path)):
            
            # This is likely a file path assigned to route.path by mistake
            # Extract relative path from the file_path for a more meaningful comparison
            try:
                # Get just the filename without extension as a fallback
                file_name = Path(file_path).stem
                self.logger.warning(f"Route path looks like file path: {route_path}, using filename: {file_name}")
                return f"/invalid-file-route/{file_name}"
            except:
                return "/invalid-route"
        
        # If route_path contains absolute directory paths (like /test-n8n/api-gateway/),
        # try to normalize it to relative path
        if route_path.startswith('/') and ('test-n8n' in route_path or 'api-gateway' in route_path):
            # Extract the API path part after common directory prefixes
            for prefix in ['/test-n8n/api-gateway/', '/test-n8n/api-gateway-1/', 
                          'test-n8n/api-gateway/', 'test-n8n/api-gateway-1/']:
                if prefix in route_path:
                    # This might be a file path, extract relative part
                    relative_part = route_path.split(prefix)[-1]
                    # If it still looks like a file path, mark as invalid
                    if ('/' in relative_part and 
                        (relative_part.endswith('.js') or 'src/' in relative_part or 'scripts/' in relative_part)):
                        file_name = Path(relative_part).stem
                        return f"/invalid-file-route/{file_name}"
                    else:
                        # Might be a valid API path, keep it but normalize
                        return f"/{relative_part}" if not relative_part.startswith('/') else relative_part
        
        # For valid API paths, ensure consistent format
        if not route_path.startswith('/') and route_path:
            route_path = f"/{route_path}"
        
        return route_path or "/unknown"
    
    def _filter_valid_routes(self, routes: List[RouteInfo], base_dir: str) -> List[RouteInfo]:
        """
        Filter out routes that are actually file paths mistaken as API routes.
        
        Args:
            routes: List of routes to filter
            base_dir: Base directory path for context
            
        Returns:
            Filtered list of valid API routes
        """
        valid_routes = []
        invalid_count = 0
        
        for route in routes:
            # Check if route.path looks like a file path
            if self._is_file_path_route(route.path, route.file_path):
                invalid_count += 1
                self.logger.debug(f"Filtering out file-path route: {route.method} {route.path}")
                continue
            
            # Check if it's a real API endpoint
            if self._is_valid_api_route(route.path):
                valid_routes.append(route)
            else:
                invalid_count += 1
                self.logger.debug(f"Filtering out invalid route: {route.method} {route.path}")
        
        if invalid_count > 0:
            self.logger.info(f"Filtered out {invalid_count} invalid file-path routes from {base_dir}")
        
        return valid_routes
    
    def _is_file_path_route(self, route_path: str, file_path: str) -> bool:
        """
        Check if a route path is actually a file path.
        
        Args:
            route_path: The route path to check
            file_path: The source file path
            
        Returns:
            True if route_path appears to be a file path
        """
        # Route path contains file extensions
        if route_path.endswith(('.js', '.ts', '.py', '.go', '.java', '.rb', '.php')):
            return True
        
        # Route path contains typical directory structures
        if any(dir_name in route_path for dir_name in ['src/', 'scripts/', 'utils/', 'lib/', 'dist/', 'build/']):
            return True
        
        # Route path contains the full directory structure from comparison
        if any(dir_name in route_path for dir_name in ['test-n8n/', 'api-gateway']):
            return True
        
        # Route path looks like a filesystem path (more than 3 directory levels)
        if route_path.count('/') > 4:  # e.g., /test-n8n/api-gateway/src/utils/something
            return True
        
        return False
    
    def _is_valid_api_route(self, route_path: str) -> bool:
        """
        Check if a route path looks like a valid API endpoint.
        
        Args:
            route_path: The route path to check
            
        Returns:
            True if route_path appears to be a valid API endpoint
        """
        # Empty or root path
        if not route_path or route_path == "/":
            return True
        
        # Must start with /
        if not route_path.startswith('/'):
            return False
        
        # Should not contain file extensions
        if route_path.endswith(('.js', '.ts', '.py', '.go', '.java', '.rb', '.php', '.html', '.css')):
            return False
        
        # Should not contain typical source code directory names
        if any(dir_name in route_path.lower() for dir_name in ['src', 'scripts', 'utils', 'lib', 'node_modules']):
            return False
        
        # Should look like an API path (contains typical API patterns)
        api_patterns = ['api/', 'auth/', 'users/', 'admin/', 'v1/', 'v2/', 'service/', 'graphql', 'webhook']
        if any(pattern in route_path.lower() for pattern in api_patterns):
            return True
        
        # Generic check: reasonable path length and structure
        path_parts = [part for part in route_path.split('/') if part]
        if len(path_parts) <= 5 and all(len(part) < 50 for part in path_parts):
            return True
        
        return False
    
    def _routes_differ(self, route1: RouteInfo, route2: RouteInfo) -> bool:
        """
        Check if two routes with the same key have different details.
        
        Args:
            route1: First route to compare
            route2: Second route to compare
            
        Returns:
            True if routes have differences
        """
        # Compare key attributes that might change
        return (
            route1.authenticated != route2.authenticated or
            route1.auth_type != route2.auth_type or
            route1.risk_score != route2.risk_score or
            len(route1.parameters) != len(route2.parameters) or
            route1.line_number != route2.line_number
        )
    
    def _analyze_route_differences(self, old_route: RouteInfo, new_route: RouteInfo) -> Dict[str, Any]:
        """
        Analyze specific differences between two routes.
        
        Args:
            old_route: Original route
            new_route: Modified route
            
        Returns:
            Dictionary of detected differences
        """
        differences = {}
        
        if old_route.authenticated != new_route.authenticated:
            differences['authentication_changed'] = {
                'old': old_route.authenticated,
                'new': new_route.authenticated
            }
        
        if old_route.auth_type != new_route.auth_type:
            differences['auth_type_changed'] = {
                'old': str(old_route.auth_type),
                'new': str(new_route.auth_type)
            }
        
        if old_route.risk_score != new_route.risk_score:
            differences['risk_score_changed'] = {
                'old': old_route.risk_score,
                'new': new_route.risk_score,
                'delta': new_route.risk_score - old_route.risk_score
            }
        
        if len(old_route.parameters) != len(new_route.parameters):
            differences['parameters_count_changed'] = {
                'old': len(old_route.parameters),
                'new': len(new_route.parameters)
            }
        
        if old_route.line_number != new_route.line_number:
            differences['line_number_changed'] = {
                'old': old_route.line_number,
                'new': new_route.line_number
            }
        
        return differences
    
    def _assess_change_risk(self, change_type: str, old_route: Optional[RouteInfo], 
                           new_route: Optional[RouteInfo]) -> RiskLevel:
        """
        Assess the security risk impact of a route change.
        
        Args:
            change_type: Type of change (ADDED, REMOVED, MODIFIED)
            old_route: Original route (if any)
            new_route: New route (if any)
            
        Returns:
            Risk level for this change
        """
        if change_type == "ADDED":
            if new_route and not new_route.authenticated:
                return RiskLevel.HIGH  # New unauthenticated endpoint
            return RiskLevel.MEDIUM
        
        elif change_type == "REMOVED":
            return RiskLevel.LOW  # Removing endpoints is generally lower risk
        
        elif change_type == "MODIFIED":
            if old_route and new_route:
                # Check if authentication was removed
                if old_route.authenticated and not new_route.authenticated:
                    return RiskLevel.HIGH
                # Check if risk score increased significantly
                if new_route.risk_score > old_route.risk_score + 2.0:
                    return RiskLevel.HIGH
                return RiskLevel.MEDIUM
        
        return RiskLevel.LOW
    
    def _analyze_file_changes(self, source_dir: Path, target_dir: Path) -> List[FileChange]:
        """
        Analyze file-level changes between directories.
        
        Args:
            source_dir: Source directory path
            target_dir: Target directory path
            
        Returns:
            List of file changes
        """
        self.logger.debug("Analyzing file-level changes")
        file_changes = []
        
        try:
            # Get all relevant files from both directories
            source_files = self._get_relevant_files(source_dir)
            target_files = self._get_relevant_files(target_dir)
            
            # Convert to relative paths for comparison
            source_rel_files = {f.relative_to(source_dir): f for f in source_files}
            target_rel_files = {f.relative_to(target_dir): f for f in target_files}
            
            source_rel_paths = set(source_rel_files.keys())
            target_rel_paths = set(target_rel_files.keys())
            
            # Find added files
            added_files = target_rel_paths - source_rel_paths
            for rel_path in added_files:
                file_changes.append(FileChange(
                    file_path=str(rel_path),
                    change_type="ADDED",
                    size_change=target_rel_files[rel_path].stat().st_size
                ))
            
            # Find removed files
            removed_files = source_rel_paths - target_rel_paths
            for rel_path in removed_files:
                file_changes.append(FileChange(
                    file_path=str(rel_path),
                    change_type="REMOVED",
                    size_change=-source_rel_files[rel_path].stat().st_size
                ))
            
            # Find modified files (simple size-based check for now)
            common_files = source_rel_paths & target_rel_paths
            for rel_path in common_files:
                source_size = source_rel_files[rel_path].stat().st_size
                target_size = target_rel_files[rel_path].stat().st_size
                
                if source_size != target_size:
                    file_changes.append(FileChange(
                        file_path=str(rel_path),
                        change_type="MODIFIED",
                        size_change=target_size - source_size
                    ))
            
            self.logger.debug(f"File analysis complete: {len(file_changes)} file changes found")
            
        except Exception as e:
            self.logger.error(f"Error analyzing file changes: {e}")
        
        return file_changes
    
    def _get_relevant_files(self, directory: Path) -> List[Path]:
        """
        Get list of relevant files for route detection.
        
        Args:
            directory: Directory to scan
            
        Returns:
            List of relevant file paths
        """
        relevant_extensions = {'.js', '.ts', '.py', '.go', '.java', '.jsx', '.tsx'}
        exclude_patterns = {'node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'venv'}
        
        files = []
        for file_path in directory.rglob('*'):
            if (file_path.is_file() and 
                file_path.suffix.lower() in relevant_extensions and
                not any(pattern in str(file_path) for pattern in exclude_patterns)):
                files.append(file_path)
        
        return files 