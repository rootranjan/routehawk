#!/usr/bin/env python3
"""
Enhanced Route Comparator for RouteHawk Phase 3

Advanced route comparison with remote repository integration, batch operations,
and enterprise features for large-scale deployment analysis.
"""

import asyncio
import logging
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from models import (
    RouteInfo, ComparisonResult, RouteChange, FileChange,
    ComparisonConfig, ComparisonFilter, RiskLevel
)
from analyzers.git_operations import GitOperations, GitConfig, AuthMethod, GitOperationError
from analyzers.directory_comparator import DirectoryComparator
from analyzers.remote_repository import RemoteRepository, RepositoryInfo, RepositoryPlatform

class BatchComparisonResult:
    """Results from batch comparison operations"""
    def __init__(self):
        self.comparisons: List[ComparisonResult] = []
        self.summary: Dict[str, Any] = {}
        self.errors: List[str] = []
        self.performance_metrics: Dict[str, Any] = {}

class EnhancedRouteComparator:
    """
    Enhanced route comparator with remote repository support and batch operations.
    
    Features:
    - Remote repository integration
    - Batch tag/branch comparisons
    - Performance optimizations
    - Enterprise reporting
    - API integration
    - Advanced filtering
    """
    
    def __init__(self, scanner, auth_config: Dict[str, str] = None):
        """
        Initialize enhanced route comparator.
        
        Args:
            scanner: AttackSurfaceScanner instance
            auth_config: Authentication configuration for remote repositories
        """
        self.scanner = scanner
        self.logger = logging.getLogger(__name__)
        self.auth_config = auth_config or {}
        self.remote_repo = RemoteRepository(auth_config)
        self.git_ops: Optional[GitOperations] = None
        self.performance_metrics = {}
    
    def compare_remote_repository(self, repo_url: str, source_ref: str, target_ref: str,
                                config: ComparisonConfig) -> ComparisonResult:
        """
        Compare routes between references in a remote repository.
        
        Args:
            repo_url: Remote repository URL
            source_ref: Source reference (tag, branch, commit)
            target_ref: Target reference (tag, branch, commit)
            config: Comparison configuration
            
        Returns:
            ComparisonResult with detailed analysis
        """
        start_time = datetime.now()
        self.logger.info(f"Starting remote repository comparison: {repo_url}")
        
        try:
            # Parse and validate repository
            repo_info = self.remote_repo.parse_repository_url(repo_url)
            
            if not self.remote_repo.validate_remote_access(repo_info):
                raise GitOperationError(f"Cannot access remote repository: {repo_url}")
            
            # Get repository metadata for optimization
            repo_info = self.remote_repo.get_repository_metadata(repo_info)
            self.logger.info(f"Repository metadata: {len(repo_info.tags)} tags, {len(repo_info.branches)} branches")
            
            # Get optimal cloning strategy
            clone_strategy = self.remote_repo.get_optimal_clone_strategy(repo_info)
            self.logger.info(f"Clone strategy: {clone_strategy}")
            
            # Create git configuration
            git_config = self._create_enhanced_git_config(config, repo_info)
            
            with GitOperations(git_config) as git_ops:
                self.git_ops = git_ops
                
                # Create temporary workspaces
                source_workspace = git_ops.create_temp_workspace()
                target_workspace = git_ops.create_temp_workspace()
                
                # Clone repository to workspaces with optimized strategy
                self._clone_with_strategy(repo_info, source_workspace, source_ref, clone_strategy)
                self._clone_with_strategy(repo_info, target_workspace, target_ref, clone_strategy)
                
                # Compare directories using existing comparator
                comparator = DirectoryComparator(self.scanner)
                
                # Enhanced comparison configuration
                enhanced_config = ComparisonConfig(
                    comparison_type=f"remote_{config.comparison_type}",
                    source=source_ref,
                    target=target_ref,
                    filters=config.filters,
                    diff_algorithm=config.diff_algorithm,
                    include_file_changes=config.include_file_changes,
                    include_risk_analysis=config.include_risk_analysis,
                    auth_method=config.auth_method
                )
                
                result = comparator.compare_directories(
                    source_workspace,
                    target_workspace,
                    enhanced_config
                )
                
                # Enhance result with remote repository metadata
                result = self._enhance_result_with_metadata(result, repo_info, source_ref, target_ref)
                
                # Add performance metrics
                end_time = datetime.now()
                self.performance_metrics['comparison_duration'] = (end_time - start_time).total_seconds()
                result.scan_metadata.update({
                    'performance_metrics': self.performance_metrics,
                    'clone_strategy': clone_strategy,
                    'remote_platform': repo_info.platform.value
                })
                
                self.logger.info(f"Remote comparison completed in {self.performance_metrics['comparison_duration']:.2f}s")
                return result
                
        except Exception as e:
            self.logger.error(f"Remote repository comparison failed: {e}")
            return ComparisonResult(
                source_version=f"remote:{source_ref}",
                target_version=f"remote:{target_ref}",
                comparison_type="remote_error",
                errors=[str(e)]
            )
    
    def batch_compare_tags(self, repo_url: str, tag_pairs: List[Tuple[str, str]],
                          config: ComparisonConfig) -> BatchComparisonResult:
        """
        Compare multiple tag pairs in batch for comprehensive analysis.
        
        Args:
            repo_url: Remote repository URL
            tag_pairs: List of (source_tag, target_tag) tuples
            config: Comparison configuration
            
        Returns:
            BatchComparisonResult with all comparisons
        """
        self.logger.info(f"Starting batch tag comparison: {len(tag_pairs)} pairs")
        start_time = datetime.now()
        
        batch_result = BatchComparisonResult()
        
        try:
            # Parse repository once
            repo_info = self.remote_repo.parse_repository_url(repo_url)
            repo_info = self.remote_repo.get_repository_metadata(repo_info)
            
            # Validate all tags exist
            available_tags = set(repo_info.tags)
            for source_tag, target_tag in tag_pairs:
                if source_tag not in available_tags:
                    batch_result.errors.append(f"Tag not found: {source_tag}")
                if target_tag not in available_tags:
                    batch_result.errors.append(f"Tag not found: {target_tag}")
            
            if batch_result.errors:
                return batch_result
            
            # Parallel execution for batch operations
            max_workers = min(len(tag_pairs), 3)  # Limit concurrent operations
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all comparison tasks
                future_to_tags = {
                    executor.submit(
                        self.compare_remote_repository,
                        repo_url, source_tag, target_tag, config
                    ): (source_tag, target_tag)
                    for source_tag, target_tag in tag_pairs
                }
                
                # Collect results
                for future in as_completed(future_to_tags):
                    source_tag, target_tag = future_to_tags[future]
                    try:
                        comparison_result = future.result()
                        batch_result.comparisons.append(comparison_result)
                        self.logger.info(f"Completed comparison: {source_tag} -> {target_tag}")
                    except Exception as e:
                        error_msg = f"Failed comparison {source_tag} -> {target_tag}: {e}"
                        batch_result.errors.append(error_msg)
                        self.logger.error(error_msg)
            
            # Generate batch summary
            batch_result.summary = self._generate_batch_summary(batch_result.comparisons)
            
            # Performance metrics
            end_time = datetime.now()
            batch_result.performance_metrics = {
                'total_duration': (end_time - start_time).total_seconds(),
                'comparisons_count': len(batch_result.comparisons),
                'average_duration': batch_result.performance_metrics.get('total_duration', 0) / max(len(batch_result.comparisons), 1),
                'parallel_workers': max_workers
            }
            
            self.logger.info(f"Batch comparison completed: {len(batch_result.comparisons)} successful, {len(batch_result.errors)} errors")
            return batch_result
            
        except Exception as e:
            batch_result.errors.append(f"Batch comparison failed: {e}")
            return batch_result
    
    def compare_release_progression(self, repo_url: str, tags: List[str],
                                  config: ComparisonConfig) -> BatchComparisonResult:
        """
        Compare release progression across multiple versions.
        
        Args:
            repo_url: Remote repository URL
            tags: List of tags in chronological order
            config: Comparison configuration
            
        Returns:
            BatchComparisonResult showing progression analysis
        """
        if len(tags) < 2:
            raise ValueError("At least 2 tags required for progression analysis")
        
        self.logger.info(f"Analyzing release progression: {' -> '.join(tags)}")
        
        # Create tag pairs for consecutive comparisons
        tag_pairs = [(tags[i], tags[i + 1]) for i in range(len(tags) - 1)]
        
        # Use batch comparison for efficiency
        batch_result = self.batch_compare_tags(repo_url, tag_pairs, config)
        
        # Enhance with progression-specific analysis
        if batch_result.comparisons:
            batch_result.summary['progression_analysis'] = self._analyze_progression(batch_result.comparisons, tags)
        
        return batch_result
    
    def discover_and_compare_latest_tags(self, repo_url: str, count: int,
                                       config: ComparisonConfig) -> BatchComparisonResult:
        """
        Discover latest tags and compare them automatically.
        
        Args:
            repo_url: Remote repository URL
            count: Number of latest tags to compare
            config: Comparison configuration
            
        Returns:
            BatchComparisonResult with latest tag comparisons
        """
        self.logger.info(f"Discovering and comparing {count} latest tags")
        
        try:
            # Get repository metadata
            repo_info = self.remote_repo.parse_repository_url(repo_url)
            repo_info = self.remote_repo.get_repository_metadata(repo_info)
            
            if len(repo_info.tags) < count:
                raise ValueError(f"Repository only has {len(repo_info.tags)} tags, requested {count}")
            
            # Sort tags (basic semver-like sorting)
            sorted_tags = self._sort_tags_semantically(repo_info.tags)
            latest_tags = sorted_tags[-count:]
            
            self.logger.info(f"Latest tags discovered: {latest_tags}")
            
            # Compare consecutive pairs
            return self.compare_release_progression(repo_url, latest_tags, config)
            
        except Exception as e:
            batch_result = BatchComparisonResult()
            batch_result.errors.append(f"Failed to discover latest tags: {e}")
            return batch_result
    
    def _clone_with_strategy(self, repo_info: RepositoryInfo, workspace: str, 
                           ref: str, strategy: Dict[str, Any]):
        """Clone repository with optimized strategy"""
        clone_url = strategy.get('clone_url', repo_info.clone_url_https)
        depth = strategy.get('depth', 1)
        
        # Determine if ref is tag or branch
        if ref in repo_info.tags:
            # Clone tag
            self.git_ops.clone_repository(clone_url, workspace, tag=ref, depth=depth)
        elif ref in repo_info.branches:
            # Clone branch
            self.git_ops.clone_repository(clone_url, workspace, branch=ref, depth=depth)
        else:
            # Try as commit or generic ref
            self.git_ops.clone_repository(clone_url, workspace, depth=depth)
            # Checkout specific ref
            try:
                self.git_ops.checkout_tag(workspace, ref)
            except:
                self.git_ops.checkout_branch(workspace, ref)
    
    def _create_enhanced_git_config(self, config: ComparisonConfig, 
                                  repo_info: RepositoryInfo) -> GitConfig:
        """Create enhanced git configuration with platform optimizations"""
        auth_method_map = {
            'auto': AuthMethod.AUTO,
            'ssh': AuthMethod.SSH,
            'token': AuthMethod.TOKEN,
            'oauth': AuthMethod.OAUTH,
            'none': AuthMethod.NONE
        }
        
        git_config = GitConfig(
            auth_method=auth_method_map.get(config.auth_method, AuthMethod.AUTO),
            timeout=600,  # Increased timeout for remote operations
        )
        
        # Platform-specific configuration
        if repo_info.platform == RepositoryPlatform.GITHUB and 'github_token' in self.auth_config:
            git_config.token = self.auth_config['github_token']
            git_config.username = self.auth_config.get('github_username', 'token')
        elif repo_info.platform == RepositoryPlatform.GITLAB and 'gitlab_token' in self.auth_config:
            git_config.token = self.auth_config['gitlab_token']
            git_config.username = self.auth_config.get('gitlab_username', 'oauth2')
        
        return git_config
    
    def _enhance_result_with_metadata(self, result: ComparisonResult, repo_info: RepositoryInfo,
                                    source_ref: str, target_ref: str) -> ComparisonResult:
        """Enhance comparison result with remote repository metadata"""
        result.scan_metadata.update({
            'remote_repository': {
                'url': repo_info.url,
                'platform': repo_info.platform.value,
                'owner': repo_info.owner,
                'repo': repo_info.repo,
                'is_private': repo_info.is_private,
                'default_branch': repo_info.default_branch
            },
            'repository_metadata': repo_info.metadata,
            'source_reference': source_ref,
            'target_reference': target_ref,
            'available_tags': len(repo_info.tags),
            'available_branches': len(repo_info.branches)
        })
        
        return result
    
    def _generate_batch_summary(self, comparisons: List[ComparisonResult]) -> Dict[str, Any]:
        """Generate summary statistics for batch comparisons"""
        if not comparisons:
            return {}
        
        total_changes = sum(len(comp.changes) for comp in comparisons)
        total_files = sum(len(comp.file_changes) for comp in comparisons)
        
        change_types = {}
        for comp in comparisons:
            for change in comp.changes:
                change_type = change.change_type
                change_types[change_type] = change_types.get(change_type, 0) + 1
        
        return {
            'total_comparisons': len(comparisons),
            'total_route_changes': total_changes,
            'total_file_changes': total_files,
            'average_changes_per_comparison': total_changes / len(comparisons),
            'change_type_distribution': change_types,
            'comparison_types': list(set(comp.comparison_type for comp in comparisons))
        }
    
    def _analyze_progression(self, comparisons: List[ComparisonResult], tags: List[str]) -> Dict[str, Any]:
        """Analyze progression patterns across releases"""
        progression = {
            'release_sequence': tags,
            'cumulative_changes': 0,
            'change_velocity': [],
            'stability_metrics': {},
            'risk_progression': []
        }
        
        cumulative = 0
        for i, comp in enumerate(comparisons):
            changes_count = len(comp.changes)
            cumulative += changes_count
            
            progression['change_velocity'].append({
                'from_version': tags[i],
                'to_version': tags[i + 1],
                'changes': changes_count,
                'cumulative': cumulative
            })
            
            # Analyze risk progression
            high_risk_changes = sum(1 for change in comp.changes 
                                  if hasattr(change, 'risk_level') and change.risk_level == RiskLevel.HIGH)
            progression['risk_progression'].append({
                'version': tags[i + 1],
                'high_risk_changes': high_risk_changes,
                'total_changes': changes_count
            })
        
        progression['cumulative_changes'] = cumulative
        
        # Calculate stability metrics
        change_counts = [len(comp.changes) for comp in comparisons]
        if change_counts:
            progression['stability_metrics'] = {
                'average_changes_per_release': sum(change_counts) / len(change_counts),
                'max_changes_in_release': max(change_counts),
                'min_changes_in_release': min(change_counts),
                'release_stability_score': self._calculate_stability_score(change_counts)
            }
        
        return progression
    
    def _calculate_stability_score(self, change_counts: List[int]) -> float:
        """Calculate stability score based on change patterns"""
        if not change_counts:
            return 0.0
        
        # Lower variance = higher stability
        mean_changes = sum(change_counts) / len(change_counts)
        variance = sum((x - mean_changes) ** 2 for x in change_counts) / len(change_counts)
        
        # Normalize to 0-100 scale (higher = more stable)
        stability_score = max(0, 100 - (variance / max(mean_changes, 1)) * 10)
        return round(stability_score, 2)
    
    def _sort_tags_semantically(self, tags: List[str]) -> List[str]:
        """Sort tags using semantic versioning rules"""
        def tag_sort_key(tag):
            # Remove 'v' prefix if present
            tag_clean = tag.lstrip('v')
            
            # Try to parse as semantic version
            parts = tag_clean.split('.')
            try:
                # Convert to integers for proper sorting
                return tuple(int(part) for part in parts[:3])  # major.minor.patch
            except ValueError:
                # Fallback to string sorting
                return (0, 0, 0, tag)
        
        return sorted(tags, key=tag_sort_key) 