#!/usr/bin/env python3
"""
Route Comparator for RouteHawk

Compares routes between git tags, branches, and commits using the GitOperations
module for repository management and the DirectoryComparator for analysis.
"""

import os
import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime

from models import (
    RouteInfo, ComparisonResult, RouteChange, FileChange,
    ComparisonConfig, ComparisonFilter, RiskLevel
)
from analyzers.git_operations import GitOperations, GitConfig, AuthMethod, GitOperationError
from analyzers.directory_comparator import DirectoryComparator

class RouteComparator:
    """
    Compare routes between git references (tags, branches, commits).
    
    Features:
    - Git tag comparison (v1.0.0 vs v2.0.0)
    - Branch comparison (main vs develop)
    - Current vs tag comparison
    - Multiple diff algorithms (strict, fuzzy, hybrid)
    - Advanced filtering by framework, method, path
    - File-level change tracking
    - Risk assessment for route changes
    """
    
    def __init__(self, scanner):
        """
        Initialize the route comparator.
        
        Args:
            scanner: AttackSurfaceScanner instance for route detection
        """
        self.scanner = scanner
        self.logger = logging.getLogger(__name__)
        self.git_ops: Optional[GitOperations] = None
    
    def compare_tags(self, repo_path: str, source_tag: str, target_tag: str,
                    config: ComparisonConfig) -> ComparisonResult:
        """
        Compare routes between two git tags.
        
        Args:
            repo_path: Path to git repository
            source_tag: Source tag (e.g., "v1.0.0")
            target_tag: Target tag (e.g., "v2.0.0")
            config: Comparison configuration
            
        Returns:
            ComparisonResult with detailed analysis
        """
        self.logger.info(f"Comparing tags: {source_tag} -> {target_tag}")
        
        git_config = self._create_git_config(config)
        
        with GitOperations(git_config) as git_ops:
            self.git_ops = git_ops
            
            try:
                # Validate repository
                if not git_ops.is_git_repository(repo_path):
                    raise GitOperationError(f"Not a git repository: {repo_path}")
                
                # Get repository info
                repo_info = git_ops.get_repository_info(repo_path)
                self.logger.info(f"Repository info: {repo_info}")
                
                # Create temporary workspaces for each tag
                source_workspace = git_ops.create_temp_workspace()
                target_workspace = git_ops.create_temp_workspace()
                
                # Clone or copy repository to workspaces
                if repo_info.get('url'):
                    # Remote repository - clone each tag
                    git_ops.clone_repository(repo_info['url'], source_workspace, tag=source_tag)
                    git_ops.clone_repository(repo_info['url'], target_workspace, tag=target_tag)
                else:
                    # Local repository - copy and checkout
                    self._copy_and_checkout(repo_path, source_workspace, source_tag)
                    self._copy_and_checkout(repo_path, target_workspace, target_tag)
                
                # Compare directories using DirectoryComparator
                comparator = DirectoryComparator(self.scanner)
                
                # Create directory comparison config
                dir_config = ComparisonConfig(
                    comparison_type="tags",
                    source=source_tag,
                    target=target_tag,
                    filters=config.filters,
                    diff_algorithm=config.diff_algorithm,
                    include_file_changes=config.include_file_changes,
                    include_risk_analysis=config.include_risk_analysis
                )
                
                result = comparator.compare_directories(
                    source_workspace,
                    target_workspace,
                    dir_config
                )
                
                # Update result with git-specific metadata
                result.source_version = f"tag:{source_tag}"
                result.target_version = f"tag:{target_tag}"
                result.comparison_type = "tags"
                result.scan_metadata.update({
                    'git_repository': repo_info.get('url', repo_path),
                    'source_tag': source_tag,
                    'target_tag': target_tag,
                    'repository_type': 'remote' if repo_info.get('url') else 'local'
                })
                
                self.logger.info(f"Tag comparison completed: {len(result.changes)} changes found")
                return result
                
            except Exception as e:
                self.logger.error(f"Error comparing tags: {e}")
                return ComparisonResult(
                    source_version=f"tag:{source_tag}",
                    target_version=f"tag:{target_tag}",
                    comparison_type="tags",
                    errors=[str(e)]
                )
    
    def compare_branches(self, repo_path: str, source_branch: str, target_branch: str,
                        config: ComparisonConfig) -> ComparisonResult:
        """
        Compare routes between two git branches.
        
        Args:
            repo_path: Path to git repository
            source_branch: Source branch (e.g., "main")
            target_branch: Target branch (e.g., "develop")
            config: Comparison configuration
            
        Returns:
            ComparisonResult with detailed analysis
        """
        self.logger.info(f"Comparing branches: {source_branch} -> {target_branch}")
        
        git_config = self._create_git_config(config)
        
        with GitOperations(git_config) as git_ops:
            self.git_ops = git_ops
            
            try:
                # Validate repository
                if not git_ops.is_git_repository(repo_path):
                    raise GitOperationError(f"Not a git repository: {repo_path}")
                
                # Get repository info
                repo_info = git_ops.get_repository_info(repo_path)
                
                # Create temporary workspaces for each branch
                source_workspace = git_ops.create_temp_workspace()
                target_workspace = git_ops.create_temp_workspace()
                
                # Clone or copy repository to workspaces
                if repo_info.get('url'):
                    # Remote repository - clone each branch
                    git_ops.clone_repository(repo_info['url'], source_workspace, branch=source_branch)
                    git_ops.clone_repository(repo_info['url'], target_workspace, branch=target_branch)
                else:
                    # Local repository - copy and checkout
                    self._copy_and_checkout(repo_path, source_workspace, source_branch)
                    self._copy_and_checkout(repo_path, target_workspace, target_branch)
                
                # Compare directories
                comparator = DirectoryComparator(self.scanner)
                
                dir_config = ComparisonConfig(
                    comparison_type="branches",
                    source=source_branch,
                    target=target_branch,
                    filters=config.filters,
                    diff_algorithm=config.diff_algorithm,
                    include_file_changes=config.include_file_changes,
                    include_risk_analysis=config.include_risk_analysis
                )
                
                result = comparator.compare_directories(
                    source_workspace,
                    target_workspace,
                    dir_config
                )
                
                # Update result with git-specific metadata
                result.source_version = f"branch:{source_branch}"
                result.target_version = f"branch:{target_branch}"
                result.comparison_type = "branches"
                result.scan_metadata.update({
                    'git_repository': repo_info.get('url', repo_path),
                    'source_branch': source_branch,
                    'target_branch': target_branch,
                    'repository_type': 'remote' if repo_info.get('url') else 'local'
                })
                
                self.logger.info(f"Branch comparison completed: {len(result.changes)} changes found")
                return result
                
            except Exception as e:
                self.logger.error(f"Error comparing branches: {e}")
                return ComparisonResult(
                    source_version=f"branch:{source_branch}",
                    target_version=f"branch:{target_branch}",
                    comparison_type="branches",
                    errors=[str(e)]
                )
    
    def compare_against_tag(self, repo_path: str, tag: str, config: ComparisonConfig) -> ComparisonResult:
        """
        Compare current repository state against a specific tag.
        
        Args:
            repo_path: Path to git repository
            tag: Tag to compare against (e.g., "v1.0.0")
            config: Comparison configuration
            
        Returns:
            ComparisonResult with detailed analysis
        """
        self.logger.info(f"Comparing current state against tag: {tag}")
        
        git_config = self._create_git_config(config)
        
        with GitOperations(git_config) as git_ops:
            self.git_ops = git_ops
            
            try:
                # Validate repository
                if not git_ops.is_git_repository(repo_path):
                    raise GitOperationError(f"Not a git repository: {repo_path}")
                
                # Get current repository info
                repo_info = git_ops.get_repository_info(repo_path)
                current_ref = f"{repo_info.get('branch', 'unknown')}@{repo_info.get('commit', 'unknown')}"
                
                # Create workspace for tag
                tag_workspace = git_ops.create_temp_workspace()
                
                # Clone or copy repository to workspace
                if repo_info.get('url'):
                    # Remote repository - clone tag
                    git_ops.clone_repository(repo_info['url'], tag_workspace, tag=tag)
                else:
                    # Local repository - copy and checkout tag
                    self._copy_and_checkout(repo_path, tag_workspace, tag)
                
                # Compare current directory against tag workspace
                comparator = DirectoryComparator(self.scanner)
                
                dir_config = ComparisonConfig(
                    comparison_type="against_tag",
                    source=tag,
                    target="current",
                    filters=config.filters,
                    diff_algorithm=config.diff_algorithm,
                    include_file_changes=config.include_file_changes,
                    include_risk_analysis=config.include_risk_analysis
                )
                
                result = comparator.compare_directories(
                    tag_workspace,
                    repo_path,
                    dir_config
                )
                
                # Update result with git-specific metadata
                result.source_version = f"tag:{tag}"
                result.target_version = f"current:{current_ref}"
                result.comparison_type = "against_tag"
                result.scan_metadata.update({
                    'git_repository': repo_info.get('url', repo_path),
                    'base_tag': tag,
                    'current_branch': repo_info.get('branch'),
                    'current_commit': repo_info.get('commit'),
                    'repository_type': 'remote' if repo_info.get('url') else 'local'
                })
                
                self.logger.info(f"Against-tag comparison completed: {len(result.changes)} changes found")
                return result
                
            except Exception as e:
                self.logger.error(f"Error comparing against tag: {e}")
                return ComparisonResult(
                    source_version=f"tag:{tag}",
                    target_version="current",
                    comparison_type="against_tag",
                    errors=[str(e)]
                )
    
    def _create_git_config(self, config: ComparisonConfig) -> GitConfig:
        """
        Create GitConfig from ComparisonConfig.
        
        Args:
            config: Comparison configuration
            
        Returns:
            GitConfig for git operations
        """
        auth_method_map = {
            'auto': AuthMethod.AUTO,
            'ssh': AuthMethod.SSH,
            'token': AuthMethod.TOKEN,
            'oauth': AuthMethod.OAUTH,
            'none': AuthMethod.NONE
        }
        
        return GitConfig(
            auth_method=auth_method_map.get(config.auth_method, AuthMethod.AUTO),
            timeout=300,  # 5 minutes default
        )
    
    def _copy_and_checkout(self, source_repo: str, target_workspace: str, ref: str):
        """
        Copy repository and checkout specific reference.
        
        Args:
            source_repo: Source repository path
            target_workspace: Target workspace path
            ref: Git reference (tag, branch, commit)
        """
        try:
            import shutil
            
            # Ensure target workspace is clean
            if os.path.exists(target_workspace):
                shutil.rmtree(target_workspace)
            
            # Copy repository
            shutil.copytree(source_repo, target_workspace)
            
            # Checkout reference
            if self.git_ops:
                # Try as tag first, then as branch
                try:
                    self.git_ops.checkout_tag(target_workspace, ref)
                    self.logger.info(f"Successfully checked out tag: {ref}")
                except Exception:
                    try:
                        self.git_ops.checkout_branch(target_workspace, ref)
                        self.logger.info(f"Successfully checked out branch: {ref}")
                    except Exception as e:
                        self.logger.warning(f"Could not checkout {ref}: {e}")
            
        except Exception as e:
            raise GitOperationError(f"Failed to copy and checkout {ref}: {e}")
    
    def get_available_tags(self, repo_path: str) -> List[str]:
        """
        Get list of available tags in repository.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            List of tag names
        """
        git_config = GitConfig()
        
        with GitOperations(git_config) as git_ops:
            try:
                return git_ops.get_tags(repo_path)
            except Exception as e:
                self.logger.error(f"Failed to get tags: {e}")
                return []
    
    def get_available_branches(self, repo_path: str, include_remote: bool = False) -> List[str]:
        """
        Get list of available branches in repository.
        
        Args:
            repo_path: Path to repository
            include_remote: Include remote branches
            
        Returns:
            List of branch names
        """
        git_config = GitConfig()
        
        with GitOperations(git_config) as git_ops:
            try:
                return git_ops.get_branches(repo_path, remote=include_remote)
            except Exception as e:
                self.logger.error(f"Failed to get branches: {e}")
                return [] 

    def _enhance_with_diff_algorithms(self, config: ComparisonConfig, 
                                    source_routes: List[RouteInfo], 
                                    target_routes: List[RouteInfo]) -> List[RouteChange]:
        """
        Use advanced diff algorithms for route comparison.
        
        Args:
            config: Comparison configuration
            source_routes: Source routes
            target_routes: Target routes
            
        Returns:
            List of route changes detected by advanced algorithms
        """
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
            self.logger.info(f"Diff algorithm metrics: {diff_engine.metrics}")
        
        return changes
    
    def _apply_advanced_filtering(self, routes: List[RouteInfo], 
                                config: ComparisonConfig) -> List[RouteInfo]:
        """
        Apply advanced filtering to routes.
        
        Args:
            routes: Routes to filter
            config: Comparison configuration with filters
            
        Returns:
            Filtered routes
        """
        from .advanced_filtering import AdvancedFilterEngine
        
        if not config.filters or not hasattr(config.filters, 'filter_string'):
            return routes
        
        filter_engine = AdvancedFilterEngine()
        
        # Parse filter string from config
        filter_string = getattr(config.filters, 'filter_string', '')
        if filter_string:
            criteria = filter_engine.parse_filter_string(filter_string)
            filtered_routes = filter_engine.apply_filters(routes, criteria)
            
            # Log filtering statistics
            stats = filter_engine.get_filter_statistics(routes, criteria)
            self.logger.info(f"Filtering: {stats['filtered_routes']}/{stats['total_routes']} routes ({stats['filter_rate']:.1f}%)")
            
            return filtered_routes
        
        return routes
    
    def _track_file_changes(self, source_workspace: str, target_workspace: str,
                          source_routes: List[RouteInfo], target_routes: List[RouteInfo],
                          config: ComparisonConfig) -> List[FileChange]:
        """
        Track file-level changes between workspaces.
        
        Args:
            source_workspace: Source workspace directory
            target_workspace: Target workspace directory
            source_routes: Source routes
            target_routes: Target routes
            config: Comparison configuration
            
        Returns:
            List of file changes
        """
        from .file_change_tracker import FileChangeTracker
        
        if not config.include_file_changes:
            return []
        
        tracker = FileChangeTracker()
        file_changes = tracker.track_directory_changes(
            source_workspace, target_workspace, source_routes, target_routes
        )
        
        # Convert FileChangeDetail to FileChange for compatibility
        converted_changes = []
        for detail in file_changes:
            file_change = FileChange(
                file_path=detail.file_path,
                change_type=detail.change_type.value,
                lines_added=detail.lines_added,
                lines_removed=detail.lines_removed,
                similarity_score=detail.content_similarity,
                impact_score=tracker.calculate_file_impact_score(detail)
            )
            converted_changes.append(file_change)
        
        # Log file change statistics
        stats = tracker.get_change_statistics(file_changes)
        self.logger.info(f"File changes: {stats.total_files_changed} files, {stats.routes_affected} routes affected")
        
        return converted_changes 