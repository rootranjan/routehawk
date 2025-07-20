#!/usr/bin/env python3
"""
Remote Repository Integration for RouteHawk

Handles remote repository operations including URL parsing, platform detection,
API integration, and advanced remote repository features for enterprise use.
"""

import re
import json
import logging
import requests
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse
import os

class RepositoryPlatform(Enum):
    """Supported repository platforms"""
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"
    AZURE_DEVOPS = "azure_devops"
    GITEA = "gitea"
    LOCAL = "local"
    UNKNOWN = "unknown"

@dataclass
class RepositoryInfo:
    """Complete repository information"""
    url: str
    platform: RepositoryPlatform
    owner: str
    repo: str
    is_private: bool = False
    default_branch: str = "main"
    clone_url_https: str = ""
    clone_url_ssh: str = ""
    tags: List[str] = None
    branches: List[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.branches is None:
            self.branches = []
        if self.metadata is None:
            self.metadata = {}

class RemoteRepositoryError(Exception):
    """Custom exception for remote repository errors"""
    pass

class RemoteRepository:
    """
    Handle remote repository operations with platform-specific optimizations.
    
    Features:
    - URL parsing and platform detection
    - GitHub/GitLab API integration
    - Batch tag/branch operations
    - Credential management
    - Performance optimization
    - Enterprise features
    """
    
    def __init__(self, auth_config: Dict[str, str] = None):
        """
        Initialize remote repository handler.
        
        Args:
            auth_config: Authentication configuration
        """
        self.logger = logging.getLogger(__name__)
        self.auth_config = auth_config or {}
        self.session = requests.Session()
        self._setup_session()
    
    def _setup_session(self):
        """Setup HTTP session with appropriate headers and auth"""
        self.session.headers.update({
            'User-Agent': 'RouteHawk-Security-Scanner/3.0',
            'Accept': 'application/vnd.github.v3+json',
        })
        
        # Add authentication if available
        if 'github_token' in self.auth_config:
            self.session.headers['Authorization'] = f"token {self.auth_config['github_token']}"
        elif 'gitlab_token' in self.auth_config:
            self.session.headers['PRIVATE-TOKEN'] = self.auth_config['gitlab_token']
    
    def parse_repository_url(self, url: str) -> RepositoryInfo:
        """
        Parse repository URL and extract platform-specific information.
        
        Args:
            url: Repository URL (HTTPS or SSH)
            
        Returns:
            RepositoryInfo with parsed details
            
        Raises:
            RemoteRepositoryError: If URL parsing fails
        """
        self.logger.info(f"Parsing repository URL: {url}")
        
        # Local path check
        if not url.startswith(('http', 'git@', 'ssh://')):
            return RepositoryInfo(
                url=url,
                platform=RepositoryPlatform.LOCAL,
                owner="local",
                repo=os.path.basename(url.rstrip('/'))
            )
        
        try:
            # GitHub patterns
            github_patterns = [
                r'https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$',
                r'git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$',
                r'ssh://git@github\.com/([^/]+)/([^/]+?)(?:\.git)?$'
            ]
            
            for pattern in github_patterns:
                match = re.match(pattern, url)
                if match:
                    owner, repo = match.groups()
                    return RepositoryInfo(
                        url=url,
                        platform=RepositoryPlatform.GITHUB,
                        owner=owner,
                        repo=repo,
                        clone_url_https=f"https://github.com/{owner}/{repo}.git",
                        clone_url_ssh=f"git@github.com:{owner}/{repo}.git"
                    )
            
            # GitLab patterns
            gitlab_patterns = [
                r'https://gitlab\.com/([^/]+)/([^/]+?)(?:\.git)?/?$',
                r'git@gitlab\.com:([^/]+)/([^/]+?)(?:\.git)?$',
                r'ssh://git@gitlab\.com/([^/]+)/([^/]+?)(?:\.git)?$'
            ]
            
            for pattern in gitlab_patterns:
                match = re.match(pattern, url)
                if match:
                    owner, repo = match.groups()
                    return RepositoryInfo(
                        url=url,
                        platform=RepositoryPlatform.GITLAB,
                        owner=owner,
                        repo=repo,
                        clone_url_https=f"https://gitlab.com/{owner}/{repo}.git",
                        clone_url_ssh=f"git@gitlab.com:{owner}/{repo}.git"
                    )
            
            # Bitbucket patterns
            bitbucket_patterns = [
                r'https://bitbucket\.org/([^/]+)/([^/]+?)(?:\.git)?/?$',
                r'git@bitbucket\.org:([^/]+)/([^/]+?)(?:\.git)?$'
            ]
            
            for pattern in bitbucket_patterns:
                match = re.match(pattern, url)
                if match:
                    owner, repo = match.groups()
                    return RepositoryInfo(
                        url=url,
                        platform=RepositoryPlatform.BITBUCKET,
                        owner=owner,
                        repo=repo,
                        clone_url_https=f"https://bitbucket.org/{owner}/{repo}.git",
                        clone_url_ssh=f"git@bitbucket.org:{owner}/{repo}.git"
                    )
            
            # Generic Git URL parsing
            parsed = urlparse(url)
            if parsed.netloc and parsed.path:
                path_parts = parsed.path.strip('/').split('/')
                if len(path_parts) >= 2:
                    owner, repo = path_parts[0], path_parts[1].replace('.git', '')
                    return RepositoryInfo(
                        url=url,
                        platform=RepositoryPlatform.UNKNOWN,
                        owner=owner,
                        repo=repo
                    )
            
            raise RemoteRepositoryError(f"Unable to parse repository URL: {url}")
            
        except Exception as e:
            raise RemoteRepositoryError(f"Failed to parse repository URL {url}: {e}")
    
    def get_repository_metadata(self, repo_info: RepositoryInfo) -> RepositoryInfo:
        """
        Fetch repository metadata from platform APIs.
        
        Args:
            repo_info: Basic repository information
            
        Returns:
            Enhanced RepositoryInfo with metadata
        """
        self.logger.info(f"Fetching metadata for {repo_info.platform.value} repository: {repo_info.owner}/{repo_info.repo}")
        
        try:
            if repo_info.platform == RepositoryPlatform.GITHUB:
                return self._get_github_metadata(repo_info)
            elif repo_info.platform == RepositoryPlatform.GITLAB:
                return self._get_gitlab_metadata(repo_info)
            elif repo_info.platform == RepositoryPlatform.BITBUCKET:
                return self._get_bitbucket_metadata(repo_info)
            else:
                self.logger.warning(f"Metadata fetching not supported for platform: {repo_info.platform.value}")
                return repo_info
                
        except Exception as e:
            self.logger.error(f"Failed to fetch metadata: {e}")
            return repo_info
    
    def _get_github_metadata(self, repo_info: RepositoryInfo) -> RepositoryInfo:
        """Fetch GitHub repository metadata"""
        try:
            # Repository info
            repo_url = f"https://api.github.com/repos/{repo_info.owner}/{repo_info.repo}"
            repo_response = self.session.get(repo_url)
            
            if repo_response.status_code == 200:
                repo_data = repo_response.json()
                repo_info.is_private = repo_data.get('private', False)
                repo_info.default_branch = repo_data.get('default_branch', 'main')
                repo_info.metadata = {
                    'description': repo_data.get('description', ''),
                    'language': repo_data.get('language', ''),
                    'stars': repo_data.get('stargazers_count', 0),
                    'forks': repo_data.get('forks_count', 0),
                    'created_at': repo_data.get('created_at', ''),
                    'updated_at': repo_data.get('updated_at', ''),
                    'size': repo_data.get('size', 0)
                }
            
            # Tags
            tags_url = f"https://api.github.com/repos/{repo_info.owner}/{repo_info.repo}/tags"
            tags_response = self.session.get(tags_url)
            if tags_response.status_code == 200:
                tags_data = tags_response.json()
                repo_info.tags = [tag['name'] for tag in tags_data]
            
            # Branches
            branches_url = f"https://api.github.com/repos/{repo_info.owner}/{repo_info.repo}/branches"
            branches_response = self.session.get(branches_url)
            if branches_response.status_code == 200:
                branches_data = branches_response.json()
                repo_info.branches = [branch['name'] for branch in branches_data]
            
            self.logger.info(f"GitHub metadata fetched: {len(repo_info.tags)} tags, {len(repo_info.branches)} branches")
            return repo_info
            
        except Exception as e:
            self.logger.error(f"Failed to fetch GitHub metadata: {e}")
            return repo_info
    
    def _get_gitlab_metadata(self, repo_info: RepositoryInfo) -> RepositoryInfo:
        """Fetch GitLab repository metadata"""
        try:
            # URL encode the project path
            project_path = f"{repo_info.owner}/{repo_info.repo}".replace('/', '%2F')
            
            # Repository info
            repo_url = f"https://gitlab.com/api/v4/projects/{project_path}"
            repo_response = self.session.get(repo_url)
            
            if repo_response.status_code == 200:
                repo_data = repo_response.json()
                repo_info.is_private = repo_data.get('visibility', 'public') != 'public'
                repo_info.default_branch = repo_data.get('default_branch', 'main')
                repo_info.metadata = {
                    'description': repo_data.get('description', ''),
                    'language': repo_data.get('languages', {}).get(list(repo_data.get('languages', {}).keys())[0] if repo_data.get('languages') else '', ''),
                    'stars': repo_data.get('star_count', 0),
                    'forks': repo_data.get('forks_count', 0),
                    'created_at': repo_data.get('created_at', ''),
                    'updated_at': repo_data.get('last_activity_at', ''),
                }
            
            # Tags
            tags_url = f"https://gitlab.com/api/v4/projects/{project_path}/repository/tags"
            tags_response = self.session.get(tags_url)
            if tags_response.status_code == 200:
                tags_data = tags_response.json()
                repo_info.tags = [tag['name'] for tag in tags_data]
            
            # Branches
            branches_url = f"https://gitlab.com/api/v4/projects/{project_path}/repository/branches"
            branches_response = self.session.get(branches_url)
            if branches_response.status_code == 200:
                branches_data = branches_response.json()
                repo_info.branches = [branch['name'] for branch in branches_data]
            
            self.logger.info(f"GitLab metadata fetched: {len(repo_info.tags)} tags, {len(repo_info.branches)} branches")
            return repo_info
            
        except Exception as e:
            self.logger.error(f"Failed to fetch GitLab metadata: {e}")
            return repo_info
    
    def _get_bitbucket_metadata(self, repo_info: RepositoryInfo) -> RepositoryInfo:
        """Fetch Bitbucket repository metadata"""
        try:
            # Repository info
            repo_url = f"https://api.bitbucket.org/2.0/repositories/{repo_info.owner}/{repo_info.repo}"
            repo_response = self.session.get(repo_url)
            
            if repo_response.status_code == 200:
                repo_data = repo_response.json()
                repo_info.is_private = repo_data.get('is_private', False)
                repo_info.default_branch = repo_data.get('mainbranch', {}).get('name', 'main')
                repo_info.metadata = {
                    'description': repo_data.get('description', ''),
                    'language': repo_data.get('language', ''),
                    'created_at': repo_data.get('created_on', ''),
                    'updated_at': repo_data.get('updated_on', ''),
                    'size': repo_data.get('size', 0)
                }
            
            # Tags
            tags_url = f"https://api.bitbucket.org/2.0/repositories/{repo_info.owner}/{repo_info.repo}/refs/tags"
            tags_response = self.session.get(tags_url)
            if tags_response.status_code == 200:
                tags_data = tags_response.json()
                repo_info.tags = [tag['name'] for tag in tags_data.get('values', [])]
            
            # Branches
            branches_url = f"https://api.bitbucket.org/2.0/repositories/{repo_info.owner}/{repo_info.repo}/refs/branches"
            branches_response = self.session.get(branches_url)
            if branches_response.status_code == 200:
                branches_data = branches_response.json()
                repo_info.branches = [branch['name'] for branch in branches_data.get('values', [])]
            
            self.logger.info(f"Bitbucket metadata fetched: {len(repo_info.tags)} tags, {len(repo_info.branches)} branches")
            return repo_info
            
        except Exception as e:
            self.logger.error(f"Failed to fetch Bitbucket metadata: {e}")
            return repo_info
    
    def validate_remote_access(self, repo_info: RepositoryInfo) -> bool:
        """
        Validate that remote repository is accessible.
        
        Args:
            repo_info: Repository information
            
        Returns:
            True if repository is accessible
        """
        try:
            if repo_info.platform == RepositoryPlatform.LOCAL:
                return os.path.exists(repo_info.url)
            
            # For remote repositories, try a simple API call
            if repo_info.platform == RepositoryPlatform.GITHUB:
                url = f"https://api.github.com/repos/{repo_info.owner}/{repo_info.repo}"
            elif repo_info.platform == RepositoryPlatform.GITLAB:
                project_path = f"{repo_info.owner}/{repo_info.repo}".replace('/', '%2F')
                url = f"https://gitlab.com/api/v4/projects/{project_path}"
            elif repo_info.platform == RepositoryPlatform.BITBUCKET:
                url = f"https://api.bitbucket.org/2.0/repositories/{repo_info.owner}/{repo_info.repo}"
            else:
                # For unknown platforms, assume accessible
                return True
            
            response = self.session.get(url)
            accessible = response.status_code in [200, 403]  # 403 might mean private but exists
            
            self.logger.info(f"Repository accessibility: {accessible} (status: {response.status_code})")
            return accessible
            
        except Exception as e:
            self.logger.error(f"Failed to validate remote access: {e}")
            return False
    
    def get_optimal_clone_strategy(self, repo_info: RepositoryInfo) -> Dict[str, Any]:
        """
        Determine optimal cloning strategy based on repository characteristics.
        
        Args:
            repo_info: Repository information
            
        Returns:
            Dictionary with cloning strategy recommendations
        """
        strategy = {
            'depth': 1,  # Shallow clone by default
            'single_branch': True,
            'clone_url': repo_info.clone_url_https,
            'auth_method': 'https',
            'parallel_jobs': 1
        }
        
        # Adjust strategy based on repository size and platform
        if repo_info.metadata:
            size = repo_info.metadata.get('size', 0)
            if size > 100000:  # Large repository (>100MB)
                strategy['depth'] = 1
                strategy['single_branch'] = True
                strategy['parallel_jobs'] = 2
            elif size > 50000:  # Medium repository (>50MB)
                strategy['depth'] = 5
                strategy['parallel_jobs'] = 1
        
        # Platform-specific optimizations
        if repo_info.platform == RepositoryPlatform.GITHUB:
            if 'github_token' in self.auth_config:
                strategy['auth_method'] = 'token'
        elif repo_info.platform == RepositoryPlatform.GITLAB:
            if 'gitlab_token' in self.auth_config:
                strategy['auth_method'] = 'token'
        
        return strategy
    
    def list_remote_tags(self, repo_info: RepositoryInfo) -> List[str]:
        """
        List all available tags in remote repository.
        
        Args:
            repo_info: Repository information
            
        Returns:
            List of tag names
        """
        if not repo_info.tags:
            repo_info = self.get_repository_metadata(repo_info)
        
        return repo_info.tags
    
    def list_remote_branches(self, repo_info: RepositoryInfo) -> List[str]:
        """
        List all available branches in remote repository.
        
        Args:
            repo_info: Repository information
            
        Returns:
            List of branch names
        """
        if not repo_info.branches:
            repo_info = self.get_repository_metadata(repo_info)
        
        return repo_info.branches
    
    def compare_remote_tags(self, repo_url: str, tag1: str, tag2: str) -> Dict[str, Any]:
        """
        Compare two tags in a remote repository using platform APIs.
        
        Args:
            repo_url: Repository URL
            tag1: First tag to compare
            tag2: Second tag to compare
            
        Returns:
            Comparison metadata from platform API
        """
        repo_info = self.parse_repository_url(repo_url)
        
        try:
            if repo_info.platform == RepositoryPlatform.GITHUB:
                compare_url = f"https://api.github.com/repos/{repo_info.owner}/{repo_info.repo}/compare/{tag1}...{tag2}"
                response = self.session.get(compare_url)
                if response.status_code == 200:
                    return response.json()
            
            elif repo_info.platform == RepositoryPlatform.GITLAB:
                project_path = f"{repo_info.owner}/{repo_info.repo}".replace('/', '%2F')
                compare_url = f"https://gitlab.com/api/v4/projects/{project_path}/repository/compare?from={tag1}&to={tag2}"
                response = self.session.get(compare_url)
                if response.status_code == 200:
                    return response.json()
            
            self.logger.warning(f"Remote comparison not supported for platform: {repo_info.platform.value}")
            return {}
            
        except Exception as e:
            self.logger.error(f"Failed to compare remote tags: {e}")
            return {} 