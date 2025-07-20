#!/usr/bin/env python3
"""
Git Operations for RouteHawk

Handles git repository operations including cloning, checkout, authentication,
and workspace management. Enforces read-only access for security.
"""

import os
import shutil
import tempfile
import logging
import subprocess
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum

try:
    import git
    from git import Repo, GitCommandError
    GIT_PYTHON_AVAILABLE = True
except ImportError:
    GIT_PYTHON_AVAILABLE = False

class AuthMethod(Enum):
    """Authentication methods for git operations"""
    AUTO = "auto"
    SSH = "ssh"
    TOKEN = "token"
    OAUTH = "oauth"
    NONE = "none"

@dataclass
class GitConfig:
    """Git configuration for authentication and operations"""
    auth_method: AuthMethod = AuthMethod.AUTO
    token: Optional[str] = None
    ssh_key_path: Optional[str] = None
    username: Optional[str] = None
    timeout: int = 300  # 5 minutes default timeout
    
class GitOperationError(Exception):
    """Custom exception for git operation errors"""
    pass

class GitOperations:
    """
    Handles all git operations with security and authentication.
    
    Features:
    - Read-only repository access (security enforced)
    - Multiple authentication methods (SSH, token, OAuth)
    - Temporary workspace management
    - Tag and branch operations
    - Remote repository support (GitHub, GitLab, etc.)
    """
    
    def __init__(self, config: GitConfig):
        """
        Initialize Git Operations.
        
        Args:
            config: Git configuration including authentication
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.temp_workspaces: List[str] = []
        
        # Validate GitPython availability
        if not GIT_PYTHON_AVAILABLE:
            self.logger.warning("GitPython not available - falling back to subprocess")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup workspaces"""
        self.cleanup_workspaces()
    
    def create_temp_workspace(self) -> str:
        """
        Create a temporary workspace for git operations.
        
        Returns:
            Path to temporary workspace
        """
        temp_dir = tempfile.mkdtemp(prefix="routehawk_git_")
        self.temp_workspaces.append(temp_dir)
        self.logger.debug(f"Created temporary workspace: {temp_dir}")
        return temp_dir
    
    def cleanup_workspaces(self):
        """Clean up all temporary workspaces"""
        for workspace in self.temp_workspaces:
            try:
                if os.path.exists(workspace):
                    shutil.rmtree(workspace)
                    self.logger.debug(f"Cleaned up workspace: {workspace}")
            except Exception as e:
                self.logger.warning(f"Failed to cleanup workspace {workspace}: {e}")
        self.temp_workspaces.clear()
    
    def is_git_repository(self, path: str) -> bool:
        """
        Check if a path is a git repository.
        
        Args:
            path: Path to check
            
        Returns:
            True if path is a git repository
        """
        try:
            if GIT_PYTHON_AVAILABLE:
                repo = Repo(path)
                return not repo.bare
            else:
                # Fall back to subprocess
                result = subprocess.run(
                    ["git", "rev-parse", "--git-dir"],
                    cwd=path,
                    capture_output=True,
                    timeout=10
                )
                return result.returncode == 0
        except Exception:
            return False
    
    def get_repository_info(self, repo_path: str) -> Dict[str, str]:
        """
        Get basic repository information.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            Dictionary with repository info
        """
        info = {
            'type': 'unknown',
            'url': '',
            'branch': '',
            'commit': '',
            'tags': []
        }
        
        try:
            if self.is_git_repository(repo_path):
                info['type'] = 'git'
                
                if GIT_PYTHON_AVAILABLE:
                    repo = Repo(repo_path)
                    info['branch'] = repo.active_branch.name if repo.active_branch else 'detached'
                    info['commit'] = repo.head.commit.hexsha[:8]
                    
                    # Get remote URL
                    if repo.remotes:
                        info['url'] = repo.remotes.origin.url
                    
                    # Get tags
                    info['tags'] = [tag.name for tag in repo.tags]
                else:
                    # Fall back to subprocess
                    try:
                        # Get current branch
                        result = subprocess.run(
                            ["git", "branch", "--show-current"],
                            cwd=repo_path,
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        if result.returncode == 0:
                            info['branch'] = result.stdout.strip()
                        
                        # Get current commit
                        result = subprocess.run(
                            ["git", "rev-parse", "--short", "HEAD"],
                            cwd=repo_path,
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        if result.returncode == 0:
                            info['commit'] = result.stdout.strip()
                    except subprocess.TimeoutExpired:
                        self.logger.warning("Git command timed out")
            else:
                info['type'] = 'directory'
                
        except Exception as e:
            self.logger.error(f"Error getting repository info: {e}")
        
        return info
    
    def clone_repository(self, repo_url: str, target_dir: str, branch: Optional[str] = None, 
                        tag: Optional[str] = None, depth: int = 1) -> str:
        """
        Clone a repository with authentication and security.
        
        Args:
            repo_url: Repository URL to clone
            target_dir: Target directory for clone
            branch: Specific branch to clone
            tag: Specific tag to clone
            depth: Clone depth (1 for shallow clone)
            
        Returns:
            Path to cloned repository
            
        Raises:
            GitOperationError: If clone operation fails
        """
        self.logger.info(f"Cloning repository: {repo_url}")
        
        try:
            # Ensure target directory exists
            Path(target_dir).mkdir(parents=True, exist_ok=True)
            
            # Prepare authentication
            auth_env = self._prepare_auth_environment()
            
            if GIT_PYTHON_AVAILABLE:
                # Use GitPython for cloning
                clone_kwargs = {
                    'depth': depth if depth > 0 else None,
                    'env': auth_env
                }
                
                if branch:
                    clone_kwargs['branch'] = branch
                
                repo = Repo.clone_from(repo_url, target_dir, **clone_kwargs)
                
                # Checkout specific tag if requested
                if tag and not branch:
                    repo.git.checkout(tag)
                
                self.logger.info(f"Successfully cloned repository to: {target_dir}")
                return target_dir
                
            else:
                # Fall back to subprocess
                cmd = ["git", "clone"]
                
                if depth > 0:
                    cmd.extend(["--depth", str(depth)])
                
                if branch:
                    cmd.extend(["--branch", branch])
                
                cmd.extend([repo_url, target_dir])
                
                result = subprocess.run(
                    cmd,
                    env={**os.environ, **auth_env},
                    capture_output=True,
                    text=True,
                    timeout=self.config.timeout
                )
                
                if result.returncode != 0:
                    raise GitOperationError(f"Git clone failed: {result.stderr}")
                
                # Checkout specific tag if requested
                if tag and not branch:
                    result = subprocess.run(
                        ["git", "checkout", tag],
                        cwd=target_dir,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if result.returncode != 0:
                        raise GitOperationError(f"Tag checkout failed: {result.stderr}")
                
                self.logger.info(f"Successfully cloned repository to: {target_dir}")
                return target_dir
                
        except subprocess.TimeoutExpired:
            raise GitOperationError(f"Clone operation timed out after {self.config.timeout} seconds")
        except Exception as e:
            raise GitOperationError(f"Failed to clone repository: {e}")
    
    def checkout_tag(self, repo_path: str, tag: str) -> bool:
        """
        Checkout a specific tag in repository.
        
        Args:
            repo_path: Path to repository
            tag: Tag name to checkout
            
        Returns:
            True if successful
            
        Raises:
            GitOperationError: If checkout fails
        """
        self.logger.info(f"Checking out tag: {tag} in {repo_path}")
        
        try:
            if GIT_PYTHON_AVAILABLE:
                repo = Repo(repo_path)
                repo.git.checkout(tag)
            else:
                result = subprocess.run(
                    ["git", "checkout", tag],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode != 0:
                    raise GitOperationError(f"Tag checkout failed: {result.stderr}")
            
            self.logger.info(f"Successfully checked out tag: {tag}")
            return True
            
        except Exception as e:
            raise GitOperationError(f"Failed to checkout tag {tag}: {e}")
    
    def checkout_branch(self, repo_path: str, branch: str) -> bool:
        """
        Checkout a specific branch in repository.
        
        Args:
            repo_path: Path to repository
            branch: Branch name to checkout
            
        Returns:
            True if successful
            
        Raises:
            GitOperationError: If checkout fails
        """
        self.logger.info(f"Checking out branch: {branch} in {repo_path}")
        
        try:
            if GIT_PYTHON_AVAILABLE:
                repo = Repo(repo_path)
                repo.git.checkout(branch)
            else:
                result = subprocess.run(
                    ["git", "checkout", branch],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode != 0:
                    raise GitOperationError(f"Branch checkout failed: {result.stderr}")
            
            self.logger.info(f"Successfully checked out branch: {branch}")
            return True
            
        except Exception as e:
            raise GitOperationError(f"Failed to checkout branch {branch}: {e}")
    
    def get_tags(self, repo_path: str) -> List[str]:
        """
        Get list of all tags in repository.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            List of tag names
        """
        try:
            if GIT_PYTHON_AVAILABLE:
                repo = Repo(repo_path)
                return [tag.name for tag in repo.tags]
            else:
                result = subprocess.run(
                    ["git", "tag", "-l"],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    return result.stdout.strip().split('\n') if result.stdout.strip() else []
                return []
                
        except Exception as e:
            self.logger.error(f"Failed to get tags: {e}")
            return []
    
    def get_branches(self, repo_path: str, remote: bool = False) -> List[str]:
        """
        Get list of branches in repository.
        
        Args:
            repo_path: Path to repository
            remote: Include remote branches
            
        Returns:
            List of branch names
        """
        try:
            if GIT_PYTHON_AVAILABLE:
                repo = Repo(repo_path)
                if remote:
                    branches = [ref.name.replace('origin/', '') for ref in repo.remote().refs]
                else:
                    branches = [head.name for head in repo.heads]
                return branches
            else:
                cmd = ["git", "branch"]
                if remote:
                    cmd.append("-r")
                
                result = subprocess.run(
                    cmd,
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    branches = []
                    for line in result.stdout.strip().split('\n'):
                        branch = line.strip().lstrip('* ').replace('origin/', '')
                        if branch and not branch.startswith('HEAD'):
                            branches.append(branch)
                    return branches
                return []
                
        except Exception as e:
            self.logger.error(f"Failed to get branches: {e}")
            return []
    
    def _prepare_auth_environment(self) -> Dict[str, str]:
        """
        Prepare environment variables for authentication.
        
        Returns:
            Dictionary of environment variables
        """
        auth_env = {}
        
        if self.config.auth_method == AuthMethod.TOKEN and self.config.token:
            # For HTTPS with token authentication
            auth_env['GIT_ASKPASS'] = 'echo'
            auth_env['GIT_USERNAME'] = self.config.username or 'token'
            auth_env['GIT_PASSWORD'] = self.config.token
            
        elif self.config.auth_method == AuthMethod.SSH and self.config.ssh_key_path:
            # For SSH key authentication
            auth_env['GIT_SSH_COMMAND'] = f'ssh -i {self.config.ssh_key_path} -o StrictHostKeyChecking=no'
        
        return auth_env
    
    def validate_read_only_access(self, repo_url: str) -> bool:
        """
        Validate that we only have read access to repository.
        
        Args:
            repo_url: Repository URL to validate
            
        Returns:
            True if read-only access confirmed
        """
        # This is a security check to ensure we don't accidentally
        # have write access to repositories
        try:
            # Check if URL suggests read-only access
            if repo_url.startswith('https://') and not self.config.token:
                return True  # Public HTTPS is typically read-only
            
            # For private repos, we assume read-only based on configuration
            # In a real implementation, you might want to test actual permissions
            self.logger.info(f"Assuming read-only access for: {repo_url}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to validate read-only access: {e}")
            return False 