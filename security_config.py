#!/usr/bin/env python3
"""
Security configuration and validation utilities for RouteHawk
"""

import os
import re
import secrets
from pathlib import Path
from typing import Optional

class SecurityConfig:
    """Security configuration and validation utilities"""
    
    @staticmethod
    def get_secure_secret_key() -> str:
        """Get secure secret key from environment or generate one"""
        secret_key = os.environ.get('ROUTEHAWK_SECRET_KEY')
        if not secret_key:
            # Generate secure random key
            secret_key = secrets.token_urlsafe(32)
        return secret_key
    
    @staticmethod
    def validate_repo_path(repo_path: str) -> bool:
        """
        Validate repository path for security.
        
        Args:
            repo_path: User-provided repository path
            
        Returns:
            True if path is safe
        """
        if not repo_path:
            return False
        
        # Check for shell injection characters
        dangerous_chars = ['|', '&', ';', '$', '`', '(', ')', '<', '>', '"', "'", '\\', '\n', '\r']
        if any(char in repo_path for char in dangerous_chars):
            return False
        
        # Check for path traversal attempts
        if '..' in repo_path or repo_path.startswith('/etc') or repo_path.startswith('/root'):
            return False
        
        # Ensure path exists and is a directory
        try:
            path = Path(repo_path).resolve()
            return path.exists() and path.is_dir()
        except (OSError, ValueError):
            return False
    
    @staticmethod
    def sanitize_repo_path(repo_path: str) -> str:
        """
        Sanitize repository path for safe execution.
        
        Args:
            repo_path: User-provided repository path
            
        Returns:
            Sanitized absolute path
            
        Raises:
            ValueError: If path is invalid or dangerous
        """
        if not SecurityConfig.validate_repo_path(repo_path):
            raise ValueError(f"Invalid or dangerous repository path: {repo_path}")
        
        # Convert to absolute path and resolve
        try:
            return str(Path(repo_path).resolve())
        except (OSError, ValueError) as e:
            raise ValueError(f"Failed to resolve path: {e}")
    
    @staticmethod
    def validate_file_path(file_path: str, base_dir: str) -> bool:
        """
        Validate file path is within base directory (prevent path traversal).
        
        Args:
            file_path: File path to validate
            base_dir: Base directory that file must be within
            
        Returns:
            True if file path is safe
        """
        try:
            file_path_resolved = Path(file_path).resolve()
            base_dir_resolved = Path(base_dir).resolve()
            
            # Check if file is within base directory
            return str(file_path_resolved).startswith(str(base_dir_resolved))
        except (OSError, ValueError):
            return False
