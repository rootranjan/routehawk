#!/usr/bin/env python3
"""
File-Level Change Tracking for RouteHawk Phase 4

Comprehensive tracking of file changes and their impact on routes:
- File modification detection (added, removed, modified)
- Line-level change analysis
- Route-to-file mapping
- Impact assessment of file changes on routes
- Content similarity analysis
- Code structure change detection
"""

import os
import hashlib
import difflib
import logging
from typing import List, Dict, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from datetime import datetime

from models import RouteInfo, FileChange

class FileChangeType(Enum):
    """Types of file changes"""
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    RENAMED = "renamed"
    UNCHANGED = "unchanged"

class LineChangeType(Enum):
    """Types of line changes within files"""
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    CONTEXT = "context"

@dataclass
class LineChange:
    """Individual line change within a file"""
    line_number: int
    change_type: LineChangeType
    content: str
    old_content: Optional[str] = None
    route_relevant: bool = False
    
@dataclass
class FileChangeDetail:
    """Detailed file change information"""
    file_path: str
    change_type: FileChangeType
    old_path: Optional[str] = None
    size_change: int = 0
    lines_added: int = 0
    lines_removed: int = 0
    lines_modified: int = 0
    content_similarity: float = 0.0
    line_changes: List[LineChange] = field(default_factory=list)
    affected_routes: List[RouteInfo] = field(default_factory=list)
    framework_files: List[str] = field(default_factory=list)
    risk_impact: str = "LOW"
    
@dataclass
class FileChangeStats:
    """Statistics about file changes"""
    total_files_changed: int = 0
    files_added: int = 0
    files_removed: int = 0
    files_modified: int = 0
    files_renamed: int = 0
    total_lines_added: int = 0
    total_lines_removed: int = 0
    routes_affected: int = 0
    high_impact_changes: int = 0

class FileChangeTracker:
    """
    Comprehensive file change tracking and analysis.
    
    Features:
    - File-level change detection and analysis
    - Line-by-line diff analysis
    - Route impact assessment
    - Content similarity measurement
    - Framework-aware analysis
    - Performance optimized for large codebases
    """
    
    def __init__(self):
        """Initialize the file change tracker"""
        self.logger = logging.getLogger(__name__)
        self.route_file_mapping: Dict[str, List[RouteInfo]] = {}
        self.framework_patterns = {
            'express': [r'\.js$', r'\.ts$', r'app\.js', r'server\.js', r'routes/.*'],
            'nestjs': [r'\.controller\.ts$', r'\.module\.ts$', r'\.service\.ts$'],
            'fastapi': [r'\.py$', r'main\.py', r'app\.py', r'routers/.*'],
            'django': [r'\.py$', r'urls\.py', r'views\.py', r'models\.py'],
            'flask': [r'\.py$', r'app\.py', r'routes\.py', r'__init__\.py'],
            'nextjs': [r'\.tsx?$', r'pages/.*', r'api/.*', r'app/.*'],
            'go': [r'\.go$', r'main\.go', r'handler.*\.go', r'router.*\.go'],
            'springboot': [r'\.java$', r'Controller\.java$', r'Application\.java$']
        }
    
    def track_directory_changes(self, source_dir: str, target_dir: str,
                               source_routes: List[RouteInfo],
                               target_routes: List[RouteInfo]) -> List[FileChangeDetail]:
        """
        Track file changes between two directories.
        
        Args:
            source_dir: Source directory path
            target_dir: Target directory path
            source_routes: Routes from source version
            target_routes: Routes from target version
            
        Returns:
            List of FileChangeDetail objects
        """
        self.logger.info(f"Tracking file changes between {source_dir} and {target_dir}")
        
        # Build route-to-file mapping
        self._build_route_file_mapping(source_routes + target_routes)
        
        # Get file lists
        source_files = self._get_file_list(source_dir)
        target_files = self._get_file_list(target_dir)
        
        # Detect file changes
        file_changes = []
        
        # Find added, removed, and common files
        source_file_set = set(source_files.keys())
        target_file_set = set(target_files.keys())
        
        added_files = target_file_set - source_file_set
        removed_files = source_file_set - target_file_set
        common_files = source_file_set & target_file_set
        
        # Process added files
        for file_path in added_files:
            change_detail = self._analyze_added_file(
                file_path, target_files[file_path], target_dir, target_routes
            )
            file_changes.append(change_detail)
        
        # Process removed files
        for file_path in removed_files:
            change_detail = self._analyze_removed_file(
                file_path, source_files[file_path], source_dir, source_routes
            )
            file_changes.append(change_detail)
        
        # Process modified files
        for file_path in common_files:
            source_file_info = source_files[file_path]
            target_file_info = target_files[file_path]
            
            # Check if file content changed
            if source_file_info['hash'] != target_file_info['hash']:
                change_detail = self._analyze_modified_file(
                    file_path, source_file_info, target_file_info,
                    source_dir, target_dir, source_routes, target_routes
                )
                file_changes.append(change_detail)
        
        self.logger.info(f"File change tracking completed: {len(file_changes)} files changed")
        return file_changes
    
    def analyze_line_changes(self, file_path: str, source_content: str, 
                           target_content: str) -> List[LineChange]:
        """
        Analyze line-by-line changes in a file.
        
        Args:
            file_path: Path to the file
            source_content: Original file content
            target_content: Modified file content
            
        Returns:
            List of LineChange objects
        """
        source_lines = source_content.splitlines()
        target_lines = target_content.splitlines()
        
        line_changes = []
        
        # Use difflib for detailed line comparison
        diff = list(difflib.unified_diff(
            source_lines, target_lines, 
            fromfile=f"a/{file_path}", tofile=f"b/{file_path}",
            lineterm='', n=3
        ))
        
        current_line = 0
        for line in diff:
            if line.startswith('@@'):
                # Parse line numbers from hunk header
                import re
                match = re.search(r'-(\d+),?\d* \+(\d+),?\d*', line)
                if match:
                    current_line = int(match.group(2))
                continue
            
            if line.startswith('+') and not line.startswith('+++'):
                # Added line
                line_changes.append(LineChange(
                    line_number=current_line,
                    change_type=LineChangeType.ADDED,
                    content=line[1:],
                    route_relevant=self._is_line_route_relevant(line[1:], file_path)
                ))
                current_line += 1
            elif line.startswith('-') and not line.startswith('---'):
                # Removed line
                line_changes.append(LineChange(
                    line_number=current_line,
                    change_type=LineChangeType.REMOVED,
                    content=line[1:],
                    route_relevant=self._is_line_route_relevant(line[1:], file_path)
                ))
            elif line.startswith(' '):
                # Context line
                current_line += 1
        
        return line_changes
    
    def calculate_file_impact_score(self, file_change: FileChangeDetail) -> float:
        """
        Calculate impact score for a file change.
        
        Args:
            file_change: File change details
            
        Returns:
            Impact score (0.0 to 1.0)
        """
        score = 0.0
        
        # Base score based on change type
        type_scores = {
            FileChangeType.ADDED: 0.3,
            FileChangeType.REMOVED: 0.8,
            FileChangeType.MODIFIED: 0.5,
            FileChangeType.RENAMED: 0.2,
            FileChangeType.UNCHANGED: 0.0
        }
        score += type_scores.get(file_change.change_type, 0.0)
        
        # Adjust based on number of affected routes
        if file_change.affected_routes:
            route_factor = min(len(file_change.affected_routes) / 10.0, 0.3)
            score += route_factor
        
        # Adjust based on file size and line changes
        if file_change.lines_added > 50 or file_change.lines_removed > 50:
            score += 0.2
        
        # Adjust based on route-relevant line changes
        route_relevant_changes = sum(1 for lc in file_change.line_changes if lc.route_relevant)
        if route_relevant_changes > 0:
            score += min(route_relevant_changes / 20.0, 0.3)
        
        # Check if it's a framework file
        if self._is_framework_file(file_change.file_path):
            score += 0.2
        
        # Cap at 1.0
        return min(score, 1.0)
    
    def get_change_statistics(self, file_changes: List[FileChangeDetail]) -> FileChangeStats:
        """
        Generate statistics from file changes.
        
        Args:
            file_changes: List of file changes
            
        Returns:
            FileChangeStats object
        """
        stats = FileChangeStats()
        
        stats.total_files_changed = len(file_changes)
        
        for change in file_changes:
            # Count by change type
            if change.change_type == FileChangeType.ADDED:
                stats.files_added += 1
            elif change.change_type == FileChangeType.REMOVED:
                stats.files_removed += 1
            elif change.change_type == FileChangeType.MODIFIED:
                stats.files_modified += 1
            elif change.change_type == FileChangeType.RENAMED:
                stats.files_renamed += 1
            
            # Line counts
            stats.total_lines_added += change.lines_added
            stats.total_lines_removed += change.lines_removed
            
            # Route impact
            stats.routes_affected += len(change.affected_routes)
            
            # High impact changes
            impact_score = self.calculate_file_impact_score(change)
            if impact_score > 0.7:
                stats.high_impact_changes += 1
        
        return stats
    
    def filter_changes_by_impact(self, file_changes: List[FileChangeDetail],
                                min_impact_score: float = 0.5) -> List[FileChangeDetail]:
        """
        Filter file changes by minimum impact score.
        
        Args:
            file_changes: List of file changes
            min_impact_score: Minimum impact score threshold
            
        Returns:
            Filtered list of high-impact changes
        """
        high_impact_changes = []
        
        for change in file_changes:
            impact_score = self.calculate_file_impact_score(change)
            if impact_score >= min_impact_score:
                high_impact_changes.append(change)
        
        return high_impact_changes
    
    def _build_route_file_mapping(self, routes: List[RouteInfo]):
        """Build mapping from files to routes"""
        self.route_file_mapping.clear()
        
        for route in routes:
            if route.file_path:
                if route.file_path not in self.route_file_mapping:
                    self.route_file_mapping[route.file_path] = []
                self.route_file_mapping[route.file_path].append(route)
    
    def _get_file_list(self, directory: str) -> Dict[str, Dict[str, Any]]:
        """Get list of files with metadata"""
        files = {}
        
        for root, dirs, filenames in os.walk(directory):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'dist', 'build']]
            
            for filename in filenames:
                # Skip non-source files
                if self._should_skip_file(filename):
                    continue
                
                file_path = os.path.join(root, filename)
                relative_path = os.path.relpath(file_path, directory)
                
                try:
                    stat = os.stat(file_path)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        file_hash = hashlib.md5(content.encode()).hexdigest()
                    
                    files[relative_path] = {
                        'path': file_path,
                        'relative_path': relative_path,
                        'size': stat.st_size,
                        'mtime': stat.st_mtime,
                        'hash': file_hash,
                        'content': content,
                        'lines': len(content.splitlines())
                    }
                except (OSError, UnicodeDecodeError) as e:
                    self.logger.warning(f"Could not read file {file_path}: {e}")
        
        return files
    
    def _should_skip_file(self, filename: str) -> bool:
        """Check if file should be skipped"""
        skip_patterns = [
            r'\.git', r'\.svn', r'\.hg',
            r'\.pyc$', r'\.pyo$', r'\.pyd$',
            r'\.class$', r'\.jar$', r'\.war$',
            r'\.o$', r'\.so$', r'\.dll$',
            r'\.jpg$', r'\.jpeg$', r'\.png$', r'\.gif$', r'\.bmp$',
            r'\.pdf$', r'\.doc$', r'\.docx$',
            r'\.log$', r'\.tmp$', r'\.temp$',
            r'package-lock\.json$', r'yarn\.lock$'
        ]
        
        import re
        for pattern in skip_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                return True
        return False
    
    def _analyze_added_file(self, file_path: str, file_info: Dict[str, Any],
                           target_dir: str, target_routes: List[RouteInfo]) -> FileChangeDetail:
        """Analyze an added file"""
        # Find routes in this file
        affected_routes = [r for r in target_routes if r.file_path and os.path.normpath(r.file_path).endswith(os.path.normpath(file_path))]
        
        # Analyze content for route-relevant lines
        line_changes = []
        lines = file_info['content'].splitlines()
        for i, line in enumerate(lines):
            if self._is_line_route_relevant(line, file_path):
                line_changes.append(LineChange(
                    line_number=i + 1,
                    change_type=LineChangeType.ADDED,
                    content=line,
                    route_relevant=True
                ))
        
        return FileChangeDetail(
            file_path=file_path,
            change_type=FileChangeType.ADDED,
            size_change=file_info['size'],
            lines_added=file_info['lines'],
            line_changes=line_changes,
            affected_routes=affected_routes,
            framework_files=self._identify_framework_files(file_path),
            risk_impact=self._assess_risk_impact(FileChangeType.ADDED, affected_routes)
        )
    
    def _analyze_removed_file(self, file_path: str, file_info: Dict[str, Any],
                             source_dir: str, source_routes: List[RouteInfo]) -> FileChangeDetail:
        """Analyze a removed file"""
        # Find routes that were in this file
        affected_routes = [r for r in source_routes if r.file_path and os.path.normpath(r.file_path).endswith(os.path.normpath(file_path))]
        
        return FileChangeDetail(
            file_path=file_path,
            change_type=FileChangeType.REMOVED,
            size_change=-file_info['size'],
            lines_removed=file_info['lines'],
            affected_routes=affected_routes,
            framework_files=self._identify_framework_files(file_path),
            risk_impact=self._assess_risk_impact(FileChangeType.REMOVED, affected_routes)
        )
    
    def _analyze_modified_file(self, file_path: str, source_info: Dict[str, Any],
                              target_info: Dict[str, Any], source_dir: str, target_dir: str,
                              source_routes: List[RouteInfo], target_routes: List[RouteInfo]) -> FileChangeDetail:
        """Analyze a modified file"""
        # Find affected routes
        source_routes_in_file = [r for r in source_routes if r.file_path and os.path.normpath(r.file_path).endswith(os.path.normpath(file_path))]
        target_routes_in_file = [r for r in target_routes if r.file_path and os.path.normpath(r.file_path).endswith(os.path.normpath(file_path))]
        affected_routes = list(set(source_routes_in_file + target_routes_in_file))
        
        # Analyze line changes
        line_changes = self.analyze_line_changes(file_path, source_info['content'], target_info['content'])
        
        # Calculate content similarity
        similarity = difflib.SequenceMatcher(None, source_info['content'], target_info['content']).ratio()
        
        # Count line changes
        lines_added = sum(1 for lc in line_changes if lc.change_type == LineChangeType.ADDED)
        lines_removed = sum(1 for lc in line_changes if lc.change_type == LineChangeType.REMOVED)
        
        return FileChangeDetail(
            file_path=file_path,
            change_type=FileChangeType.MODIFIED,
            size_change=target_info['size'] - source_info['size'],
            lines_added=lines_added,
            lines_removed=lines_removed,
            content_similarity=similarity,
            line_changes=line_changes,
            affected_routes=affected_routes,
            framework_files=self._identify_framework_files(file_path),
            risk_impact=self._assess_risk_impact(FileChangeType.MODIFIED, affected_routes)
        )
    
    def _is_line_route_relevant(self, line: str, file_path: str) -> bool:
        """Check if a line is relevant to route definition"""
        line_lower = line.lower().strip()
        
        # Common route definition patterns
        route_patterns = [
            r'@app\.',  # Flask decorators
            r'@router\.',  # FastAPI routers
            r'@.*\.(get|post|put|delete|patch)',  # General decorators
            r'app\.(get|post|put|delete|patch)',  # Express routes
            r'router\.(get|post|put|delete|patch)',  # Router methods
            r'@.*mapping',  # Spring Boot mappings
            r'Route\(',  # ASP.NET routes
            r'def\s+\w+.*:',  # Python function definitions
            r'function\s+\w+',  # JavaScript functions
            r'const\s+\w+\s*=.*=>',  # Arrow functions
        ]
        
        import re
        for pattern in route_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        
        return False
    
    def _is_framework_file(self, file_path: str) -> bool:
        """Check if file is a framework-specific file"""
        import re
        for framework, patterns in self.framework_patterns.items():
            for pattern in patterns:
                if re.search(pattern, file_path, re.IGNORECASE):
                    return True
        return False
    
    def _identify_framework_files(self, file_path: str) -> List[str]:
        """Identify which frameworks this file belongs to"""
        frameworks = []
        import re
        
        for framework, patterns in self.framework_patterns.items():
            for pattern in patterns:
                if re.search(pattern, file_path, re.IGNORECASE):
                    frameworks.append(framework)
                    break
        
        return frameworks
    
    def _assess_risk_impact(self, change_type: FileChangeType, affected_routes: List[RouteInfo]) -> str:
        """Assess risk impact of file change"""
        if change_type == FileChangeType.REMOVED and affected_routes:
            return "HIGH"
        elif len(affected_routes) > 5:
            return "HIGH"
        elif len(affected_routes) > 1:
            return "MEDIUM"
        else:
            return "LOW" 