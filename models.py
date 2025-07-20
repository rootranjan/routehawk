#!/usr/bin/env python3
"""
Data models for RouteHawk API scanner
Defines all data structures used throughout the application
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union, Tuple
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field

class Framework(Enum):
    """Supported web frameworks"""
    EXPRESS = "express"
    NESTJS = "nestjs"  
    NEXTJS = "nextjs"
    FLASK = "flask"
    DJANGO = "django"
    FASTAPI = "fastapi"
    SPRING = "spring"
    SPRING_BOOT = "spring_boot"
    GO_HTTP = "go_http"
    GRPC = "grpc"
    RUBY_RAILS = "ruby_rails"
    LARAVEL = "laravel"
    ASPNET_CORE = "aspnet_core"
    TERRAFORM = "terraform"
    INFRASTRUCTURE = "infrastructure"
    UNKNOWN = "unknown"

class HTTPMethod(Enum):
    """HTTP methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    CONNECT = "CONNECT"
    TRACE = "TRACE"
    ALL = "*"
    
class AuthType(Enum):
    """Authentication types"""
    NONE = "none"
    BASIC = "basic"
    JWT = "jwt" 
    SESSION = "session"
    API_KEY = "api_key"
    OAUTH = "oauth"
    BASIC_AUTH = "basic_auth"
    BEARER_TOKEN = "bearer_token"
    CUSTOM = "custom"
    UNKNOWN = "unknown"
     
class RiskLevel(Enum):
    """Risk assessment levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM" 
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class TemplateVariable:
    """Represents a template variable extracted from source code"""
    name: str
    value: str
    source: str  # 'env', 'config', 'hardcoded', 'dynamic'
    line_number: int
    confidence: float

@dataclass 
class Parameter:
    """Route parameter definition"""
    name: str
    type: str
    required: bool = True
    description: str = ""

class RouteParameter(BaseModel):
    """Route parameter model for backward compatibility"""
    name: str
    type: Optional[str] = None
    required: bool = True
    validation: Optional[str] = None

class SecurityFinding(BaseModel):
    """Security finding model"""
    type: str
    severity: str
    description: str
    recommendation: str
    cwe_id: Optional[str] = None

@dataclass
class RouteContext:
    """Extended route context information"""
    middleware: List[str] = field(default_factory=list)
    decorators: List[str] = field(default_factory=list)  
    parent_class: str = ""
    imports: List[str] = field(default_factory=list)

@dataclass
class PathStructure:
    """Decomposed path structure for analysis"""
    segments: List[str] = field(default_factory=list)        # ['api', 'v1', 'users']
    variables: List[str] = field(default_factory=list)       # ['userId', 'action'] 
    infrastructure: List[str] = field(default_factory=list)   # ['/api-service']
    full: str = ""                                             # '/api-service/merchant/api/v1'

@dataclass
class QueryParam:
    """Query parameter from URL or route definition"""
    name: str
    type: str = "string"
    required: bool = False
    default_value: Optional[str] = None

@dataclass
class RoutePrefix:
    """Route prefix information"""
    value: str = ""          # '/api/v1' - backward compatibility
    source: str = ""         # 'router', 'controller', 'blueprint'  
    infrastructure: str = "" # '/api-service' - backward compatibility
    resolved: bool = False   # backward compatibility
    # Extended fields for prefix resolver
    framework: List[str] = field(default_factory=list)  # Framework-level prefixes
    service: List[str] = field(default_factory=list)    # Service-level prefixes 
    full: str = ""           # Full combined prefix
    confidence: float = 0.0  # Confidence score for detection
    conflicts: List[str] = field(default_factory=list)  # Any prefix conflicts

class PrefixBreakdown(BaseModel):
    """Detailed breakdown of route prefix components"""
    infrastructure: str = ""     # '/api-service'
    service: str = ""           # '/merchant'  
    api: str = ""              # '/api/v1'
    route: str = ""            # '/users/:id'

class RouteInfo(BaseModel):
    """Complete route information model"""
    path: str
    method: str
    framework: Framework
    service_name: str = ""
    file_path: str
    line_number: int = 0
    authenticated: bool = False
    auth_type: AuthType = AuthType.NONE
    auth_required: bool = False  # Backward compatibility
    risk_level: RiskLevel = RiskLevel.LOW  # Backward compatibility
    risk_score: float = 0.0
    risk_factors: List[str] = Field(default_factory=list)  # Backward compatibility
    original_path: Optional[str] = None  # Backward compatibility
    full_path: Optional[str] = None  # For prefix-resolved paths
    prefix_info: Optional[Dict[str, Any]] = Field(default_factory=dict)  # Prefix resolution metadata
    prefix_breakdown: Optional[PrefixBreakdown] = None  # Detailed prefix breakdown
    metadata: Dict[str, Any] = Field(default_factory=dict)  # Backward compatibility
    security_findings: List[SecurityFinding] = Field(default_factory=list)  # Backward compatibility
    parameters: List[Union[Parameter, RouteParameter]] = Field(default_factory=list)
    query_params: List[QueryParam] = Field(default_factory=list)
    context: Optional[RouteContext] = None
    path_structure: Optional[PathStructure] = None
    prefix: Optional[RoutePrefix] = None
    template_variables: List[TemplateVariable] = Field(default_factory=list)
    template_resolved: bool = False
    discovery_time: datetime = Field(default_factory=datetime.now)
    
    class Config:
        use_enum_values = True
        arbitrary_types_allowed = True
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for export"""
        return {
            'path': self.path,
            'method': self.method, 
            'framework': self.framework.value if isinstance(self.framework, Framework) else self.framework,
            'service_name': self.service_name,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'authenticated': 'Yes' if self.authenticated else 'No',
            'auth_type': self.auth_type.value if isinstance(self.auth_type, AuthType) else self.auth_type,
            'parameters': [{'name': p.name, 'type': getattr(p, 'type', 'string'), 'required': p.required} for p in self.parameters],
            'query_params': [{'name': q.name, 'type': q.type, 'required': q.required} for q in self.query_params],
            'risk_score': self.risk_score,
            'template_resolved': self.template_resolved,
            'discovery_time': self.discovery_time.isoformat() if hasattr(self.discovery_time, 'isoformat') else str(self.discovery_time)
        }

class ServiceInfo(BaseModel):
    """Service information model"""
    name: str
    path: str
    framework: Framework
    routes: List[RouteInfo] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)
    
    class Config:
        use_enum_values = True

class ScanConfig(BaseModel):
    """Scan configuration model"""
    repo_path: str
    include_patterns: List[str] = Field(default_factory=lambda: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java"])
    exclude_patterns: List[str] = Field(default_factory=lambda: ["node_modules", ".git", "dist", "build", "__pycache__"])
    frameworks: List[Framework] = Field(default_factory=lambda: [
        Framework.NESTJS, Framework.EXPRESS, Framework.NEXTJS, 
        Framework.GO_HTTP, Framework.FASTAPI, Framework.SPRING_BOOT
    ])
    use_ai_analysis: bool = True
    risk_threshold: RiskLevel = RiskLevel.MEDIUM
    resolve_prefixes: bool = False
    prefix_config_path: Optional[str] = None
    output_formats: List[str] = Field(default_factory=lambda: ["json", "html"])
    output_directory: str = "reports"
    
    # Additional fields used in main routehawk.py
    organization_patterns: bool = True
    prefixes_only: bool = False
    
    # Performance optimization fields (Phase 4)
    performance_mode: str = "auto"
    cache_enabled: bool = True
    max_memory_mb: int = 1024
    chunk_size: Optional[int] = None  # Auto-calculated if not specified
    max_workers: Optional[int] = None  # Auto-calculated if not specified
    progress_mode: str = "enhanced"
    performance_report: bool = True
    
    class Config:
        use_enum_values = True

class GitLabIntegration(BaseModel):
    """GitLab integration configuration"""
    gitlab_url: str = ""
    access_token: str = ""
    project_id: Optional[int] = None
    create_mr_comments: bool = True
    
    class Config:
        use_enum_values = True

@dataclass
class ScanResult:
    """Complete scan results"""
    routes: List[RouteInfo] = field(default_factory=list)
    total_routes: int = 0
    frameworks_detected: List[Framework] = field(default_factory=list)
    scan_time: datetime = field(default_factory=datetime.now)
    scan_id: Optional[str] = ""  # Backward compatibility
    repository_path: Optional[str] = ""  # Backward compatibility
    commit_hash: Optional[str] = None  # Backward compatibility
    branch: Optional[str] = None  # Backward compatibility
    scan_duration_seconds: float = 0.0  # Backward compatibility
    files_analyzed: int = 0  # Backward compatibility
    total_files: int = 0  # Backward compatibility
    errors: List[str] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list) # Backward compatibility
    organization_services: List[ServiceInfo] = field(default_factory=list)  # Backward compatibility
    internal_services: List[ServiceInfo] = field(default_factory=list)  # Backward compatibility
    external_services: List[ServiceInfo] = field(default_factory=list)  # Backward compatibility
    business_services: List[ServiceInfo] = field(default_factory=list)  # Backward compatibility
    infrastructure_services: List[ServiceInfo] = field(default_factory=list)  # Backward compatibility
    security_services: List[ServiceInfo] = field(default_factory=list)  # Backward compatibility
    data_services: List[ServiceInfo] = field(default_factory=list)  # Backward compatibility
    web_services: List[ServiceInfo] = field(default_factory=list)  # Backward compatibility
    api_services: List[ServiceInfo] = field(default_factory=list)  # Backward compatibility
    routes_by_framework: Dict[str, int] = field(default_factory=dict)  # Backward compatibility
    routes_by_method: Dict[str, int] = field(default_factory=dict)  # Backward compatibility
    routes_by_risk: Dict[str, int] = field(default_factory=dict)  # Backward compatibility
    high_risk_routes: int = 0  # Backward compatibility
    medium_risk_routes: int = 0  # Backward compatibility
    low_risk_routes: int = 0  # Backward compatibility
    unauthenticated_routes: int = 0  # Backward compatibility
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary statistics"""
        return {
            'total_routes': self.total_routes,
            'frameworks': [f.value if hasattr(f, 'value') else f for f in self.frameworks_detected],
            'authenticated_routes': sum(1 for r in self.routes if r.authenticated),
            'unauthenticated_routes': sum(1 for r in self.routes if not r.authenticated),
            'high_risk_routes': sum(1 for r in self.routes if r.risk_score > 70),
            'template_resolved_routes': sum(1 for r in self.routes if r.template_resolved),
            'scan_time': self.scan_time.isoformat(),
            'errors': len(self.errors)
        }

# =============================================================================
# Git Comparison Models
# =============================================================================

@dataclass
class FileChange:
    """Represents a file-level change between two versions"""
    file_path: str
    change_type: str  # "ADDED", "REMOVED", "MODIFIED"
    lines_changed: Optional[List[Tuple[int, int]]] = None  # [(start, end), ...]
    size_change: int = 0  # bytes difference
    old_hash: Optional[str] = None  # Git hash of old version
    new_hash: Optional[str] = None  # Git hash of new version

@dataclass
class RouteChange:
    """Represents a route-level change between two versions"""
    change_type: str  # "ADDED", "REMOVED", "MODIFIED"
    old_route: Optional[RouteInfo] = None
    new_route: Optional[RouteInfo] = None
    risk_impact: RiskLevel = RiskLevel.LOW
    file_changes: List[FileChange] = field(default_factory=list)
    change_details: Dict[str, Any] = field(default_factory=dict)
    
    def get_route_signature(self) -> str:
        """Get a consistent signature for the route"""
        route = self.new_route or self.old_route
        if route:
            method = route.method.value if hasattr(route.method, 'value') else str(route.method)
            return f"{method}:{route.path}:{route.file_path}"
        return "unknown:unknown:unknown"

class ComparisonFilter(BaseModel):
    """Filter configuration for route comparisons"""
    frameworks: Optional[List[Framework]] = None
    paths: Optional[List[str]] = None  # glob patterns
    methods: Optional[List[HTTPMethod]] = None
    file_paths: Optional[List[str]] = None  # glob patterns
    original_paths: Optional[List[str]] = None  # glob patterns
    
    class Config:
        use_enum_values = True

class ComparisonConfig(BaseModel):
    """Configuration for git comparison operations"""
    comparison_type: str  # "tags", "branches", "directories", "against_tag"
    source: str  # source tag/branch/directory
    target: str  # target tag/branch/directory  
    filters: Optional[ComparisonFilter] = None
    diff_algorithm: str = "hybrid"  # "strict", "fuzzy", "hybrid"
    include_file_changes: bool = True
    include_risk_analysis: bool = True
    temp_workspace: Optional[str] = None
    parallel_workers: int = 4
    auth_method: str = "auto"  # "auto", "token", "ssh", "oauth"
    
    class Config:
        use_enum_values = True

@dataclass
class ComparisonResult:
    """Complete comparison results between two versions"""
    source_version: str  # tag, branch, or directory path
    target_version: str  # tag, branch, or directory path
    comparison_type: str  # "tags", "branches", "directories", "against_tag"
    changes: List[RouteChange] = field(default_factory=list)
    file_changes: List[FileChange] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)  # counts by change_type
    scan_metadata: Dict[str, Any] = field(default_factory=dict)
    comparison_time: datetime = field(default_factory=datetime.now)
    errors: List[str] = field(default_factory=list)
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get comparison summary statistics"""
        route_counts = {"ADDED": 0, "REMOVED": 0, "MODIFIED": 0, "UNCHANGED": 0}
        file_counts = {"ADDED": 0, "REMOVED": 0, "MODIFIED": 0}
        
        for change in self.changes:
            route_counts[change.change_type] = route_counts.get(change.change_type, 0) + 1
            
        for file_change in self.file_changes:
            file_counts[file_change.change_type] = file_counts.get(file_change.change_type, 0) + 1
        
        return {
            'source_version': self.source_version,
            'target_version': self.target_version,
            'comparison_type': self.comparison_type,
            'route_changes': route_counts,
            'file_changes': file_counts,
            'total_route_changes': len(self.changes),
            'total_file_changes': len(self.file_changes),
            'comparison_time': self.comparison_time.isoformat(),
            'has_errors': len(self.errors) > 0,
            'error_count': len(self.errors)
        } 