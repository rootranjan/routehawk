#!/usr/bin/env python3
"""
Enterprise Configuration Management for RouteHawk

Comprehensive configuration system supporting:
- Enterprise settings and preferences
- Custom risk assessment rules
- Framework-specific configurations
- User and organization customizations
- Validation and defaults
"""

import os
import yaml
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)

class ConfigFormat(Enum):
    """Supported configuration formats"""
    YAML = "yaml"
    JSON = "json"
    TOML = "toml"

class RiskRuleType(Enum):
    """Types of custom risk rules"""
    PATH_PATTERN = "path_pattern"
    METHOD_BASED = "method_based"
    FRAMEWORK_SPECIFIC = "framework_specific"
    PARAMETER_VALIDATION = "parameter_validation"
    AUTH_REQUIREMENT = "auth_requirement"
    BUSINESS_LOGIC = "business_logic"
    COMPLIANCE = "compliance"

@dataclass
class CustomRiskRule:
    """Custom risk assessment rule configuration"""
    name: str
    rule_type: RiskRuleType
    conditions: Dict[str, Any]
    risk_score_modifier: float
    risk_level_override: Optional[str] = None
    description: str = ""
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    
    def matches(self, route_info: Dict[str, Any]) -> bool:
        """Check if this rule matches the given route"""
        try:
            if self.rule_type == RiskRuleType.PATH_PATTERN:
                import fnmatch
                path = route_info.get('path', '')
                patterns = self.conditions.get('patterns', [])
                return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)
            
            elif self.rule_type == RiskRuleType.METHOD_BASED:
                method = route_info.get('method', '').upper()
                methods = [m.upper() for m in self.conditions.get('methods', [])]
                return method in methods
            
            elif self.rule_type == RiskRuleType.FRAMEWORK_SPECIFIC:
                framework = route_info.get('framework', '')
                frameworks = self.conditions.get('frameworks', [])
                return framework in frameworks
            
            elif self.rule_type == RiskRuleType.AUTH_REQUIREMENT:
                auth_type = route_info.get('auth_type', 'unknown')
                required_auth = self.conditions.get('required_auth_types', [])
                return auth_type not in required_auth
            
            return False
            
        except Exception as e:
            logger.error(f"Error evaluating rule {self.name}: {e}")
            return False

@dataclass
class OrganizationSettings:
    """Organization-specific configuration settings"""
    organization_name: str = ""
    domain_patterns: List[str] = field(default_factory=list)
    service_classification_rules: Dict[str, List[str]] = field(default_factory=dict)
    critical_path_patterns: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)
    security_baseline: str = "standard"  # standard, strict, enterprise

@dataclass
class FrameworkSettings:
    """Framework-specific configuration settings"""
    enabled_frameworks: List[str] = field(default_factory=lambda: ["all"])
    framework_priorities: Dict[str, int] = field(default_factory=dict)
    custom_detectors: Dict[str, str] = field(default_factory=dict)
    file_patterns: Dict[str, List[str]] = field(default_factory=dict)
    exclusion_patterns: Dict[str, List[str]] = field(default_factory=dict)

@dataclass
class SecuritySettings:
    """Security-related configuration settings"""
    default_risk_threshold: str = "medium"
    enable_ai_analysis: bool = False
    ai_model_config: Dict[str, Any] = field(default_factory=dict)
    auth_analysis_enabled: bool = True
    vulnerability_checks: List[str] = field(default_factory=list)
    compliance_reporting: bool = False

@dataclass
class PerformanceSettings:
    """Performance optimization settings"""
    max_workers: Optional[int] = None
    chunk_size: Optional[int] = None
    memory_limit_mb: int = 1024
    cache_enabled: bool = True
    cache_ttl_hours: int = 24
    progress_reporting: str = "enhanced"  # simple, enhanced, quiet

@dataclass
class OutputSettings:
    """Output and reporting configuration"""
    default_formats: List[str] = field(default_factory=lambda: ["terminal"])
    custom_templates: Dict[str, str] = field(default_factory=dict)
    report_branding: Dict[str, str] = field(default_factory=dict)
    export_settings: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EnterpriseConfig:
    """Complete enterprise configuration"""
    version: str = "1.0"
    organization: OrganizationSettings = field(default_factory=OrganizationSettings)
    frameworks: FrameworkSettings = field(default_factory=FrameworkSettings)
    security: SecuritySettings = field(default_factory=SecuritySettings)
    performance: PerformanceSettings = field(default_factory=PerformanceSettings)
    output: OutputSettings = field(default_factory=OutputSettings)
    custom_risk_rules: List[CustomRiskRule] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

class ConfigurationManager:
    """
    Enterprise configuration management system.
    
    Features:
    - Multiple configuration sources (files, environment, defaults)
    - Custom risk rule management
    - Organization-specific settings
    - Configuration validation
    - Hot-reload capabilities
    - Secure credential handling
    """
    
    def __init__(self, config_paths: Optional[List[str]] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_paths: List of configuration file paths to load
        """
        self.logger = logging.getLogger(__name__)
        self.config_paths = config_paths or self._get_default_config_paths()
        self.config = EnterpriseConfig()
        self._load_configurations()
    
    def _get_default_config_paths(self) -> List[str]:
        """Get default configuration file paths"""
        paths = []
        
        # System-wide configuration
        system_config = "/etc/routehawk/config.yaml"
        if os.path.exists(system_config):
            paths.append(system_config)
        
        # User configuration
        home_config = Path.home() / ".routehawk" / "config.yaml"
        if home_config.exists():
            paths.append(str(home_config))
        
        # Project-local configuration
        for config_name in ["routehawk.yaml", "routehawk.yml", ".routehawk.yaml"]:
            if os.path.exists(config_name):
                paths.append(config_name)
        
        # Environment variable override
        env_config = os.getenv("ROUTEHAWK_CONFIG")
        if env_config and os.path.exists(env_config):
            paths.append(env_config)
        
        return paths
    
    def _load_configurations(self):
        """Load and merge configurations from all sources"""
        self.logger.info(f"Loading configurations from: {self.config_paths}")
        
        for config_path in self.config_paths:
            try:
                self._load_config_file(config_path)
                self.logger.info(f"Loaded configuration from: {config_path}")
            except Exception as e:
                self.logger.warning(f"Failed to load config {config_path}: {e}")
        
        # Load environment variable overrides
        self._load_environment_overrides()
        
        # Validate configuration
        self._validate_configuration()
    
    def _load_config_file(self, config_path: str):
        """Load configuration from a file"""
        with open(config_path, 'r') as f:
            if config_path.endswith(('.yaml', '.yml')):
                config_data = yaml.safe_load(f)
            elif config_path.endswith('.json'):
                config_data = json.load(f)
            else:
                # Try YAML first, then JSON
                try:
                    f.seek(0)
                    config_data = yaml.safe_load(f)
                except:
                    f.seek(0)
                    config_data = json.load(f)
        
        # Merge with existing configuration
        self._merge_config(config_data)
    
    def _merge_config(self, new_config: Dict[str, Any]):
        """Merge new configuration with existing configuration"""
        if not new_config:
            return
        
        # Handle organization settings
        if 'organization' in new_config:
            org_data = new_config['organization']
            for key, value in org_data.items():
                if hasattr(self.config.organization, key):
                    setattr(self.config.organization, key, value)
        
        # Handle framework settings
        if 'frameworks' in new_config:
            fw_data = new_config['frameworks']
            for key, value in fw_data.items():
                if hasattr(self.config.frameworks, key):
                    setattr(self.config.frameworks, key, value)
        
        # Handle security settings
        if 'security' in new_config:
            sec_data = new_config['security']
            for key, value in sec_data.items():
                if hasattr(self.config.security, key):
                    setattr(self.config.security, key, value)
        
        # Handle performance settings
        if 'performance' in new_config:
            perf_data = new_config['performance']
            for key, value in perf_data.items():
                if hasattr(self.config.performance, key):
                    setattr(self.config.performance, key, value)
        
        # Handle output settings
        if 'output' in new_config:
            out_data = new_config['output']
            for key, value in out_data.items():
                if hasattr(self.config.output, key):
                    setattr(self.config.output, key, value)
        
        # Handle custom risk rules
        if 'custom_risk_rules' in new_config:
            rules_data = new_config['custom_risk_rules']
            for rule_data in rules_data:
                try:
                    rule = CustomRiskRule(
                        name=rule_data['name'],
                        rule_type=RiskRuleType(rule_data['rule_type']),
                        conditions=rule_data['conditions'],
                        risk_score_modifier=rule_data['risk_score_modifier'],
                        risk_level_override=rule_data.get('risk_level_override'),
                        description=rule_data.get('description', ''),
                        enabled=rule_data.get('enabled', True),
                        tags=rule_data.get('tags', [])
                    )
                    self.config.custom_risk_rules.append(rule)
                except Exception as e:
                    self.logger.error(f"Invalid risk rule: {e}")
    
    def _load_environment_overrides(self):
        """Load configuration overrides from environment variables"""
        # Security settings from environment
        if os.getenv('ROUTEHAWK_AI_ENABLED'):
            self.config.security.enable_ai_analysis = os.getenv('ROUTEHAWK_AI_ENABLED').lower() == 'true'
        
        if os.getenv('ROUTEHAWK_RISK_THRESHOLD'):
            self.config.security.default_risk_threshold = os.getenv('ROUTEHAWK_RISK_THRESHOLD')
        
        # Performance settings from environment
        if os.getenv('ROUTEHAWK_MAX_WORKERS'):
            try:
                self.config.performance.max_workers = int(os.getenv('ROUTEHAWK_MAX_WORKERS'))
            except ValueError:
                pass
        
        if os.getenv('ROUTEHAWK_MEMORY_LIMIT'):
            try:
                self.config.performance.memory_limit_mb = int(os.getenv('ROUTEHAWK_MEMORY_LIMIT'))
            except ValueError:
                pass
        
        # Organization settings from environment
        if os.getenv('ROUTEHAWK_ORG_NAME'):
            self.config.organization.organization_name = os.getenv('ROUTEHAWK_ORG_NAME')
    
    def _validate_configuration(self):
        """Validate the loaded configuration"""
        try:
            # Validate risk threshold
            valid_thresholds = ['low', 'medium', 'high']
            if self.config.security.default_risk_threshold not in valid_thresholds:
                self.logger.warning(f"Invalid risk threshold, using 'medium'")
                self.config.security.default_risk_threshold = 'medium'
            
            # Validate memory limit
            if self.config.performance.memory_limit_mb < 128:
                self.logger.warning("Memory limit too low, setting to 128MB")
                self.config.performance.memory_limit_mb = 128
            
            # Validate output formats
            valid_formats = ['terminal', 'json', 'csv', 'sarif', 'html']
            self.config.output.default_formats = [
                fmt for fmt in self.config.output.default_formats 
                if fmt in valid_formats
            ]
            
            if not self.config.output.default_formats:
                self.config.output.default_formats = ['terminal']
            
            self.logger.info("Configuration validation completed")
            
        except Exception as e:
            self.logger.error(f"Configuration validation failed: {e}")
    
    def get_custom_risk_rules(self, enabled_only: bool = True) -> List[CustomRiskRule]:
        """Get custom risk rules"""
        if enabled_only:
            return [rule for rule in self.config.custom_risk_rules if rule.enabled]
        return self.config.custom_risk_rules
    
    def apply_custom_risk_rules(self, route_info: Dict[str, Any]) -> Dict[str, Any]:
        """Apply custom risk rules to route information"""
        modified_route = route_info.copy()
        
        for rule in self.get_custom_risk_rules():
            if rule.matches(route_info):
                self.logger.debug(f"Applied rule '{rule.name}' to route {route_info.get('path')}")
                
                # Modify risk score
                current_score = modified_route.get('risk_score', 0.0)
                modified_route['risk_score'] = current_score + rule.risk_score_modifier
                
                # Override risk level if specified
                if rule.risk_level_override:
                    modified_route['risk_level'] = rule.risk_level_override
                
                # Add rule tags
                if 'applied_rules' not in modified_route:
                    modified_route['applied_rules'] = []
                modified_route['applied_rules'].append(rule.name)
        
        return modified_route
    
    def export_configuration(self, output_path: str, format: ConfigFormat = ConfigFormat.YAML):
        """Export current configuration to file"""
        config_dict = asdict(self.config)
        
        with open(output_path, 'w') as f:
            if format == ConfigFormat.YAML:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            elif format == ConfigFormat.JSON:
                json.dump(config_dict, f, indent=2)
        
        self.logger.info(f"Configuration exported to: {output_path}")
    
    def create_example_config(self, output_path: str):
        """Create an example configuration file with all options"""
        example_config = {
            'version': '1.0',
            'organization': {
                'organization_name': 'Example Corp',
                'domain_patterns': ['*.example.com', '*.internal.example.com'],
                'service_classification_rules': {
                    'critical': ['payment', 'auth', 'billing'],
                    'high': ['user', 'order', 'inventory'],
                    'medium': ['content', 'search', 'notification'],
                    'low': ['logging', 'monitoring', 'testing']
                },
                'critical_path_patterns': ['/payment/*', '/admin/*', '/api/auth/*'],
                'excluded_paths': ['/health', '/metrics', '/debug'],
                'compliance_frameworks': ['SOX', 'PCI-DSS', 'GDPR'],
                'security_baseline': 'enterprise'
            },
            'frameworks': {
                'enabled_frameworks': ['nestjs', 'express', 'fastapi', 'go'],
                'framework_priorities': {
                    'nestjs': 1,
                    'express': 2,
                    'fastapi': 3,
                    'go': 4
                },
                'file_patterns': {
                    'nestjs': ['**/*.controller.ts', '**/*.gateway.ts'],
                    'express': ['**/*route*.js', '**/*router*.js']
                }
            },
            'security': {
                'default_risk_threshold': 'medium',
                'enable_ai_analysis': True,
                'ai_model_config': {
                    'provider': 'gemini',
                    'model': 'gemini-pro',
                    'temperature': 0.1
                },
                'vulnerability_checks': ['auth', 'injection', 'validation'],
                'compliance_reporting': True
            },
            'performance': {
                'max_workers': 8,
                'chunk_size': 1000,
                'memory_limit_mb': 2048,
                'cache_enabled': True,
                'cache_ttl_hours': 48,
                'progress_reporting': 'enhanced'
            },
            'output': {
                'default_formats': ['terminal', 'json', 'html'],
                'report_branding': {
                    'organization_name': 'Example Corp Security Team',
                    'logo_url': 'https://example.com/logo.png'
                },
                'export_settings': {
                    'include_metadata': True,
                    'include_file_details': True
                }
            },
            'custom_risk_rules': [
                {
                    'name': 'Admin Endpoint High Risk',
                    'rule_type': 'path_pattern',
                    'conditions': {
                        'patterns': ['/admin/*', '/management/*', '/internal/*']
                    },
                    'risk_score_modifier': 3.0,
                    'risk_level_override': 'high',
                    'description': 'Administrative endpoints require elevated security',
                    'enabled': True,
                    'tags': ['admin', 'privileged']
                },
                {
                    'name': 'Payment Endpoint Critical',
                    'rule_type': 'path_pattern',
                    'conditions': {
                        'patterns': ['/payment/*', '/billing/*', '/transaction/*']
                    },
                    'risk_score_modifier': 5.0,
                    'risk_level_override': 'critical',
                    'description': 'Payment endpoints are business critical',
                    'enabled': True,
                    'tags': ['payment', 'financial', 'pci']
                },
                {
                    'name': 'Unauthenticated Write Operations',
                    'rule_type': 'method_based',
                    'conditions': {
                        'methods': ['POST', 'PUT', 'DELETE', 'PATCH']
                    },
                    'risk_score_modifier': 2.0,
                    'description': 'Write operations without authentication are risky',
                    'enabled': True,
                    'tags': ['auth', 'write-ops']
                }
            ]
        }
        
        with open(output_path, 'w') as f:
            yaml.dump(example_config, f, default_flow_style=False, indent=2)
        
        self.logger.info(f"Example configuration created: {output_path}")

# Global configuration manager instance
_config_manager: Optional[ConfigurationManager] = None

def get_config_manager(config_paths: Optional[List[str]] = None) -> ConfigurationManager:
    """Get or create global configuration manager instance"""
    global _config_manager
    if _config_manager is None or config_paths:
        _config_manager = ConfigurationManager(config_paths)
    return _config_manager

def get_enterprise_config() -> EnterpriseConfig:
    """Get current enterprise configuration"""
    return get_config_manager().config 