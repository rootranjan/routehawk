#!/usr/bin/env python3
"""
Advanced Filtering System for RouteHawk Phase 4

Provides sophisticated filtering capabilities for route comparison:
- Framework-based filtering (express, nestjs, fastapi, etc.)
- Path pattern filtering with wildcards and regex
- HTTP method filtering with logical operators
- Multi-criteria filtering with AND/OR logic
- Risk-level filtering
- File-based filtering
"""

import re
import logging
from typing import List, Dict, Set, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from models import RouteInfo, Framework, HTTPMethod, RiskLevel

class FilterOperator(Enum):
    """Filter logical operators"""
    AND = "and"
    OR = "or"
    NOT = "not"

class FilterType(Enum):
    """Types of filters available"""
    FRAMEWORK = "framework"
    PATH = "path"
    METHOD = "method"
    RISK_LEVEL = "risk_level"
    FILE_PATH = "file_path"
    AUTH_REQUIRED = "auth_required"
    PARAMS = "params"
    CUSTOM = "custom"

@dataclass
class FilterRule:
    """Individual filter rule"""
    filter_type: FilterType
    operator: FilterOperator
    values: List[str]
    pattern: Optional[str] = None
    regex: Optional[re.Pattern] = None
    case_sensitive: bool = False
    
    def __post_init__(self):
        if self.pattern and not self.regex:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            try:
                self.regex = re.compile(self.pattern, flags)
            except re.error as e:
                logging.warning(f"Invalid regex pattern '{self.pattern}': {e}")
                self.regex = None

@dataclass
class FilterCriteria:
    """Complete filtering criteria with multiple rules"""
    rules: List[FilterRule]
    global_operator: FilterOperator = FilterOperator.AND
    description: str = ""

class AdvancedFilterEngine:
    """
    Advanced filtering engine for sophisticated route filtering.
    
    Features:
    - Multi-criteria filtering with logical operators
    - Pattern matching with wildcards and regex
    - Framework-aware filtering
    - Performance optimized for large datasets
    - Flexible rule composition
    """
    
    def __init__(self):
        """Initialize the filter engine"""
        self.logger = logging.getLogger(__name__)
        self.custom_filters: Dict[str, Callable] = {}
        
        # Predefined filter patterns
        self.predefined_patterns = {
            'api': r'/api/.*',
            'admin': r'.*/admin/.*',
            'auth': r'.*/auth/.*|.*/login.*|.*/register.*',
            'payment': r'.*/payment.*|.*/billing.*|.*/checkout.*',
            'user': r'.*/user.*|.*/profile.*',
            'public': r'/public/.*|/assets/.*|/static/.*'
        }
    
    def parse_filter_string(self, filter_string: str) -> FilterCriteria:
        """
        Parse filter string into FilterCriteria.
        
        Supported formats:
        - "framework=express,nestjs"
        - "path=/api/*,/admin/*"
        - "method=POST,PUT,DELETE"
        - "framework=express;path=/api/*;method=POST"
        - "path=*/admin*;method=POST,PUT;risk_level=HIGH"
        
        Args:
            filter_string: Filter string to parse
            
        Returns:
            FilterCriteria object
        """
        if not filter_string:
            return FilterCriteria(rules=[])
        
        rules = []
        
        # Split by semicolon for AND conditions
        and_conditions = filter_string.split(';')
        
        for condition in and_conditions:
            condition = condition.strip()
            if '=' not in condition:
                continue
            
            filter_type_str, values_str = condition.split('=', 1)
            filter_type_str = filter_type_str.strip().lower()
            
            # Parse filter type
            filter_type = self._parse_filter_type(filter_type_str)
            if not filter_type:
                self.logger.warning(f"Unknown filter type: {filter_type_str}")
                continue
            
            # Parse values (comma-separated for OR conditions)
            values = [v.strip() for v in values_str.split(',')]
            
            # Create filter rule
            rule = FilterRule(
                filter_type=filter_type,
                operator=FilterOperator.OR if len(values) > 1 else FilterOperator.AND,
                values=values
            )
            
            # Handle pattern-based filters
            if filter_type == FilterType.PATH:
                rule.pattern = self._convert_to_regex_pattern(values)
            
            rules.append(rule)
        
        return FilterCriteria(
            rules=rules,
            global_operator=FilterOperator.AND,
            description=f"Parsed from: {filter_string}"
        )
    
    def apply_filters(self, routes: List[RouteInfo], 
                     criteria: FilterCriteria) -> List[RouteInfo]:
        """
        Apply filtering criteria to a list of routes.
        
        Args:
            routes: List of routes to filter
            criteria: Filtering criteria to apply
            
        Returns:
            Filtered list of routes
        """
        if not criteria.rules:
            return routes
        
        self.logger.info(f"Applying {len(criteria.rules)} filter rules to {len(routes)} routes")
        
        filtered_routes = []
        
        for route in routes:
            if self._route_matches_criteria(route, criteria):
                filtered_routes.append(route)
        
        self.logger.info(f"Filtering completed: {len(filtered_routes)} routes match criteria")
        return filtered_routes
    
    def create_framework_filter(self, frameworks: List[str]) -> FilterCriteria:
        """Create a framework-based filter"""
        return FilterCriteria(
            rules=[FilterRule(
                filter_type=FilterType.FRAMEWORK,
                operator=FilterOperator.OR,
                values=frameworks
            )],
            description=f"Framework filter: {', '.join(frameworks)}"
        )
    
    def create_path_filter(self, patterns: List[str], 
                          use_regex: bool = False) -> FilterCriteria:
        """Create a path-based filter with pattern matching"""
        rule = FilterRule(
            filter_type=FilterType.PATH,
            operator=FilterOperator.OR,
            values=patterns
        )
        
        if use_regex:
            # Combine patterns into single regex
            combined_pattern = '|'.join(f"({pattern})" for pattern in patterns)
            rule.pattern = combined_pattern
        else:
            # Convert wildcards to regex
            rule.pattern = self._convert_to_regex_pattern(patterns)
        
        return FilterCriteria(
            rules=[rule],
            description=f"Path filter: {', '.join(patterns)}"
        )
    
    def create_method_filter(self, methods: List[str]) -> FilterCriteria:
        """Create an HTTP method filter"""
        return FilterCriteria(
            rules=[FilterRule(
                filter_type=FilterType.METHOD,
                operator=FilterOperator.OR,
                values=[method.upper() for method in methods]
            )],
            description=f"Method filter: {', '.join(methods)}"
        )
    
    def create_risk_filter(self, risk_levels: List[str]) -> FilterCriteria:
        """Create a risk level filter"""
        return FilterCriteria(
            rules=[FilterRule(
                filter_type=FilterType.RISK_LEVEL,
                operator=FilterOperator.OR,
                values=[level.upper() for level in risk_levels]
            )],
            description=f"Risk filter: {', '.join(risk_levels)}"
        )
    
    def create_composite_filter(self, *criteria_list: FilterCriteria, 
                               operator: FilterOperator = FilterOperator.AND) -> FilterCriteria:
        """Combine multiple filter criteria with specified operator"""
        all_rules = []
        descriptions = []
        
        for criteria in criteria_list:
            all_rules.extend(criteria.rules)
            if criteria.description:
                descriptions.append(criteria.description)
        
        return FilterCriteria(
            rules=all_rules,
            global_operator=operator,
            description=f"Composite ({operator.value}): {'; '.join(descriptions)}"
        )
    
    def create_predefined_filter(self, filter_name: str) -> Optional[FilterCriteria]:
        """Create filter from predefined patterns"""
        if filter_name.lower() not in self.predefined_patterns:
            return None
        
        pattern = self.predefined_patterns[filter_name.lower()]
        
        return FilterCriteria(
            rules=[FilterRule(
                filter_type=FilterType.PATH,
                operator=FilterOperator.OR,
                values=[pattern],
                pattern=pattern
            )],
            description=f"Predefined filter: {filter_name}"
        )
    
    def register_custom_filter(self, name: str, filter_func: Callable[[RouteInfo], bool]):
        """Register a custom filter function"""
        self.custom_filters[name] = filter_func
        self.logger.info(f"Registered custom filter: {name}")
    
    def _route_matches_criteria(self, route: RouteInfo, 
                               criteria: FilterCriteria) -> bool:
        """Check if a route matches the filtering criteria"""
        if not criteria.rules:
            return True
        
        rule_results = []
        
        for rule in criteria.rules:
            result = self._route_matches_rule(route, rule)
            rule_results.append(result)
        
        # Apply global operator
        if criteria.global_operator == FilterOperator.AND:
            return all(rule_results)
        elif criteria.global_operator == FilterOperator.OR:
            return any(rule_results)
        else:  # NOT
            return not any(rule_results)
    
    def _route_matches_rule(self, route: RouteInfo, rule: FilterRule) -> bool:
        """Check if a route matches a specific filter rule"""
        if rule.filter_type == FilterType.FRAMEWORK:
            return self._match_framework(route, rule)
        elif rule.filter_type == FilterType.PATH:
            return self._match_path(route, rule)
        elif rule.filter_type == FilterType.METHOD:
            return self._match_method(route, rule)
        elif rule.filter_type == FilterType.RISK_LEVEL:
            return self._match_risk_level(route, rule)
        elif rule.filter_type == FilterType.FILE_PATH:
            return self._match_file_path(route, rule)
        elif rule.filter_type == FilterType.AUTH_REQUIRED:
            return self._match_auth_required(route, rule)
        elif rule.filter_type == FilterType.PARAMS:
            return self._match_params(route, rule)
        elif rule.filter_type == FilterType.CUSTOM:
            return self._match_custom(route, rule)
        
        return False
    
    def _match_framework(self, route: RouteInfo, rule: FilterRule) -> bool:
        """Match framework filter"""
        if not route.framework:
            return False
        
        # Safe access to framework
        framework_name = route.framework.value if hasattr(route.framework, 'value') else str(route.framework)
        framework_name = framework_name.lower()
        
        target_frameworks = [f.lower() for f in rule.values]
        
        if rule.operator == FilterOperator.OR:
            return framework_name in target_frameworks
        elif rule.operator == FilterOperator.AND:
            return framework_name in target_frameworks
        else:  # NOT
            return framework_name not in target_frameworks
    
    def _match_path(self, route: RouteInfo, rule: FilterRule) -> bool:
        """Match path filter with pattern support"""
        if not route.path:
            return False
        
        # Use regex pattern if available
        if rule.regex:
            match = rule.regex.search(route.path)
            if rule.operator == FilterOperator.NOT:
                return not match
            else:
                return bool(match)
        
        # Fallback to simple wildcard matching
        for pattern in rule.values:
            if self._wildcard_match(route.path, pattern):
                if rule.operator == FilterOperator.NOT:
                    return False
                else:
                    return True
        
        return rule.operator == FilterOperator.NOT
    
    def _match_method(self, route: RouteInfo, rule: FilterRule) -> bool:
        """Match HTTP method filter"""
        if not route.method:
            return False
        
        # Safe access to method
        method_name = route.method.value if hasattr(route.method, 'value') else str(route.method)
        method_name = method_name.upper()
        
        target_methods = [m.upper() for m in rule.values]
        
        if rule.operator == FilterOperator.OR:
            return method_name in target_methods
        elif rule.operator == FilterOperator.AND:
            return method_name in target_methods
        else:  # NOT
            return method_name not in target_methods
    
    def _match_risk_level(self, route: RouteInfo, rule: FilterRule) -> bool:
        """Match risk level filter"""
        if not hasattr(route, 'risk_level') or not route.risk_level:
            return False
        
        risk_name = route.risk_level.value.upper()
        target_risks = [r.upper() for r in rule.values]
        
        if rule.operator == FilterOperator.OR:
            return risk_name in target_risks
        elif rule.operator == FilterOperator.AND:
            return risk_name in target_risks
        else:  # NOT
            return risk_name not in target_risks
    
    def _match_file_path(self, route: RouteInfo, rule: FilterRule) -> bool:
        """Match file path filter"""
        if not route.file_path:
            return False
        
        for pattern in rule.values:
            if self._wildcard_match(route.file_path, pattern):
                return rule.operator != FilterOperator.NOT
        
        return rule.operator == FilterOperator.NOT
    
    def _match_auth_required(self, route: RouteInfo, rule: FilterRule) -> bool:
        """Match authentication requirement filter"""
        auth_required = getattr(route, 'auth_required', False)
        target_value = rule.values[0].lower() == 'true' if rule.values else False
        
        if rule.operator == FilterOperator.NOT:
            return auth_required != target_value
        else:
            return auth_required == target_value
    
    def _match_params(self, route: RouteInfo, rule: FilterRule) -> bool:
        """Match route parameters filter"""
        route_params = getattr(route, 'parameters', [])
        
        for param_pattern in rule.values:
            if any(self._wildcard_match(param, param_pattern) for param in route_params):
                return rule.operator != FilterOperator.NOT
        
        return rule.operator == FilterOperator.NOT
    
    def _match_custom(self, route: RouteInfo, rule: FilterRule) -> bool:
        """Match custom filter"""
        filter_name = rule.values[0] if rule.values else ""
        custom_filter = self.custom_filters.get(filter_name)
        
        if not custom_filter:
            return False
        
        try:
            result = custom_filter(route)
            return not result if rule.operator == FilterOperator.NOT else result
        except Exception as e:
            self.logger.error(f"Custom filter '{filter_name}' failed: {e}")
            return False
    
    def _wildcard_match(self, text: str, pattern: str) -> bool:
        """Simple wildcard matching (* and ?)"""
        # Convert wildcard pattern to regex
        regex_pattern = pattern.replace('*', '.*').replace('?', '.')
        regex_pattern = f"^{regex_pattern}$"
        
        try:
            return bool(re.match(regex_pattern, text, re.IGNORECASE))
        except re.error:
            return False
    
    def _convert_to_regex_pattern(self, patterns: List[str]) -> str:
        """Convert wildcard patterns to regex"""
        regex_patterns = []
        
        for pattern in patterns:
            # Check if it's already a regex (contains regex metacharacters)
            if any(char in pattern for char in ['^', '$', '[', ']', '(', ')', '|', '+']):
                regex_patterns.append(pattern)
            else:
                # Convert wildcard to regex
                regex_pattern = pattern.replace('*', '.*').replace('?', '.')
                regex_patterns.append(regex_pattern)
        
        # Combine with OR
        return '|'.join(f"({pattern})" for pattern in regex_patterns)
    
    def _parse_filter_type(self, filter_type_str: str) -> Optional[FilterType]:
        """Parse filter type from string"""
        type_mapping = {
            'framework': FilterType.FRAMEWORK,
            'frameworks': FilterType.FRAMEWORK,
            'path': FilterType.PATH,
            'paths': FilterType.PATH,
            'method': FilterType.METHOD,
            'methods': FilterType.METHOD,
            'risk': FilterType.RISK_LEVEL,
            'risk_level': FilterType.RISK_LEVEL,
            'file': FilterType.FILE_PATH,
            'file_path': FilterType.FILE_PATH,
            'auth': FilterType.AUTH_REQUIRED,
            'auth_required': FilterType.AUTH_REQUIRED,
            'params': FilterType.PARAMS,
            'parameters': FilterType.PARAMS,
            'custom': FilterType.CUSTOM
        }
        
        return type_mapping.get(filter_type_str.lower())
    
    def get_filter_statistics(self, routes: List[RouteInfo], 
                             criteria: FilterCriteria) -> Dict[str, Any]:
        """Get statistics about filter application"""
        total_routes = len(routes)
        filtered_routes = self.apply_filters(routes, criteria)
        filtered_count = len(filtered_routes)
        
        # Analyze filter impact
        framework_distribution = {}
        method_distribution = {}
        
        for route in filtered_routes:
            if route.framework:
                framework = route.framework.value
                framework_distribution[framework] = framework_distribution.get(framework, 0) + 1
            
            if route.method:
                method = route.method.value
                method_distribution[method] = method_distribution.get(method, 0) + 1
        
        return {
            'total_routes': total_routes,
            'filtered_routes': filtered_count,
            'filter_rate': (filtered_count / total_routes * 100) if total_routes > 0 else 0,
            'framework_distribution': framework_distribution,
            'method_distribution': method_distribution,
            'criteria_description': criteria.description
        } 