"""
Universal Template Resolution System for RouteHawk
Supports template literals, variable substitution, and dynamic route construction 
across multiple frameworks and programming languages.
"""

import re
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass
from pathlib import Path

from models import Framework, RouteParameter


@dataclass
class ResolvedRoute:
    """Represents a fully resolved route with all template variables processed"""
    original_template: str
    resolved_path: str
    path_parameters: List[str]
    query_parameters: List[str]
    resolved_variables: Dict[str, str]
    confidence: float
    metadata: Dict[str, Any]


@dataclass 
class FrameworkContext:
    """Context information for framework-specific template resolution"""
    framework: Framework
    file_path: str
    file_content: str
    variables: Dict[str, str]
    configuration: Dict[str, Any]


class BaseTemplateResolver(ABC):
    """Base class for framework-specific template resolution"""
    
    def __init__(self, framework: Framework):
        self.framework = framework
        self.common_patterns = {
            # Universal variable patterns
            'env_var': re.compile(r'\$\{([A-Z_][A-Z0-9_]*)\}'),  # ${API_PREFIX}
            'property': re.compile(r'\$\{([^}]+)\}'),  # ${app.prefix}
            'interpolation': re.compile(r'\{([^}]+)\}'),  # {variable}
        }
    
    @abstractmethod
    def extract_variables(self, content: str) -> Dict[str, str]:
        """Extract variable declarations from file content"""
        pass
    
    @abstractmethod
    def parse_template_syntax(self, template: str, variables: Dict[str, str]) -> ResolvedRoute:
        """Parse framework-specific template syntax"""
        pass
    
    def resolve_template(self, template: str, context: FrameworkContext) -> ResolvedRoute:
        """Universal template resolution entry point"""
        try:
            # Extract variables if not provided
            if not context.variables:
                context.variables = self.extract_variables(context.file_content)
            
            # Framework-specific parsing
            resolved = self.parse_template_syntax(template, context.variables)
            
            # Post-processing
            resolved = self._apply_universal_rules(resolved, context)
            
            return resolved
            
        except Exception as e:
            return ResolvedRoute(
                original_template=template,
                resolved_path=template,
                path_parameters=[],
                query_parameters=[],
                resolved_variables={},
                confidence=0.0,
                metadata={'error': str(e)}
            )
    
    def _apply_universal_rules(self, resolved: ResolvedRoute, context: FrameworkContext) -> ResolvedRoute:
        """Apply universal post-processing rules"""
        path = resolved.resolved_path
        
        # Ensure path starts with /
        if not path.startswith('/'):
            path = '/' + path
        
        # Clean up multiple slashes
        path = re.sub(r'/+', '/', path)
        
        # Extract query parameters if present
        if '?' in path:
            path_part, query_part = path.split('?', 1)
            query_params = self._extract_query_params(query_part)
            resolved.query_parameters.extend(query_params)
            path = path_part
        
        # Update resolved path
        resolved.resolved_path = path
        
        return resolved
    
    def _extract_query_params(self, query_string: str) -> List[str]:
        """Extract parameter names from query string"""
        params = []
        for param_pair in query_string.split('&'):
            if '=' in param_pair:
                param_name = param_pair.split('=')[0]
                if param_name and param_name not in params:
                    params.append(param_name)
        return params
    
    def _normalize_parameter_syntax(self, path: str) -> Tuple[str, List[str]]:
        """Normalize different parameter syntaxes to OpenAPI format"""
        parameters = []
        
        # Convert various parameter formats to {param}
        conversions = [
            (r':(\w+)', r'{\1}'),           # Express :id -> {id}
            (r'\[(\w+)\]', r'{\1}'),        # Next.js [id] -> {id}
            (r'\[\.\.\.(\w+)\]', r'{...\1}'), # Next.js [...slug] -> {...slug}
            (r'<(\w+)>', r'{\1}'),          # Some frameworks <id> -> {id}
        ]
        
        normalized_path = path
        for pattern, replacement in conversions:
            matches = re.findall(pattern, normalized_path)
            parameters.extend(matches)
            normalized_path = re.sub(pattern, replacement, normalized_path)
        
        return normalized_path, parameters


class JavaScriptTemplateResolver(BaseTemplateResolver):
    """Template resolver for JavaScript/TypeScript frameworks"""
    
    def __init__(self, framework: Framework):
        super().__init__(framework)
        self.js_patterns = {
            'const_declaration': re.compile(r'const\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            'let_declaration': re.compile(r'let\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            'var_declaration': re.compile(r'var\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            'export_const': re.compile(r'export\s+const\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]'),
            'template_literal': re.compile(r'`([^`]*\$\{[^`]*\}[^`]*)`'),
            'template_var': re.compile(r'\$\{([^}()]+)\}'),
            'template_func': re.compile(r'\$\{([^}]+)\(\)\}'),
        }
    
    def extract_variables(self, content: str) -> Dict[str, str]:
        """Extract JavaScript/TypeScript variable declarations"""
        variables = {}
        
        for pattern_name, pattern in self.js_patterns.items():
            if 'declaration' in pattern_name or 'export' in pattern_name:
                matches = pattern.findall(content)
                for var_name, var_value in matches:
                    variables[var_name] = var_value
        
        return variables
    
    def parse_template_syntax(self, template: str, variables: Dict[str, str]) -> ResolvedRoute:
        """Parse JavaScript template literal syntax"""
        resolved_path = template
        path_params = []
        query_params = []
        resolved_vars = {}
        
        # Remove template literal backticks
        if resolved_path.startswith('`') and resolved_path.endswith('`'):
            resolved_path = resolved_path[1:-1]
        
        # Split URL and query string
        url_parts = resolved_path.split('?')
        path_part = url_parts[0]
        query_part = url_parts[1] if len(url_parts) > 1 else ""
        
        # Resolve variables: ${prefixApi} -> actual value
        for var_name, var_value in variables.items():
            var_pattern = f'${{{var_name}}}'
            if var_pattern in path_part:
                path_part = path_part.replace(var_pattern, var_value)
                resolved_vars[var_name] = var_value
        
        # Convert parameters: ${accountId} -> {accountId}
        param_matches = self.js_patterns['template_var'].findall(path_part)
        for param in param_matches:
            if param not in variables:
                path_part = path_part.replace(f'${{{param}}}', f'{{{param}}}')
                if param not in path_params:
                    path_params.append(param)
        
        # Handle function calls: ${timestamp()} -> {timestamp}
        func_matches = self.js_patterns['template_func'].findall(path_part)
        for func_name in func_matches:
            path_part = path_part.replace(f'${{{func_name}()}}', f'{{{func_name}}}')
            if func_name not in path_params:
                path_params.append(func_name)
        
        # Process query parameters
        if query_part:
            for var_name, var_value in variables.items():
                var_pattern = f'${{{var_name}}}'
                query_part = query_part.replace(var_pattern, var_value)
            
            # Convert function calls in query
            query_func_matches = self.js_patterns['template_func'].findall(query_part)
            for func_name in query_func_matches:
                query_part = query_part.replace(f'${{{func_name}()}}', f'{{{func_name}}}')
                if func_name not in query_params:
                    query_params.append(func_name)
        
        # Calculate confidence
        confidence = 1.0
        if '${' in path_part:  # Unresolved variables
            confidence *= 0.7
        if resolved_vars:  # Successfully resolved variables
            confidence = min(confidence + 0.2, 1.0)
        
        return ResolvedRoute(
            original_template=template,
            resolved_path=path_part,
            path_parameters=path_params,
            query_parameters=query_params,
            resolved_variables=resolved_vars,
            confidence=confidence,
            metadata={
                'framework': self.framework.value,
                'template_type': 'javascript_template_literal'
            }
        )


class GoTemplateResolver(BaseTemplateResolver):
    """Template resolver for Go HTTP frameworks"""
    
    def __init__(self, framework: Framework):
        super().__init__(framework)
        self.go_patterns = {
            'var_declaration': re.compile(r'var\s+(\w+)\s*=\s*"([^"]+)"'),
            'const_declaration': re.compile(r'const\s+(\w+)\s*=\s*"([^"]+)"'),
            'short_var': re.compile(r'(\w+)\s*:=\s*"([^"]+)"'),
            'sprintf': re.compile(r'fmt\.Sprintf\s*\(\s*"([^"]*)",\s*([^)]+)\)'),
            'string_concat': re.compile(r'"([^"]*?)"\s*\+\s*(\w+)'),
        }
    
    def extract_variables(self, content: str) -> Dict[str, str]:
        """Extract Go variable declarations"""
        variables = {}
        
        for pattern_name, pattern in self.go_patterns.items():
            if 'declaration' in pattern_name or 'short_var' in pattern_name:
                matches = pattern.findall(content)
                for var_name, var_value in matches:
                    variables[var_name] = var_value
        
        return variables
    
    def parse_template_syntax(self, template: str, variables: Dict[str, str]) -> ResolvedRoute:
        """Parse Go template syntax (fmt.Sprintf, string concatenation)"""
        resolved_path = template
        path_params = []
        resolved_vars = {}
        
        # Handle fmt.Sprintf patterns
        sprintf_match = self.go_patterns['sprintf'].search(template)
        if sprintf_match:
            format_string, args = sprintf_match.groups()
            resolved_path = self._resolve_sprintf(format_string, args, variables)
            
            # Extract parameters from the arguments
            arg_list = [arg.strip() for arg in args.split(',')]
            for arg in arg_list:
                if arg not in variables:
                    path_params.append(arg)
                else:
                    resolved_vars[arg] = variables[arg]
            
        # Handle string concatenation
        else:
            for var_name, var_value in variables.items():
                resolved_path = resolved_path.replace(var_name, var_value)
                if var_name in template:
                    resolved_vars[var_name] = var_value
        
        # Extract parameters from Go patterns
        # Go typically uses {id} in URL patterns already
        param_pattern = re.compile(r'\{(\w+)\}')
        path_params = param_pattern.findall(resolved_path)
        
        return ResolvedRoute(
            original_template=template,
            resolved_path=resolved_path,
            path_parameters=path_params,
            query_parameters=[],
            resolved_variables=resolved_vars,
            confidence=0.8,
            metadata={
                'framework': self.framework.value,
                'template_type': 'go_sprintf' if sprintf_match else 'go_string_concat'
            }
        )
    
    def _resolve_sprintf(self, format_string: str, args: str, variables: Dict[str, str]) -> str:
        """Resolve fmt.Sprintf format string with arguments"""
        # Simple resolution - replace %s, %d with parameter placeholders
        arg_list = [arg.strip() for arg in args.split(',')]
        resolved = format_string
        
        # Replace format specifiers with actual values or parameters
        for i, arg in enumerate(arg_list):
            if arg in variables:
                # Replace with variable value
                resolved = resolved.replace('%s', variables[arg], 1)
                resolved = resolved.replace('%d', variables[arg], 1)
            else:
                # Replace with parameter placeholder
                resolved = resolved.replace('%s', f'{{{arg}}}', 1)
                resolved = resolved.replace('%d', f'{{{arg}}}', 1)
        
        return resolved


class PythonTemplateResolver(BaseTemplateResolver):
    """Template resolver for Python frameworks (FastAPI, Django, Flask)"""
    
    def __init__(self, framework: Framework):
        super().__init__(framework)
        self.python_patterns = {
            'assignment': re.compile(r'(\w+)\s*=\s*[\'"]([^\'"]+)[\'"]'),
            'fstring': re.compile(r'f[\'"]([^\'"]*\{[^\'"]*\}[^\'"]*)[\'"]'),
            'format_method': re.compile(r'[\'"]([^\'"]*\{\}[^\'"]*)[\'"]\.format\(([^)]+)\)'),
            'percent_format': re.compile(r'[\'"]([^\'"]*%s[^\'"]*)[\'"]%\s*\(([^)]+)\)'),
            'fstring_var': re.compile(r'\{(\w+)\}'),
        }
    
    def extract_variables(self, content: str) -> Dict[str, str]:
        """Extract Python variable assignments"""
        variables = {}
        
        matches = self.python_patterns['assignment'].findall(content)
        for var_name, var_value in matches:
            # Look for common prefix/path variables
            if any(keyword in var_name.lower() for keyword in ['prefix', 'path', 'base', 'api', 'url']):
                variables[var_name] = var_value
        
        return variables
    
    def parse_template_syntax(self, template: str, variables: Dict[str, str]) -> ResolvedRoute:
        """Parse Python template syntax (f-strings, .format(), % formatting)"""
        resolved_path = template
        path_params = []
        resolved_vars = {}
        template_type = 'python_string'
        
        # Remove f-string prefix and quotes
        if resolved_path.startswith('f"') and resolved_path.endswith('"'):
            resolved_path = resolved_path[2:-1]
            template_type = 'python_fstring'
        elif resolved_path.startswith("f'") and resolved_path.endswith("'"):
            resolved_path = resolved_path[2:-1]
            template_type = 'python_fstring'
        
        # Handle f-strings
        if template_type == 'python_fstring':
            resolved_path = self._resolve_fstring(resolved_path, variables)
            resolved_vars.update({k: v for k, v in variables.items() if f'{{{k}}}' in resolved_path})
        
        # Handle .format() method
        format_match = self.python_patterns['format_method'].search(template)
        if format_match:
            template_type = 'python_format_method'
            format_string, args = format_match.groups()
            resolved_path = self._resolve_format_method(format_string, args, variables)
        
        # Extract parameters
        param_matches = self.python_patterns['fstring_var'].findall(resolved_path)
        for param in param_matches:
            if param not in variables:  # Only parameters, not resolved variables
                path_params.append(param)
        
        return ResolvedRoute(
            original_template=template,
            resolved_path=resolved_path,
            path_parameters=path_params,
            query_parameters=[],
            resolved_variables=resolved_vars,
            confidence=0.9,
            metadata={
                'framework': self.framework.value,
                'template_type': template_type
            }
        )
    
    def _resolve_fstring(self, format_string: str, variables: Dict[str, str]) -> str:
        """Resolve Python f-string variables"""
        resolved = format_string
        for var_name, var_value in variables.items():
            resolved = resolved.replace(f'{{{var_name}}}', var_value)
        return resolved
    
    def _resolve_format_method(self, format_string: str, args: str, variables: Dict[str, str]) -> str:
        """Resolve .format() method arguments"""
        # Simple implementation - replace {} with arg values
        arg_list = [arg.strip() for arg in args.split(',')]
        resolved = format_string
        
        for arg in arg_list:
            if arg in variables:
                resolved = resolved.replace('{}', variables[arg], 1)
            else:
                resolved = resolved.replace('{}', f'{{{arg}}}', 1)
        
        return resolved


def get_template_resolver(framework: Framework) -> BaseTemplateResolver:
    """Factory function to get appropriate template resolver for framework"""
    
    javascript_frameworks = [Framework.EXPRESS, Framework.NESTJS, Framework.NEXTJS]
    python_frameworks = [Framework.FASTAPI]
    go_frameworks = [Framework.GO_HTTP]
    
    if framework in javascript_frameworks:
        return JavaScriptTemplateResolver(framework)
    elif framework in python_frameworks:
        return PythonTemplateResolver(framework)
    elif framework in go_frameworks:
        return GoTemplateResolver(framework)
    else:
        # Return JavaScript resolver as default for unknown frameworks
        return JavaScriptTemplateResolver(framework) 