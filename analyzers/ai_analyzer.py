import logging
from typing import List, Dict, Any, Optional
import google.generativeai as genai
from models import RouteInfo, SecurityFinding, ScanResult
from datetime import datetime

class AIAnalyzer:
    """
    AI-powered analyzer for semantic analysis of routes and security assessment.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.api_key = api_key
        
        if self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-1.5-pro')
                self.enabled = True
            except Exception as e:
                self.logger.warning(f"Failed to initialize Gemini API: {e}")
                self.enabled = False
        else:
            self.enabled = False
            self.logger.info("No Gemini API key provided, AI analysis disabled")
    
    def analyze_routes(self, routes: List[RouteInfo]) -> List[RouteInfo]:
        """
        Analyze routes using AI for enhanced security insights.
        """
        if not self.enabled:
            return routes
        
        enhanced_routes = []
        for route in routes:
            try:
                enhanced_route = self._analyze_single_route(route)
                enhanced_routes.append(enhanced_route)
            except Exception as e:
                self.logger.error(f"Error analyzing route {route.path}: {e}")
                enhanced_routes.append(route)
        
        return enhanced_routes
    
    def _analyze_single_route(self, route: RouteInfo) -> RouteInfo:
        """
        Analyze a single route with AI.
        """
        if not self.enabled:
            return route
        
        try:
            # Create prompt for AI analysis
            prompt = self._create_analysis_prompt(route)
            
            # Get AI response
            response = self.model.generate_content(prompt)
            
            # Parse and enhance route with AI insights
            enhanced_route = self._enhance_route_with_ai_insights(route, response.text)
            return enhanced_route
            
        except Exception as e:
            self.logger.error(f"AI analysis failed for route {route.path}: {e}")
            return route
    
    def _create_analysis_prompt(self, route: RouteInfo) -> str:
        """
        Create a prompt for AI analysis of the route.
        """
        prompt = f"""
        Analyze this API route for security vulnerabilities and risk assessment:
        
        Route: {route.method.value} {route.path}
        Framework: {route.framework.value}
        Authentication: {route.auth_type.value}
        File: {route.file_path}:{route.line_number}
        
        Parameters:
        {[f"{p.name} ({p.type}, {p.location})" for p in route.parameters]}
        
        Existing security findings:
        {[f"{f.type}: {f.description}" for f in route.security_findings]}
        
        Please provide:
        1. Additional security vulnerabilities that might be present
        2. Risk assessment explanation
        3. Recommended security improvements
        4. Any organization-specific security concerns (payment, user data, etc.)
        
        Respond in JSON format:
        {{
            "additional_findings": [
                {{
                    "type": "vulnerability_type",
                    "severity": "high|medium|low",
                    "description": "detailed description",
                    "recommendation": "how to fix"
                }}
            ],
            "risk_explanation": "why this route has this risk level",
            "recommendations": ["list of security improvements"],
            "organization_concerns": ["Organization-specific security considerations"]
        }}
        """
        return prompt
    
    def _enhance_route_with_ai_insights(self, route: RouteInfo, ai_response: str) -> RouteInfo:
        """
        Enhance route with AI insights.
        """
        try:
            import json
            
            # Try to parse JSON response
            try:
                insights = json.loads(ai_response)
            except json.JSONDecodeError:
                # If JSON parsing fails, extract insights using regex
                insights = self._extract_insights_from_text(ai_response)
            
            # Add additional security findings
            additional_findings = []
            for finding_data in insights.get('additional_findings', []):
                finding = SecurityFinding(
                    type=finding_data.get('type', 'AI Analysis'),
                    severity=finding_data.get('severity', 'MEDIUM').upper(),
                    description=finding_data.get('description', ''),
                    recommendation=finding_data.get('recommendation', 'Review code for potential security issues')
                )
                additional_findings.append(finding)
            
            # Update route metadata with AI insights
            enhanced_metadata = route.metadata.copy()
            enhanced_metadata.update({
                'ai_analysis': {
                    'risk_explanation': insights.get('risk_explanation', ''),
                    'recommendations': insights.get('recommendations', []),
                    'organization_concerns': insights.get('organization_concerns', [])
                }
            })
            
            # Create enhanced route
            enhanced_route = RouteInfo(
                method=route.method,
                path=route.path,
                file_path=route.file_path,
                line_number=route.line_number,
                framework=route.framework,
                auth_type=route.auth_type,
                parameters=route.parameters,
                risk_level=route.risk_level,
                security_findings=route.security_findings + additional_findings,
                metadata=enhanced_metadata
            )
            
            return enhanced_route
            
        except Exception as e:
            self.logger.error(f"Error enhancing route with AI insights: {e}")
            return route
    
    def _extract_insights_from_text(self, text: str) -> Dict[str, Any]:
        """
        Extract insights from AI response text when JSON parsing fails.
        """
        insights = {
            'additional_findings': [],
            'risk_explanation': '',
            'recommendations': [],
            'organization_concerns': []
        }
        
        # Simple text parsing fallback
        lines = text.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if 'vulnerabilit' in line.lower():
                current_section = 'vulnerabilities'
            elif 'risk' in line.lower():
                current_section = 'risk'
            elif 'recommend' in line.lower():
                current_section = 'recommendations'
            elif 'organization' in line.lower():
                current_section = 'organization'
            elif line and current_section:
                if current_section == 'recommendations':
                    insights['recommendations'].append(line)
                elif current_section == 'organization':
                    insights['organization_concerns'].append(line)
                elif current_section == 'risk':
                    insights['risk_explanation'] = line
        
        return insights
    
    def generate_summary_insights(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Generate high-level insights about the entire scan.
        """
        if not self.enabled:
            return {}
        
        try:
            # Create summary prompt
            prompt = self._create_summary_prompt(scan_result)
            
            # Get AI response
            response = self.model.generate_content(prompt)
            
            # Parse insights
            return self._parse_summary_insights(response.text)
            
        except Exception as e:
            self.logger.error(f"Error generating summary insights: {e}")
            return {}
    
    def _create_summary_prompt(self, scan_result: ScanResult) -> str:
        """
        Create prompt for summary analysis.
        """
        high_risk_routes = [r for r in scan_result.routes if r.risk_level.name == 'HIGH']
        frameworks = list(set(r.framework.value for r in scan_result.routes))
        
        prompt = f"""
        Analyze this attack surface scan results:
        
        Total routes found: {len(scan_result.routes)}
        High-risk routes: {len(high_risk_routes)}
        Frameworks detected: {', '.join(frameworks)}
        Services scanned: {len(scan_result.services)}
        
        High-risk routes:
        {[f"{r.method.value} {r.path}" for r in high_risk_routes[:10]]}
        
        Provide strategic security recommendations for the overall attack surface:
        1. Top security priorities
        2. Framework-specific recommendations
        3. Business-specific security concerns
        4. Overall security posture assessment
        
        Focus on actionable insights for modern web applications handling sensitive data.
        """
        return prompt
    
    def _parse_summary_insights(self, response: str) -> Dict[str, Any]:
        """
        Parse summary insights from AI response.
        """
        return {
            'summary': response,
            'generated_by': 'Gemini 1.5 Pro',
            'timestamp': str(datetime.now())
        } 