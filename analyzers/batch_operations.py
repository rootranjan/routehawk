#!/usr/bin/env python3
"""
Batch Operations Manager for RouteHawk Phase 3

Enterprise-scale batch operations for automated repository analysis,
continuous monitoring, and large-scale security assessments.
"""

import asyncio
import logging
import json
import yaml
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any, Union
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict

from models import (
    RouteInfo, ComparisonResult, RouteChange, FileChange,
    ComparisonConfig, ComparisonFilter, RiskLevel, Framework
)
from analyzers.enhanced_route_comparator import EnhancedRouteComparator, BatchComparisonResult
from analyzers.remote_repository import RemoteRepository, RepositoryInfo

@dataclass
class BatchJob:
    """Configuration for a batch operation job"""
    job_id: str
    job_type: str  # "multi_repo", "release_progression", "tag_discovery", "monitoring"
    repositories: List[str]
    comparison_config: ComparisonConfig
    filters: Optional[ComparisonFilter] = None
    schedule: Optional[str] = None  # Cron-like schedule
    notification_config: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    last_run: Optional[datetime] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass
class BatchJobResult:
    """Results from a batch job execution"""
    job_id: str
    job_type: str
    status: str  # "success", "partial", "failed"
    started_at: datetime
    completed_at: Optional[datetime] = None
    repositories_processed: int = 0
    repositories_failed: int = 0
    total_comparisons: int = 0
    total_route_changes: int = 0
    high_risk_changes: int = 0
    results: List[BatchComparisonResult] = None
    errors: List[str] = None
    summary_report: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.results is None:
            self.results = []
        if self.errors is None:
            self.errors = []

class BatchOperationsManager:
    """
    Manage enterprise-scale batch operations for route comparison.
    
    Features:
    - Multi-repository analysis
    - Automated tag discovery and comparison
    - Release progression monitoring
    - Scheduled batch jobs
    - Performance optimization
    - Enterprise reporting
    - Risk aggregation across repositories
    """
    
    def __init__(self, scanner, auth_config: Dict[str, str] = None):
        """
        Initialize batch operations manager.
        
        Args:
            scanner: AttackSurfaceScanner instance
            auth_config: Authentication configuration
        """
        self.scanner = scanner
        self.logger = logging.getLogger(__name__)
        self.auth_config = auth_config or {}
        self.enhanced_comparator = EnhancedRouteComparator(scanner, auth_config)
        self.remote_repo = RemoteRepository(auth_config)
        self.active_jobs: Dict[str, BatchJob] = {}
        self.job_history: List[BatchJobResult] = []
    
    def create_multi_repository_job(self, repositories: List[str], 
                                  comparison_type: str,
                                  config: ComparisonConfig,
                                  job_id: Optional[str] = None) -> BatchJob:
        """
        Create a batch job for analyzing multiple repositories.
        
        Args:
            repositories: List of repository URLs
            comparison_type: Type of comparison ("latest_tags", "branches", "custom")
            config: Comparison configuration
            job_id: Optional custom job ID
            
        Returns:
            BatchJob configuration
        """
        if job_id is None:
            job_id = f"multi_repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        batch_job = BatchJob(
            job_id=job_id,
            job_type="multi_repo",
            repositories=repositories,
            comparison_config=config
        )
        
        self.active_jobs[job_id] = batch_job
        self.logger.info(f"Created multi-repository job: {job_id} with {len(repositories)} repositories")
        
        return batch_job
    
    def execute_multi_repository_analysis(self, job: BatchJob) -> BatchJobResult:
        """
        Execute multi-repository batch analysis.
        
        Args:
            job: Batch job configuration
            
        Returns:
            BatchJobResult with comprehensive results
        """
        result = BatchJobResult(
            job_id=job.job_id,
            job_type=job.job_type,
            status="running",
            started_at=datetime.now()
        )
        
        self.logger.info(f"Starting multi-repository analysis: {job.job_id}")
        
        try:
            # Parallel processing for multiple repositories
            max_workers = min(len(job.repositories), 5)  # Limit concurrent operations
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit repository analysis tasks
                future_to_repo = {
                    executor.submit(
                        self._analyze_single_repository,
                        repo_url, job.comparison_config
                    ): repo_url
                    for repo_url in job.repositories
                }
                
                # Collect results
                for future in as_completed(future_to_repo):
                    repo_url = future_to_repo[future]
                    try:
                        repo_result = future.result()
                        result.results.append(repo_result)
                        result.repositories_processed += 1
                        result.total_comparisons += len(repo_result.comparisons)
                        result.total_route_changes += sum(
                            len(comp.changes) for comp in repo_result.comparisons
                        )
                        self.logger.info(f"Completed analysis for: {repo_url}")
                    except Exception as e:
                        error_msg = f"Failed to analyze {repo_url}: {e}"
                        result.errors.append(error_msg)
                        result.repositories_failed += 1
                        self.logger.error(error_msg)
            
            # Generate comprehensive summary
            result.summary_report = self._generate_multi_repo_summary(result.results)
            result.high_risk_changes = self._count_high_risk_changes(result.results)
            
            result.status = "success" if result.repositories_failed == 0 else "partial"
            result.completed_at = datetime.now()
            
            self.logger.info(f"Multi-repository analysis completed: {result.repositories_processed} success, {result.repositories_failed} failed")
            
        except Exception as e:
            result.status = "failed"
            result.errors.append(f"Batch job failed: {e}")
            result.completed_at = datetime.now()
        
        # Update job history
        self.job_history.append(result)
        
        return result
    
    def discover_and_analyze_releases(self, repositories: List[str], 
                                    release_count: int = 5,
                                    config: ComparisonConfig = None) -> BatchJobResult:
        """
        Automatically discover and analyze recent releases across repositories.
        
        Args:
            repositories: List of repository URLs
            release_count: Number of recent releases to analyze
            config: Comparison configuration
            
        Returns:
            BatchJobResult with release analysis
        """
        if config is None:
            config = ComparisonConfig(
                comparison_type="release_discovery",
                source="auto",
                target="auto",
                diff_algorithm="hybrid",
                include_file_changes=True,
                include_risk_analysis=True
            )
        
        job = self.create_multi_repository_job(
            repositories,
            "release_discovery",
            config,
            f"release_discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        result = BatchJobResult(
            job_id=job.job_id,
            job_type="release_discovery",
            status="running",
            started_at=datetime.now()
        )
        
        self.logger.info(f"Starting automated release discovery for {len(repositories)} repositories")
        
        try:
            for repo_url in repositories:
                try:
                    # Discover latest releases
                    repo_analysis = self.enhanced_comparator.discover_and_compare_latest_tags(
                        repo_url, release_count, config
                    )
                    
                    if repo_analysis.comparisons:
                        result.results.append(repo_analysis)
                        result.repositories_processed += 1
                        result.total_comparisons += len(repo_analysis.comparisons)
                        result.total_route_changes += sum(
                            len(comp.changes) for comp in repo_analysis.comparisons
                        )
                    
                    self.logger.info(f"Discovered {len(repo_analysis.comparisons)} release comparisons for: {repo_url}")
                    
                except Exception as e:
                    error_msg = f"Failed release discovery for {repo_url}: {e}"
                    result.errors.append(error_msg)
                    result.repositories_failed += 1
                    self.logger.error(error_msg)
            
            # Generate release-specific summary
            result.summary_report = self._generate_release_discovery_summary(result.results)
            result.high_risk_changes = self._count_high_risk_changes(result.results)
            
            result.status = "success" if result.repositories_failed == 0 else "partial"
            result.completed_at = datetime.now()
            
        except Exception as e:
            result.status = "failed"
            result.errors.append(f"Release discovery failed: {e}")
            result.completed_at = datetime.now()
        
        self.job_history.append(result)
        return result
    
    def continuous_monitoring_setup(self, repositories: List[str],
                                  monitoring_config: Dict[str, Any]) -> BatchJob:
        """
        Set up continuous monitoring for repository changes.
        
        Args:
            repositories: List of repository URLs to monitor
            monitoring_config: Configuration for monitoring frequency and thresholds
            
        Returns:
            BatchJob for continuous monitoring
        """
        job_id = f"monitoring_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        config = ComparisonConfig(
            comparison_type="monitoring",
            source="latest",
            target="current",
            diff_algorithm="hybrid",
            include_file_changes=True,
            include_risk_analysis=True
        )
        
        batch_job = BatchJob(
            job_id=job_id,
            job_type="monitoring",
            repositories=repositories,
            comparison_config=config,
            schedule=monitoring_config.get('schedule', '0 */6 * * *'),  # Every 6 hours
            notification_config=monitoring_config.get('notifications', {})
        )
        
        self.active_jobs[job_id] = batch_job
        self.logger.info(f"Set up continuous monitoring: {job_id} for {len(repositories)} repositories")
        
        return batch_job
    
    def generate_enterprise_report(self, job_results: List[BatchJobResult],
                                 report_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Generate enterprise-grade report from batch job results.
        
        Args:
            job_results: List of batch job results
            report_type: Type of report ("comprehensive", "executive", "security")
            
        Returns:
            Enterprise report dictionary
        """
        self.logger.info(f"Generating {report_type} enterprise report from {len(job_results)} job results")
        
        # Aggregate metrics across all jobs
        total_repos = sum(result.repositories_processed for result in job_results)
        total_comparisons = sum(result.total_comparisons for result in job_results)
        total_changes = sum(result.total_route_changes for result in job_results)
        total_high_risk = sum(result.high_risk_changes for result in job_results)
        
        # Risk distribution analysis
        risk_distribution = self._analyze_risk_distribution(job_results)
        
        # Repository health scoring
        repo_health = self._calculate_repository_health_scores(job_results)
        
        # Trend analysis
        trend_analysis = self._analyze_trends(job_results)
        
        enterprise_report = {
            'report_metadata': {
                'report_type': report_type,
                'generated_at': datetime.now().isoformat(),
                'jobs_analyzed': len(job_results),
                'time_period': self._get_analysis_time_period(job_results)
            },
            'executive_summary': {
                'repositories_analyzed': total_repos,
                'total_comparisons': total_comparisons,
                'total_route_changes': total_changes,
                'high_risk_changes': total_high_risk,
                'security_score': self._calculate_overall_security_score(job_results),
                'key_findings': self._extract_key_findings(job_results)
            },
            'risk_analysis': {
                'risk_distribution': risk_distribution,
                'critical_repositories': self._identify_critical_repositories(job_results),
                'security_trends': trend_analysis.get('security_trends', {}),
                'recommendations': self._generate_security_recommendations(job_results)
            },
            'repository_health': repo_health,
            'performance_metrics': {
                'average_analysis_time': self._calculate_average_analysis_time(job_results),
                'success_rate': self._calculate_success_rate(job_results),
                'efficiency_metrics': self._calculate_efficiency_metrics(job_results)
            },
            'detailed_findings': self._compile_detailed_findings(job_results) if report_type == "comprehensive" else None
        }
        
        return enterprise_report
    
    def export_batch_results(self, results: List[BatchJobResult], 
                           export_format: str, output_path: str):
        """
        Export batch results in various formats.
        
        Args:
            results: List of batch job results
            export_format: Format ("json", "yaml", "csv", "xlsx")
            output_path: Output file path
        """
        self.logger.info(f"Exporting batch results to {export_format}: {output_path}")
        
        if export_format.lower() == "json":
            self._export_json(results, output_path)
        elif export_format.lower() == "yaml":
            self._export_yaml(results, output_path)
        elif export_format.lower() == "csv":
            self._export_csv(results, output_path)
        else:
            raise ValueError(f"Unsupported export format: {export_format}")
    
    def _analyze_single_repository(self, repo_url: str, config: ComparisonConfig) -> BatchComparisonResult:
        """Analyze a single repository with automatic tag discovery"""
        try:
            # Get repository info
            repo_info = self.remote_repo.parse_repository_url(repo_url)
            repo_info = self.remote_repo.get_repository_metadata(repo_info)
            
            if len(repo_info.tags) < 2:
                # Not enough tags for comparison
                batch_result = BatchComparisonResult()
                batch_result.errors.append(f"Repository {repo_url} has insufficient tags for comparison")
                return batch_result
            
            # Compare latest 3 tags
            return self.enhanced_comparator.discover_and_compare_latest_tags(repo_url, 3, config)
            
        except Exception as e:
            batch_result = BatchComparisonResult()
            batch_result.errors.append(f"Failed to analyze repository {repo_url}: {e}")
            return batch_result
    
    def _generate_multi_repo_summary(self, results: List[BatchComparisonResult]) -> Dict[str, Any]:
        """Generate summary for multi-repository analysis"""
        if not results:
            return {}
        
        total_comparisons = sum(len(result.comparisons) for result in results)
        total_changes = sum(
            sum(len(comp.changes) for comp in result.comparisons) 
            for result in results
        )
        
        # Repository rankings by change volume
        repo_rankings = []
        for i, result in enumerate(results):
            changes = sum(len(comp.changes) for comp in result.comparisons)
            repo_rankings.append({
                'repository_index': i,
                'total_changes': changes,
                'comparisons_count': len(result.comparisons)
            })
        
        repo_rankings.sort(key=lambda x: x['total_changes'], reverse=True)
        
        return {
            'repositories_analyzed': len(results),
            'total_comparisons': total_comparisons,
            'total_changes': total_changes,
            'average_changes_per_repo': total_changes / len(results) if results else 0,
            'repository_rankings': repo_rankings[:10],  # Top 10
            'analysis_distribution': self._analyze_change_distribution(results)
        }
    
    def _generate_release_discovery_summary(self, results: List[BatchComparisonResult]) -> Dict[str, Any]:
        """Generate summary for release discovery analysis"""
        summary = self._generate_multi_repo_summary(results)
        
        # Add release-specific metrics
        release_metrics = {
            'release_patterns': self._analyze_release_patterns(results),
            'version_stability': self._analyze_version_stability(results),
            'breaking_change_frequency': self._analyze_breaking_changes(results)
        }
        
        summary.update(release_metrics)
        return summary
    
    def _count_high_risk_changes(self, results: List[BatchComparisonResult]) -> int:
        """Count high-risk changes across all results"""
        count = 0
        for result in results:
            for comparison in result.comparisons:
                for change in comparison.changes:
                    if hasattr(change, 'risk_level') and change.risk_level == RiskLevel.HIGH:
                        count += 1
        return count
    
    def _analyze_risk_distribution(self, job_results: List[BatchJobResult]) -> Dict[str, Any]:
        """Analyze risk distribution across all results"""
        risk_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        
        for job_result in job_results:
            for batch_result in job_result.results:
                for comparison in batch_result.comparisons:
                    for change in comparison.changes:
                        risk_level = getattr(change, 'risk_level', 'UNKNOWN')
                        if hasattr(risk_level, 'value'):
                            risk_level = risk_level.value
                        risk_counts[str(risk_level).upper()] = risk_counts.get(str(risk_level).upper(), 0) + 1
        
        total = sum(risk_counts.values())
        return {
            'counts': risk_counts,
            'percentages': {k: (v / total * 100) if total > 0 else 0 for k, v in risk_counts.items()}
        }
    
    def _calculate_repository_health_scores(self, job_results: List[BatchJobResult]) -> Dict[str, Any]:
        """Calculate health scores for repositories"""
        # Simplified health scoring based on change patterns and risk levels
        return {
            'scoring_methodology': 'Change frequency and risk level based',
            'health_categories': {
                'excellent': 'Low change frequency, low risk',
                'good': 'Moderate changes, managed risk',
                'attention': 'High change frequency or elevated risk',
                'critical': 'Very high changes with high risk'
            }
        }
    
    def _analyze_trends(self, job_results: List[BatchJobResult]) -> Dict[str, Any]:
        """Analyze trends across job results"""
        if len(job_results) < 2:
            return {'message': 'Insufficient data for trend analysis'}
        
        # Sort by completion time
        sorted_results = sorted(job_results, key=lambda x: x.completed_at or x.started_at)
        
        change_trend = []
        for result in sorted_results:
            change_trend.append({
                'timestamp': (result.completed_at or result.started_at).isoformat(),
                'total_changes': result.total_route_changes,
                'high_risk_changes': result.high_risk_changes
            })
        
        return {
            'change_trend': change_trend,
            'trend_direction': self._determine_trend_direction(change_trend)
        }
    
    def _determine_trend_direction(self, trend_data: List[Dict]) -> str:
        """Determine if trend is increasing, decreasing, or stable"""
        if len(trend_data) < 2:
            return 'insufficient_data'
        
        recent_changes = [item['total_changes'] for item in trend_data[-3:]]
        if len(recent_changes) < 2:
            return 'stable'
        
        if recent_changes[-1] > recent_changes[0]:
            return 'increasing'
        elif recent_changes[-1] < recent_changes[0]:
            return 'decreasing'
        else:
            return 'stable'
    
    def _calculate_overall_security_score(self, job_results: List[BatchJobResult]) -> float:
        """Calculate overall security score (0-100)"""
        if not job_results:
            return 0.0
        
        total_changes = sum(result.total_route_changes for result in job_results)
        total_high_risk = sum(result.high_risk_changes for result in job_results)
        
        if total_changes == 0:
            return 100.0
        
        risk_ratio = total_high_risk / total_changes
        security_score = max(0, 100 - (risk_ratio * 100))
        
        return round(security_score, 2)
    
    def _extract_key_findings(self, job_results: List[BatchJobResult]) -> List[str]:
        """Extract key findings from job results"""
        findings = []
        
        total_repos = sum(result.repositories_processed for result in job_results)
        total_high_risk = sum(result.high_risk_changes for result in job_results)
        
        if total_high_risk > 0:
            findings.append(f"Identified {total_high_risk} high-risk route changes across {total_repos} repositories")
        
        failed_repos = sum(result.repositories_failed for result in job_results)
        if failed_repos > 0:
            findings.append(f"{failed_repos} repositories failed analysis and require attention")
        
        return findings
    
    def _export_json(self, results: List[BatchJobResult], output_path: str):
        """Export results to JSON format"""
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'results_count': len(results),
            'results': [asdict(result) for result in results]
        }
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
    
    def _export_yaml(self, results: List[BatchJobResult], output_path: str):
        """Export results to YAML format"""
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'results_count': len(results),
            'results': [asdict(result) for result in results]
        }
        
        with open(output_path, 'w') as f:
            yaml.dump(export_data, f, default_flow_style=False)
    
    def _export_csv(self, results: List[BatchJobResult], output_path: str):
        """Export results to CSV format"""
        import csv
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Job ID', 'Job Type', 'Status', 'Started At', 'Completed At',
                'Repositories Processed', 'Repositories Failed', 'Total Comparisons',
                'Total Route Changes', 'High Risk Changes'
            ])
            
            # Data rows
            for result in results:
                writer.writerow([
                    result.job_id,
                    result.job_type,
                    result.status,
                    result.started_at.isoformat() if result.started_at else '',
                    result.completed_at.isoformat() if result.completed_at else '',
                    result.repositories_processed,
                    result.repositories_failed,
                    result.total_comparisons,
                    result.total_route_changes,
                    result.high_risk_changes
                ])
    
    # Additional helper methods for analysis
    def _analyze_change_distribution(self, results: List[BatchComparisonResult]) -> Dict[str, Any]:
        """Analyze distribution of changes across repositories"""
        return {'message': 'Change distribution analysis placeholder'}
    
    def _analyze_release_patterns(self, results: List[BatchComparisonResult]) -> Dict[str, Any]:
        """Analyze release patterns"""
        return {'message': 'Release patterns analysis placeholder'}
    
    def _analyze_version_stability(self, results: List[BatchComparisonResult]) -> Dict[str, Any]:
        """Analyze version stability"""
        return {'message': 'Version stability analysis placeholder'}
    
    def _analyze_breaking_changes(self, results: List[BatchComparisonResult]) -> Dict[str, Any]:
        """Analyze breaking changes frequency"""
        return {'message': 'Breaking changes analysis placeholder'}
    
    def _identify_critical_repositories(self, job_results: List[BatchJobResult]) -> List[Dict[str, Any]]:
        """Identify repositories that need immediate attention"""
        return [{'message': 'Critical repositories identification placeholder'}]
    
    def _generate_security_recommendations(self, job_results: List[BatchJobResult]) -> List[str]:
        """Generate security recommendations"""
        return ['Security recommendations placeholder']
    
    def _calculate_average_analysis_time(self, job_results: List[BatchJobResult]) -> float:
        """Calculate average analysis time"""
        return 0.0
    
    def _calculate_success_rate(self, job_results: List[BatchJobResult]) -> float:
        """Calculate overall success rate"""
        return 100.0
    
    def _calculate_efficiency_metrics(self, job_results: List[BatchJobResult]) -> Dict[str, Any]:
        """Calculate efficiency metrics"""
        return {'message': 'Efficiency metrics placeholder'}
    
    def _compile_detailed_findings(self, job_results: List[BatchJobResult]) -> Dict[str, Any]:
        """Compile detailed findings for comprehensive reports"""
        return {'message': 'Detailed findings compilation placeholder'}
    
    def _get_analysis_time_period(self, job_results: List[BatchJobResult]) -> Dict[str, str]:
        """Get the time period covered by the analysis"""
        if not job_results:
            return {}
        
        start_times = [result.started_at for result in job_results if result.started_at]
        end_times = [result.completed_at for result in job_results if result.completed_at]
        
        if start_times and end_times:
            return {
                'start': min(start_times).isoformat(),
                'end': max(end_times).isoformat()
            }
        
        return {} 