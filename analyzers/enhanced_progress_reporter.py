#!/usr/bin/env python3
"""
Enhanced Progress Reporter for RouteHawk Scanner

Phase 4: Performance & Optimization
Provides real-time progress updates, ETA calculations, and performance metrics
for long-running scanning operations.
"""

import time
import threading
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.live import Live
from rich.table import Table
from rich.panel import Panel


@dataclass
class ProgressMetrics:
    """Progress tracking metrics"""
    total_items: int = 0
    completed_items: int = 0
    current_stage: str = "Initializing"
    start_time: float = 0.0
    items_per_second: float = 0.0
    estimated_completion: Optional[datetime] = None
    memory_usage_mb: float = 0.0
    cache_hit_rate: float = 0.0
    
    @property
    def progress_percentage(self) -> float:
        return (self.completed_items / self.total_items * 100) if self.total_items > 0 else 0.0
    
    @property
    def elapsed_time(self) -> float:
        return time.time() - self.start_time if self.start_time > 0 else 0.0


class EnhancedProgressReporter:
    """Enhanced progress reporter with real-time updates and performance metrics"""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.metrics = ProgressMetrics()
        self.is_running = False
        self.update_thread = None
        self.live_display = None
        self.progress_callback: Optional[Callable[[ProgressMetrics], None]] = None
        
        # Performance tracking
        self._last_update_time = 0.0
        self._last_completed_count = 0
        self._update_interval = 0.5  # Update every 500ms
        
    def start_progress(self, total_items: int, stage: str = "Processing"):
        """Start progress tracking"""
        self.metrics.total_items = total_items
        self.metrics.completed_items = 0
        self.metrics.current_stage = stage
        self.metrics.start_time = time.time()
        self._last_update_time = self.metrics.start_time
        self._last_completed_count = 0
        self.is_running = True
        
        # Start live display
        self._create_live_display()
        
        # Start update thread
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
    
    def update_progress(self, completed_items: int, stage: Optional[str] = None,
                       memory_usage_mb: Optional[float] = None,
                       cache_hit_rate: Optional[float] = None):
        """Update progress metrics"""
        if not self.is_running:
            return
        
        self.metrics.completed_items = completed_items
        
        if stage:
            self.metrics.current_stage = stage
        
        if memory_usage_mb is not None:
            self.metrics.memory_usage_mb = memory_usage_mb
        
        if cache_hit_rate is not None:
            self.metrics.cache_hit_rate = cache_hit_rate
        
        # Calculate performance metrics
        current_time = time.time()
        time_diff = current_time - self._last_update_time
        
        if time_diff >= self._update_interval:
            completed_diff = completed_items - self._last_completed_count
            if time_diff > 0:
                self.metrics.items_per_second = completed_diff / time_diff
            
            # Calculate ETA
            remaining_items = self.metrics.total_items - self.metrics.completed_items
            if self.metrics.items_per_second > 0 and remaining_items > 0:
                eta_seconds = remaining_items / self.metrics.items_per_second
                self.metrics.estimated_completion = datetime.now() + timedelta(seconds=eta_seconds)
            
            self._last_update_time = current_time
            self._last_completed_count = completed_items
        
        # Call progress callback if set
        if self.progress_callback:
            self.progress_callback(self.metrics)
    
    def set_progress_callback(self, callback: Callable[[ProgressMetrics], None]):
        """Set callback function for progress updates"""
        self.progress_callback = callback
    
    def stop_progress(self):
        """Stop progress tracking"""
        self.is_running = False
        
        if self.update_thread and self.update_thread.is_alive():
            self.update_thread.join(timeout=1.0)
        
        if self.live_display:
            self.live_display.stop()
            
        # Display final summary
        self._display_final_summary()
    
    def _create_live_display(self):
        """Create rich live display for progress"""
        def generate_display():
            return self._create_progress_table()
        
        self.live_display = Live(
            generate_display(),
            console=self.console,
            refresh_per_second=2,
            transient=False
        )
        self.live_display.start()
    
    def _create_progress_table(self) -> Panel:
        """Create progress display table"""
        table = Table(show_header=False, show_edge=False, pad_edge=False)
        table.add_column("Metric", style="cyan", width=20)
        table.add_column("Value", style="white")
        
        # Progress bar
        progress_bar = "█" * int(self.metrics.progress_percentage / 5)
        progress_bar += "░" * (20 - len(progress_bar))
        
        # Format time
        elapsed = self.metrics.elapsed_time
        elapsed_str = f"{int(elapsed//60):02d}:{int(elapsed%60):02d}"
        
        # ETA
        eta_str = "Calculating..."
        if self.metrics.estimated_completion:
            eta = self.metrics.estimated_completion
            eta_str = eta.strftime("%H:%M:%S")
        
        # Add rows
        table.add_row("Progress", f"{progress_bar} {self.metrics.progress_percentage:.1f}%")
        table.add_row("Items", f"{self.metrics.completed_items:,} / {self.metrics.total_items:,}")
        table.add_row("Rate", f"{self.metrics.items_per_second:.1f} items/sec")
        table.add_row("Elapsed", elapsed_str)
        table.add_row("ETA", eta_str)
        table.add_row("Stage", self.metrics.current_stage)
        
        if self.metrics.memory_usage_mb > 0:
            table.add_row("Memory", f"{self.metrics.memory_usage_mb:.1f} MB")
        
        if self.metrics.cache_hit_rate > 0:
            table.add_row("Cache Hit Rate", f"{self.metrics.cache_hit_rate:.1f}%")
        
        return Panel(
            table,
            title="[bold blue]🚀 RouteHawk Scanning Progress[/bold blue]",
            title_align="left",
            border_style="blue"
        )
    
    def _update_loop(self):
        """Background update loop for live display"""
        while self.is_running:
            try:
                if self.live_display:
                    self.live_display.update(self._create_progress_table())
                time.sleep(0.5)
            except Exception:
                break
    
    def _display_final_summary(self):
        """Display final progress summary"""
        elapsed = self.metrics.elapsed_time
        rate = self.metrics.completed_items / elapsed if elapsed > 0 else 0
        
        summary_table = Table(title="📊 Scan Summary", show_header=True)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Total Items Processed", f"{self.metrics.completed_items:,}")
        summary_table.add_row("Total Time", f"{int(elapsed//60):02d}:{int(elapsed%60):02d}")
        summary_table.add_row("Average Rate", f"{rate:.1f} items/sec")
        summary_table.add_row("Completion", "100%" if self.metrics.completed_items >= self.metrics.total_items else f"{self.metrics.progress_percentage:.1f}%")
        
        if self.metrics.memory_usage_mb > 0:
            summary_table.add_row("Peak Memory", f"{self.metrics.memory_usage_mb:.1f} MB")
        
        if self.metrics.cache_hit_rate > 0:
            summary_table.add_row("Final Cache Hit Rate", f"{self.metrics.cache_hit_rate:.1f}%")
        
        self.console.print()
        self.console.print(summary_table)


class BatchProgressTracker:
    """Progress tracker for batch operations"""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.batch_metrics: Dict[str, ProgressMetrics] = {}
        self.overall_progress = ProgressMetrics()
        
    def add_batch_item(self, item_id: str, total_items: int, description: str = ""):
        """Add a new batch item to track"""
        metrics = ProgressMetrics()
        metrics.total_items = total_items
        metrics.current_stage = description or item_id
        metrics.start_time = time.time()
        self.batch_metrics[item_id] = metrics
        
        # Update overall progress
        self.overall_progress.total_items = sum(m.total_items for m in self.batch_metrics.values())
    
    def update_batch_item(self, item_id: str, completed_items: int, stage: Optional[str] = None):
        """Update progress for a specific batch item"""
        if item_id not in self.batch_metrics:
            return
        
        metrics = self.batch_metrics[item_id]
        metrics.completed_items = completed_items
        
        if stage:
            metrics.current_stage = stage
        
        # Update overall progress
        self.overall_progress.completed_items = sum(m.completed_items for m in self.batch_metrics.values())
    
    def complete_batch_item(self, item_id: str):
        """Mark a batch item as complete"""
        if item_id not in self.batch_metrics:
            return
        
        metrics = self.batch_metrics[item_id]
        metrics.completed_items = metrics.total_items
        metrics.current_stage = "Completed"
        
        # Update overall progress
        self.overall_progress.completed_items = sum(m.completed_items for m in self.batch_metrics.values())
    
    def display_batch_summary(self):
        """Display summary of all batch operations"""
        table = Table(title="📦 Batch Operations Summary", show_header=True)
        table.add_column("Item", style="cyan")
        table.add_column("Progress", style="white")
        table.add_column("Status", style="green")
        
        for item_id, metrics in self.batch_metrics.items():
            progress_pct = metrics.progress_percentage
            status = "✅ Complete" if progress_pct >= 100 else f"🔄 {metrics.current_stage}"
            progress_bar = "█" * int(progress_pct / 10) + "░" * (10 - int(progress_pct / 10))
            
            table.add_row(
                item_id,
                f"{progress_bar} {progress_pct:.1f}%",
                status
            )
        
        self.console.print()
        self.console.print(table)
        
        # Overall summary
        overall_pct = self.overall_progress.progress_percentage
        self.console.print(f"\n[bold green]Overall Progress: {overall_pct:.1f}% ({self.overall_progress.completed_items:,} / {self.overall_progress.total_items:,} items)[/bold green]") 