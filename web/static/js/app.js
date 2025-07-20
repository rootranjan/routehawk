/**
 * RouteHawk Attack Surface Scanner - Web Interface JavaScript
 * Provides common functionality and utilities for the web interface
 */

// Global configuration
const AppConfig = {
    apiBaseUrl: '/api',
    refreshInterval: 30000, // 30 seconds
    maxRetries: 3,
    charts: {},
    activeModals: new Set()
};

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

/**
 * Initialize the application
 */
function initializeApp() {
    // Initialize tooltips
    initializeTooltips();
    
    // Initialize copy-to-clipboard functionality
    initializeCopyButtons();
    
    // Initialize auto-refresh
    initializeAutoRefresh();
    
    // Initialize keyboard shortcuts
    initializeKeyboardShortcuts();
    
    // Initialize progress indicators
    initializeProgressIndicators();
    
    console.log('RouteHawk Attack Surface Scanner initialized');
}

/**
 * Initialize Bootstrap tooltips
 */
function initializeTooltips() {
    const tooltipElements = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltipElements.forEach(element => {
        new bootstrap.Tooltip(element);
    });
}

/**
 * Initialize copy-to-clipboard buttons
 */
function initializeCopyButtons() {
    const copyButtons = document.querySelectorAll('.copy-btn');
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const target = this.getAttribute('data-copy-target');
            const element = document.querySelector(target);
            
            if (element) {
                copyToClipboard(element.textContent || element.value);
                showNotification('Copied to clipboard', 'success');
            }
        });
    });
}

/**
 * Initialize auto-refresh functionality
 */
function initializeAutoRefresh() {
    const autoRefreshElements = document.querySelectorAll('[data-auto-refresh]');
    
    autoRefreshElements.forEach(element => {
        const interval = parseInt(element.getAttribute('data-auto-refresh')) || AppConfig.refreshInterval;
        const url = element.getAttribute('data-refresh-url');
        
        if (url) {
            setInterval(() => {
                refreshElement(element, url);
            }, interval);
        }
    });
}

/**
 * Initialize keyboard shortcuts
 */
function initializeKeyboardShortcuts() {
    document.addEventListener('keydown', function(event) {
        // Ctrl/Cmd + K: Focus search
        if ((event.ctrlKey || event.metaKey) && event.key === 'k') {
            event.preventDefault();
            const searchInput = document.querySelector('#search-input, .search-input');
            if (searchInput) {
                searchInput.focus();
            }
        }
        
        // Ctrl/Cmd + Enter: Start scan (if on scan page)
        if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
            const scanButton = document.querySelector('#startScanBtn');
            if (scanButton && !scanButton.disabled) {
                scanButton.click();
            }
        }
        
        // Escape: Close modals
        if (event.key === 'Escape') {
            closeActiveModals();
        }
    });
}

/**
 * Initialize progress indicators
 */
function initializeProgressIndicators() {
    const progressBars = document.querySelectorAll('.progress-bar[data-animate]');
    
    progressBars.forEach(bar => {
        const target = parseInt(bar.getAttribute('data-target')) || 0;
        animateProgressBar(bar, target);
    });
}

/**
 * Copy text to clipboard
 */
function copyToClipboard(text) {
    if (navigator.clipboard) {
        return navigator.clipboard.writeText(text);
    } else {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        return Promise.resolve();
    }
}

/**
 * Show notification toast
 */
function showNotification(message, type = 'info', duration = 3000) {
    const toastContainer = getOrCreateToastContainer();
    
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <i class="bi bi-${getIconForType(type)} me-2"></i>
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    
    const bsToast = new bootstrap.Toast(toast, { delay: duration });
    bsToast.show();
    
    // Remove toast element after it's hidden
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}

/**
 * Get or create toast container
 */
function getOrCreateToastContainer() {
    let container = document.querySelector('.toast-container');
    
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container position-fixed top-0 end-0 p-3';
        container.style.zIndex = '9999';
        document.body.appendChild(container);
    }
    
    return container;
}

/**
 * Get icon for notification type
 */
function getIconForType(type) {
    const icons = {
        success: 'check-circle',
        danger: 'exclamation-triangle',
        warning: 'exclamation-triangle',
        info: 'info-circle',
        primary: 'info-circle'
    };
    
    return icons[type] || 'info-circle';
}

/**
 * Animate progress bar to target value
 */
function animateProgressBar(bar, target, duration = 1000) {
    const start = parseInt(bar.style.width) || 0;
    const range = target - start;
    const startTime = performance.now();
    
    function updateProgress(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const current = start + (range * easeOutCubic(progress));
        
        bar.style.width = `${current}%`;
        bar.setAttribute('aria-valuenow', current);
        bar.textContent = `${Math.round(current)}%`;
        
        if (progress < 1) {
            requestAnimationFrame(updateProgress);
        }
    }
    
    requestAnimationFrame(updateProgress);
}

/**
 * Easing function for animations
 */
function easeOutCubic(t) {
    return 1 - Math.pow(1 - t, 3);
}

/**
 * Refresh element content from URL
 */
async function refreshElement(element, url) {
    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const html = await response.text();
        element.innerHTML = html;
        
        // Re-initialize components in refreshed content
        initializeTooltips();
        initializeCopyButtons();
        
    } catch (error) {
        console.error('Failed to refresh element:', error);
        showNotification('Failed to refresh content', 'danger');
    }
}

/**
 * Close all active modals
 */
function closeActiveModals() {
    const modals = document.querySelectorAll('.modal.show');
    modals.forEach(modal => {
        const bsModal = bootstrap.Modal.getInstance(modal);
        if (bsModal) {
            bsModal.hide();
        }
    });
}

/**
 * Format file size in human-readable format
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Format date in human-readable format
 */
function formatDate(date) {
    if (!date) return 'N/A';
    
    const d = new Date(date);
    const now = new Date();
    const diff = now - d;
    
    // Less than a minute
    if (diff < 60000) {
        return 'Just now';
    }
    
    // Less than an hour
    if (diff < 3600000) {
        const minutes = Math.floor(diff / 60000);
        return `${minutes} minute${minutes !== 1 ? 's' : ''} ago`;
    }
    
    // Less than a day
    if (diff < 86400000) {
        const hours = Math.floor(diff / 3600000);
        return `${hours} hour${hours !== 1 ? 's' : ''} ago`;
    }
    
    // Default format
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
}

/**
 * Debounce function to limit function calls
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * API helper functions
 */
const API = {
    /**
     * Make GET request
     */
    async get(endpoint) {
        const response = await fetch(`${AppConfig.apiBaseUrl}${endpoint}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return response.json();
    },

    /**
     * Make POST request
     */
    async post(endpoint, data) {
        const response = await fetch(`${AppConfig.apiBaseUrl}${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return response.json();
    },

    /**
     * Make PUT request
     */
    async put(endpoint, data) {
        const response = await fetch(`${AppConfig.apiBaseUrl}${endpoint}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return response.json();
    },

    /**
     * Make DELETE request
     */
    async delete(endpoint) {
        const response = await fetch(`${AppConfig.apiBaseUrl}${endpoint}`, {
            method: 'DELETE'
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return response.json();
    }
};

/**
 * Security utilities
 */
const Security = {
    /**
     * Get severity color class
     */
    getSeverityClass(severity) {
        const classes = {
            'CRITICAL': 'danger',
            'HIGH': 'danger',
            'MEDIUM': 'warning',
            'LOW': 'success'
        };
        return classes[severity] || 'secondary';
    },

    /**
     * Get framework color class
     */
    getFrameworkClass(framework) {
        const classes = {
            'NestJS': 'framework-nestjs',
            'Express': 'framework-express',
            'Next.js': 'framework-nextjs',
            'Go HTTP': 'framework-go',
            'FastAPI': 'framework-python',
            'Django': 'framework-python',
            'Infrastructure': 'framework-infrastructure'
        };
        return classes[framework] || 'secondary';
    },

    /**
     * Get method color class
     */
    getMethodClass(method) {
        const classes = {
            'GET': 'method-get',
            'POST': 'method-post',
            'PUT': 'method-put',
            'DELETE': 'method-delete',
            'PATCH': 'method-patch'
        };
        return classes[method] || 'secondary';
    }
};

/**
 * Chart utilities
 */
const Charts = {
    /**
     * Default chart colors
     */
    colors: {
        primary: '#0d6efd',
        secondary: '#6c757d',
        success: '#198754',
        danger: '#dc3545',
        warning: '#ffc107',
        info: '#0dcaf0'
    },

    /**
     * Create or update pie chart
     */
    createPieChart(canvas, data, options = {}) {
        const ctx = canvas.getContext('2d');
        
        const defaultOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        };

        const config = {
            type: 'doughnut',
            data: data,
            options: { ...defaultOptions, ...options }
        };

        // Destroy existing chart if it exists
        if (AppConfig.charts[canvas.id]) {
            AppConfig.charts[canvas.id].destroy();
        }

        AppConfig.charts[canvas.id] = new Chart(ctx, config);
        return AppConfig.charts[canvas.id];
    },

    /**
     * Create or update bar chart
     */
    createBarChart(canvas, data, options = {}) {
        const ctx = canvas.getContext('2d');
        
        const defaultOptions = {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        };

        const config = {
            type: 'bar',
            data: data,
            options: { ...defaultOptions, ...options }
        };

        // Destroy existing chart if it exists
        if (AppConfig.charts[canvas.id]) {
            AppConfig.charts[canvas.id].destroy();
        }

        AppConfig.charts[canvas.id] = new Chart(ctx, config);
        return AppConfig.charts[canvas.id];
    }
};

/**
 * Table utilities
 */
const Tables = {
    /**
     * Initialize sortable tables
     */
    initializeSortable() {
        const tables = document.querySelectorAll('.table-sortable');
        tables.forEach(table => {
            this.makeSortable(table);
        });
    },

    /**
     * Make table sortable
     */
    makeSortable(table) {
        const headers = table.querySelectorAll('th[data-sort]');
        
        headers.forEach(header => {
            header.style.cursor = 'pointer';
            header.innerHTML += ' <i class="bi bi-arrow-down-up text-muted"></i>';
            
            header.addEventListener('click', () => {
                const column = header.getAttribute('data-sort');
                const type = header.getAttribute('data-sort-type') || 'string';
                this.sortTable(table, column, type);
            });
        });
    },

    /**
     * Sort table by column
     */
    sortTable(table, column, type) {
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        
        rows.sort((a, b) => {
            const aVal = a.querySelector(`[data-sort-value="${column}"]`)?.textContent || '';
            const bVal = b.querySelector(`[data-sort-value="${column}"]`)?.textContent || '';
            
            if (type === 'number') {
                return parseFloat(aVal) - parseFloat(bVal);
            } else if (type === 'date') {
                return new Date(aVal) - new Date(bVal);
            } else {
                return aVal.localeCompare(bVal);
            }
        });
        
        // Clear and re-append sorted rows
        tbody.innerHTML = '';
        rows.forEach(row => tbody.appendChild(row));
    }
};

// Export for global access
window.AppConfig = AppConfig;
window.API = API;
window.Security = Security;
window.Charts = Charts;
window.Tables = Tables;
window.showNotification = showNotification;
window.formatFileSize = formatFileSize;
window.formatDate = formatDate;
window.debounce = debounce; 

function startScan() {
    const repoPath = document.getElementById('repoPath').value;
    const useAI = document.getElementById('useAI').checked;
    
    if (!repoPath) {
        updateScanResults('Error: Please enter a repository path', 'error');
        return;
    }
    
    // Update UI
    document.getElementById('scanButton').disabled = true;
    document.getElementById('scanButton').innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Scanning...';
    updateScanResults('Starting scan via CLI backend...', 'info');
    
    // Call CLI backend endpoint
    fetch('/api/scan/cli-backend', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            repo_path: repoPath,
            use_ai: useAI
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // CLI backend succeeded
            const summary = data.summary;
            updateScanResults(`
                <div class="alert alert-success">
                    <h5><i class="bi bi-check-circle"></i> Scan Completed Successfully via CLI Backend</h5>
                    <p><strong>Repository:</strong> ${data.repository_path}</p>
                    <hr>
                    <div class="row">
                        <div class="col-md-6">
                            <h6>Route Summary:</h6>
                            <ul class="list-unstyled">
                                <li><i class="bi bi-globe"></i> <strong>Total Routes:</strong> ${summary.total_routes}</li>
                                <li><i class="bi bi-exclamation-triangle text-danger"></i> <strong>High Risk:</strong> ${summary.high_risk_routes}</li>
                                <li><i class="bi bi-exclamation-circle text-warning"></i> <strong>Medium Risk:</strong> ${summary.medium_risk_routes}</li>
                                <li><i class="bi bi-info-circle text-success"></i> <strong>Low Risk:</strong> ${summary.low_risk_routes}</li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h6>Scan Details:</h6>
                            <ul class="list-unstyled">
                                <li><i class="bi bi-hdd"></i> <strong>Services Found:</strong> ${summary.services_found}</li>
                                <li><i class="bi bi-clock"></i> <strong>Duration:</strong> ${summary.scan_duration}s</li>
                                <li><i class="bi bi-code-square"></i> <strong>Frameworks:</strong> ${data.frameworks_detected.join(', ')}</li>
                            </ul>
                        </div>
                    </div>
                    ${data.json_report_path ? `<p class="mt-2"><i class="bi bi-file-earmark-text"></i> <strong>JSON Report:</strong> ${data.json_report_path}</p>` : ''}
                </div>
            `, 'success');
        } else {
            // CLI backend failed
            updateScanResults(`
                <div class="alert alert-danger">
                    <h5><i class="bi bi-x-circle"></i> CLI Backend Scan Failed</h5>
                    <p><strong>Error:</strong> ${data.error}</p>
                    ${data.stderr ? `<p><strong>Error Details:</strong> <code>${data.stderr}</code></p>` : ''}
                </div>
            `, 'error');
        }
    })
    .catch(error => {
        console.error('Scan error:', error);
        updateScanResults(`
            <div class="alert alert-danger">
                <h5><i class="bi bi-x-circle"></i> Network Error</h5>
                <p>Failed to communicate with CLI backend: ${error.message}</p>
            </div>
        `, 'error');
    })
    .finally(() => {
        // Reset button
        document.getElementById('scanButton').disabled = false;
        document.getElementById('scanButton').innerHTML = '<i class="bi bi-play-circle"></i> Start Scan';
    });
} 