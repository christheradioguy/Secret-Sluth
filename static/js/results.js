/**
 * Search Results JavaScript
 * Handles filtering, sorting, export, and Vault link functionality
 * Updated: 2025-08-27 20:40:00
 */

// Global variables
let vaultUrl = '';

// Initialize results page
document.addEventListener('DOMContentLoaded', function() {
    // Get vault URL from template
    vaultUrl = document.querySelector('meta[name="vault-url"]')?.getAttribute('content') || '';
    
    // Initialize filters
    initializeFilters();
    
    // Initialize tooltips
    initializeTooltips();
});

// Initialize filter functionality
function initializeFilters() {
    const filterEngine = document.getElementById('filterEngine');
    const filterType = document.getElementById('filterType');
    const sortBy = document.getElementById('sortBy');
    
    if (filterEngine && filterType && sortBy) {
        // Apply filters when changed
        [filterEngine, filterType, sortBy].forEach(element => {
            element.addEventListener('change', applyFilters);
        });
    }
}

// Apply filters and update URL
function applyFilters() {
    const filterEngine = document.getElementById('filterEngine');
    const filterType = document.getElementById('filterType');
    const sortBy = document.getElementById('sortBy');
    
    const params = new URLSearchParams();
    
    if (filterEngine && filterEngine.value) params.append('engine_path', filterEngine.value);
    if (filterType && filterType.value) params.append('match_type', filterType.value);
    if (sortBy && sortBy.value) params.append('sort_by', sortBy.value);
    
    window.location.href = window.location.pathname + '?' + params.toString();
}

// Initialize tooltips
function initializeTooltips() {
    // Initialize Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Export functionality
function exportResults(format) {
    const params = new URLSearchParams();
    params.append('format', format);
    params.append('include_secret_data', 'false');
    
    window.location.href = '/search/export?' + params.toString();
}

// Clear results functionality
function clearResults() {
    if (confirm('Are you sure you want to clear all search results? This action cannot be undone.')) {
        fetch('/search/clear', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showToast('Cleared!', data.message, 'success');
                
                // Redirect to search form
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 2000);
            } else {
                showToast('Error', 'Failed to clear results: ' + data.error, 'danger');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showToast('Error', 'Failed to clear results', 'danger');
        });
    }
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        showToast('Copied!', 'Path copied to clipboard', 'success');
    }).catch(function() {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        showToast('Copied!', 'Path copied to clipboard', 'success');
    });
}



// Open Vault link
function openVaultLink(engineType, enginePath, displayPath) {
    console.log('=== VAULT LINK DEBUG ===');
    console.log('openVaultLink called with:', { engineType, enginePath, displayPath });
    console.log('Function signature updated - using separate parameters');
    
    // Get vault URL from meta tag or use the global variable
    const currentVaultUrl = vaultUrl || document.querySelector('meta[name="vault-url"]')?.getAttribute('content') || '';
    
    if (!currentVaultUrl) {
        showToast('Error', 'Vault URL not available', 'danger');
        return;
    }
    
    // URL encode the display path properly
    // Encode spaces and forward slashes
    const encodedSubpath = displayPath.replace(/ /g, '%20').replace(/\//g, '%2F');
    console.log('URL encoding:', { displayPath, encodedSubpath });
    
    // Construct the Vault UI URL based on engine type
    let vaultUiUrl;
    if (engineType === 'kv') {
        // KV stores: /ui/vault/secrets/engine_name/kv/secret_path
        vaultUiUrl = `${currentVaultUrl}/ui/vault/secrets/${enginePath}/kv/${encodedSubpath}`;
    } else if (engineType === 'database') {
        // Database: /ui/vault/secrets/engine_name/database/secret_path
        vaultUiUrl = `${currentVaultUrl}/ui/vault/secrets/${enginePath}/database/${encodedSubpath}`;
    } else if (engineType === 'ssh') {
        // SSH: /ui/vault/secrets/engine_name/ssh/secret_path
        vaultUiUrl = `${currentVaultUrl}/ui/vault/secrets/${enginePath}/ssh/${encodedSubpath}`;
    } else if (engineType === 'pki') {
        // PKI: /ui/vault/secrets/engine_name/pki/secret_path
        vaultUiUrl = `${currentVaultUrl}/ui/vault/secrets/${enginePath}/pki/${encodedSubpath}`;
    } else if (engineType === 'transit') {
        // Transit: /ui/vault/secrets/engine_name/transit/secret_path
        vaultUiUrl = `${currentVaultUrl}/ui/vault/secrets/${enginePath}/transit/${encodedSubpath}`;
    } else if (engineType === 'aws') {
        // AWS: /ui/vault/secrets/engine_name/aws/secret_path
        vaultUiUrl = `${currentVaultUrl}/ui/vault/secrets/${enginePath}/aws/${encodedSubpath}`;
    } else if (engineType === 'azure') {
        // Azure: /ui/vault/secrets/engine_name/azure/secret_path
        vaultUiUrl = `${currentVaultUrl}/ui/vault/secrets/${enginePath}/azure/${encodedSubpath}`;
    } else if (engineType === 'gcp') {
        // GCP: /ui/vault/secrets/engine_name/gcp/secret_path
        vaultUiUrl = `${currentVaultUrl}/ui/vault/secrets/${enginePath}/gcp/${encodedSubpath}`;
    } else {
        // Generic fallback: /ui/vault/secrets/engine_name/secret_path
        const encodedPath = encodeURIComponent(displayPath);
        vaultUiUrl = `${currentVaultUrl}/ui/vault/secrets/${enginePath}/${encodedPath}`;
    }
    
    console.log('Final vault UI URL:', vaultUiUrl);
    
    // Open in new tab
    window.open(vaultUiUrl, '_blank');
    
    showToast('Vault Link', 'Opening secret in Vault UI...', 'success');
}



// Show toast notification
function showToast(title, message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = 'toast position-fixed top-0 end-0 m-3';
    
    const iconClass = type === 'success' ? 'fas fa-check' : 
                     type === 'danger' ? 'fas fa-exclamation-triangle' : 
                     'fas fa-info-circle';
    
    toast.innerHTML = `
        <div class="toast-header">
            <i class="${iconClass} text-${type}"></i>
            <strong class="me-auto">${title}</strong>
            <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
        </div>
        <div class="toast-body">
            ${message}
        </div>
    `;
    
    document.body.appendChild(toast);
    new bootstrap.Toast(toast).show();
    
    setTimeout(() => {
        if (document.body.contains(toast)) {
            document.body.removeChild(toast);
        }
    }, 3000);
}



// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + E to export
    if ((e.ctrlKey || e.metaKey) && e.key === 'e') {
        e.preventDefault();
        exportResults('json');
    }
    
    // Ctrl/Cmd + F to focus search
    if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        e.preventDefault();
        const searchInput = document.querySelector('input[type="text"]');
        if (searchInput) {
            searchInput.focus();
        }
    }
    
    // Escape to close modals
    if (e.key === 'Escape') {
        const modals = document.querySelectorAll('.modal.show');
        modals.forEach(modal => {
            const modalInstance = bootstrap.Modal.getInstance(modal);
            if (modalInstance) {
                modalInstance.hide();
            }
        });
    }
});

// Responsive table handling
function handleResponsiveTable() {
    const tables = document.querySelectorAll('.table-responsive');
    tables.forEach(table => {
        const tableElement = table.querySelector('table');
        if (tableElement && tableElement.scrollWidth > table.clientWidth) {
            table.classList.add('has-horizontal-scroll');
        }
    });
}

// Initialize responsive table handling
document.addEventListener('DOMContentLoaded', handleResponsiveTable);
window.addEventListener('resize', handleResponsiveTable);
