/**
 * Engine Selection JavaScript
 * 
 * Handles the engine selection interface including:
 * - Search and filtering
 * - Bulk selection operations
 * - Form submission
 * - Real-time updates
 */

console.log('Engine selection JavaScript loaded!');

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM Content Loaded event fired!');
    // Initialize the engine selection interface
    initializeEngineSelection();
});

function initializeEngineSelection() {
    console.log('Initializing engine selection...');
    
    // Initialize counters and summary
    updateSelectionSummary();
    
    // Set up event listeners
    setupEventListeners();
    
    // Populate filter dropdowns
    populateFilterDropdowns();
    
    // Update initial counts
    updateCounts();
    
    console.log('Engine selection initialization complete');
}

function setupEventListeners() {
    console.log('Setting up event listeners...');
    
    // Search functionality
    const searchInput = document.getElementById('engine-search');
    if (searchInput) {
        console.log('Found search input, adding listener');
        searchInput.addEventListener('input', debounce(performSearch, 300));
    } else {
        console.log('Search input not found');
    }
    
    // Filter dropdowns
    const typeFilter = document.getElementById('type-filter');
    if (typeFilter) {
        console.log('Found type filter, adding listener');
        typeFilter.addEventListener('change', performFilter);
    } else {
        console.log('Type filter not found');
    }
    
    const accessibilityFilter = document.getElementById('accessibility-filter');
    if (accessibilityFilter) {
        console.log('Found accessibility filter, adding listener');
        accessibilityFilter.addEventListener('change', performFilter);
    } else {
        console.log('Accessibility filter not found');
    }
    
    // Bulk action buttons
    const selectAllBtn = document.getElementById('select-all');
    if (selectAllBtn) {
        console.log('Found select all button, adding listener');
        selectAllBtn.addEventListener('click', function() {
            console.log('Select all clicked');
            selectAllEngines();
        });
    } else {
        console.log('Select all button not found');
    }
    
    const deselectAllBtn = document.getElementById('deselect-all');
    if (deselectAllBtn) {
        console.log('Found deselect all button, adding listener');
        deselectAllBtn.addEventListener('click', function() {
            console.log('Deselect all clicked');
            deselectAllEngines();
        });
    } else {
        console.log('Deselect all button not found');
    }
    
    const selectAccessibleBtn = document.getElementById('select-accessible');
    if (selectAccessibleBtn) {
        console.log('Found select accessible button, adding listener');
        selectAccessibleBtn.addEventListener('click', function() {
            console.log('Select accessible clicked');
            selectAccessibleEngines();
        });
    } else {
        console.log('Select accessible button not found');
    }
    
                    const selectKvOnlyBtn = document.getElementById('select-kv-only');
                if (selectKvOnlyBtn) {
                    console.log('Found select KV only button, adding listener');
                    selectKvOnlyBtn.addEventListener('click', function() {
                        console.log('Select KV only clicked');
                        selectKvEngines();
                    });
                } else {
                    console.log('Select KV only button not found');
                }
                
                const expandAllBtn = document.getElementById('expand-all');
                if (expandAllBtn) {
                    console.log('Found expand all button, adding listener');
                    expandAllBtn.addEventListener('click', function() {
                        console.log('Expand all clicked');
                        expandAllGroups();
                    });
                } else {
                    console.log('Expand all button not found');
                }
                
                const collapseAllBtn = document.getElementById('collapse-all');
                if (collapseAllBtn) {
                    console.log('Found collapse all button, adding listener');
                    collapseAllBtn.addEventListener('click', function() {
                        console.log('Collapse all clicked');
                        collapseAllGroups();
                    });
                } else {
                    console.log('Collapse all button not found');
                }
    
    // Checkbox change events
    document.addEventListener('change', function(e) {
        if (e.target.type === 'checkbox' && e.target.closest('.engine-item')) {
            console.log('Checkbox changed:', e.target.value);
            updateSelectionSummary();
        }
    });
    
    // Form submission
    const form = document.getElementById('engine-selection-form');
    if (form) {
        console.log('Found form, adding submit listener');
        form.addEventListener('submit', handleFormSubmission);
    } else {
        console.log('Form not found');
    }
    
    console.log('Event listeners setup complete');
}

function populateFilterDropdowns() {
    const typeFilter = document.getElementById('type-filter');
    if (!typeFilter) return;
    
    // Get all engine types from the page
    const engineItems = document.querySelectorAll('.engine-item');
    const types = new Set();
    
    engineItems.forEach(item => {
        const type = item.dataset.type;
        if (type) {
            types.add(type);
        }
    });
    
    // Add options to the dropdown
    types.forEach(type => {
        const option = document.createElement('option');
        option.value = type;
        option.textContent = type.charAt(0).toUpperCase() + type.slice(1);
        typeFilter.appendChild(option);
    });
}

function performSearch() {
    const searchTerm = document.getElementById('engine-search').value.toLowerCase();
    const engineItems = document.querySelectorAll('.engine-item');
    
    engineItems.forEach(item => {
        const path = item.dataset.path.toLowerCase();
        const type = item.dataset.type.toLowerCase();
        const tags = item.dataset.tags.toLowerCase();
        
        const matches = path.includes(searchTerm) || 
                       type.includes(searchTerm) || 
                       tags.includes(searchTerm);
        
        if (matches) {
            item.style.display = '';
        } else {
            item.style.display = 'none';
        }
    });
    
    updateCounts();
}

function performFilter() {
    const typeFilter = document.getElementById('type-filter').value;
    const accessibilityFilter = document.getElementById('accessibility-filter').value;
    const engineItems = document.querySelectorAll('.engine-item');
    
    engineItems.forEach(item => {
        const type = item.dataset.type;
        const accessible = item.dataset.accessible === 'true';
        
        let show = true;
        
        // Type filter
        if (typeFilter && type !== typeFilter) {
            show = false;
        }
        
        // Accessibility filter
        if (accessibilityFilter === 'accessible' && !accessible) {
            show = false;
        } else if (accessibilityFilter === 'inaccessible' && accessible) {
            show = false;
        }
        
        item.style.display = show ? '' : 'none';
    });
    
    updateCounts();
}

function selectAllEngines() {
    console.log('selectAllEngines called');
    const visibleItems = document.querySelectorAll('.engine-item:not([style*="display: none"])');
    console.log('Found visible items:', visibleItems.length);
    
    visibleItems.forEach((item, index) => {
        const checkbox = item.querySelector('input[type="checkbox"]');
        if (checkbox) {
            console.log(`Checking checkbox ${index}:`, checkbox.value);
            checkbox.checked = true;
        } else {
            console.log(`No checkbox found in item ${index}`);
        }
    });
    
    console.log('Calling updateSelectionSummary');
    updateSelectionSummary();
}

function deselectAllEngines() {
    console.log('deselectAllEngines called');
    const checkboxes = document.querySelectorAll('.engine-item input[type="checkbox"]');
    console.log('Found checkboxes:', checkboxes.length);
    
    checkboxes.forEach((checkbox, index) => {
        console.log(`Unchecking checkbox ${index}:`, checkbox.value);
        checkbox.checked = false;
    });
    
    console.log('Calling updateSelectionSummary');
    updateSelectionSummary();
}

function selectAccessibleEngines() {
    const visibleItems = document.querySelectorAll('.engine-item:not([style*="display: none"])');
    visibleItems.forEach(item => {
        if (item.dataset.accessible === 'true') {
            const checkbox = item.querySelector('input[type="checkbox"]');
            if (checkbox) {
                checkbox.checked = true;
            }
        }
    });
    updateSelectionSummary();
}

function selectKvEngines() {
    const visibleItems = document.querySelectorAll('.engine-item:not([style*="display: none"])');
    visibleItems.forEach(item => {
        if (item.dataset.type === 'kv') {
            const checkbox = item.querySelector('input[type="checkbox"]');
            if (checkbox) {
                checkbox.checked = true;
            }
        }
    });
    updateSelectionSummary();
}

function updateSelectionSummary() {
    const checkboxes = document.querySelectorAll('.engine-item input[type="checkbox"]:checked');
    const selectedCount = checkboxes.length;
    
    // Update the selected count display
    const selectedCountElement = document.getElementById('selected-count');
    if (selectedCountElement) {
        selectedCountElement.textContent = selectedCount;
    }
    
    // Update the selection summary text
    const summaryElement = document.getElementById('selection-summary');
    if (summaryElement) {
        if (selectedCount === 0) {
            summaryElement.textContent = 'No engines selected';
        } else if (selectedCount === 1) {
            summaryElement.textContent = '1 engine selected';
        } else {
            summaryElement.textContent = `${selectedCount} engines selected`;
        }
    }
}

function updateCounts() {
    const visibleItems = document.querySelectorAll('.engine-item:not([style*="display: none"])');
    const totalCount = visibleItems.length;
    
    let accessibleCount = 0;
    const types = new Set();
    
    visibleItems.forEach(item => {
        if (item.dataset.accessible === 'true') {
            accessibleCount++;
        }
        if (item.dataset.type) {
            types.add(item.dataset.type);
        }
    });
    
    // Update count displays
    const totalCountElement = document.getElementById('total-count');
    if (totalCountElement) {
        totalCountElement.textContent = totalCount;
    }
    
    const accessibleCountElement = document.getElementById('accessible-count');
    if (accessibleCountElement) {
        accessibleCountElement.textContent = accessibleCount;
    }
    
    const typesCountElement = document.getElementById('engine-types-count');
    if (typesCountElement) {
        typesCountElement.textContent = types.size;
    }
}

async function handleFormSubmission(e) {
    e.preventDefault();
    
    // Show loading modal
    const loadingModal = new bootstrap.Modal(document.getElementById('loadingModal'));
    loadingModal.show();
    
    try {
                            // Get selected engines
                    const checkboxes = document.querySelectorAll('.engine-item input[type="checkbox"]:checked');
                    const selectedEngines = Array.from(checkboxes).map(checkbox => checkbox.value);
        
        // Create form data
        const formData = new FormData();
        selectedEngines.forEach(engine => {
            formData.append('selected_engines[]', engine);
        });
        
        // Submit the selection
        const response = await fetch('/engines/select', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            // Show success message
            showAlert('success', result.message);
            
            // Redirect back to dashboard after a short delay
            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 1500);
        } else {
            showAlert('danger', result.message || 'Error saving selection');
        }
        
    } catch (error) {
        console.error('Error submitting form:', error);
        showAlert('danger', 'Error saving selection. Please try again.');
    } finally {
        // Hide loading modal
        loadingModal.hide();
    }
}

function showAlert(type, message) {
    // Create alert element
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Insert at the top of the container
    const container = document.querySelector('.container-fluid');
    container.insertBefore(alertDiv, container.firstChild);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

// Toggle engine group visibility
function toggleEngineGroup(heading) {
    const engineList = heading.nextElementSibling;
    const icon = heading.querySelector('i');
    
    if (engineList.style.display === 'none') {
        engineList.style.display = 'block';
        icon.className = 'fas fa-chevron-down me-2';
    } else {
        engineList.style.display = 'none';
        icon.className = 'fas fa-chevron-right me-2';
    }
}

// Expand all engine groups
function expandAllGroups() {
    const headings = document.querySelectorAll('.engine-group h6');
    headings.forEach(heading => {
        const engineList = heading.nextElementSibling;
        const icon = heading.querySelector('i');
        engineList.style.display = 'block';
        icon.className = 'fas fa-chevron-down me-2';
    });
}

// Collapse all engine groups
function collapseAllGroups() {
    const headings = document.querySelectorAll('.engine-group h6');
    headings.forEach(heading => {
        const engineList = heading.nextElementSibling;
        const icon = heading.querySelector('i');
        engineList.style.display = 'none';
        icon.className = 'fas fa-chevron-right me-2';
    });
}

// Utility function for debouncing
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
