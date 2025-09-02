"""
Search routes for Secret Sluth.

This module handles search functionality including search form display,
search execution, and results display.
"""

from flask import Blueprint, render_template, request, jsonify, session, current_app, redirect, url_for
from app.search_engine import SearchEngine, SearchConfig
from app.session_manager import session_manager
from app.engine_manager import engine_manager
from app.middleware.auth_middleware import require_auth
from app.logging_config import get_logger
from app.audit_logger import audit_logger
from app.search_cache import search_cache
from app.search_optimizer import search_optimizer
from app.middleware.rate_limit_middleware import rate_limit
import time
import uuid
from datetime import datetime
from typing import Dict, Any, List
from app.validators import input_validator

# Global storage for search results
_search_results_storage: Dict[str, Dict[str, Any]] = {}

def cleanup_old_searches():
    """Clean up old search results to prevent memory leaks and ensure data security."""
    global _search_results_storage
    
    current_time = time.time()
    max_age_seconds = 1800  # 30 minutes maximum age
    max_searches = 5  # Keep only 5 most recent searches
    
    # Remove expired searches (older than 30 minutes)
    expired_searches = []
    for search_id, search_data in _search_results_storage.items():
        if current_time - search_data['timestamp'] > max_age_seconds:
            expired_searches.append(search_id)
    
    for search_id in expired_searches:
        del _search_results_storage[search_id]
        logger.info(f"Removed expired search result: {search_id}")
    
    # If still too many searches, keep only the most recent ones
    if len(_search_results_storage) > max_searches:
        sorted_searches = sorted(_search_results_storage.items(), 
                               key=lambda x: x[1]['timestamp'], reverse=True)
        _search_results_storage = dict(sorted_searches[:max_searches])
        logger.info(f"Cleaned up old search results, kept {len(_search_results_storage)} searches")
    
    if expired_searches or len(_search_results_storage) > max_searches:
        logger.info(f"Search cleanup completed: removed {len(expired_searches)} expired, kept {len(_search_results_storage)} active")


def clear_user_search_results(user_session_id=None):
    """Clear search results for a specific user session."""
    global _search_results_storage
    
    if user_session_id:
        # Clear specific user's search results
        user_searches = []
        for search_id, search_data in _search_results_storage.items():
            if search_data.get('user_session_id') == user_session_id:
                user_searches.append(search_id)
        
        for search_id in user_searches:
            del _search_results_storage[search_id]
        
        if user_searches:
            logger.info(f"Cleared {len(user_searches)} search results for user session {user_session_id}")
            return len(user_searches)
    else:
        # Clear all search results
        cleared_count = len(_search_results_storage)
        _search_results_storage.clear()
        logger.info(f"Cleared all {cleared_count} search results")
        return cleared_count

logger = get_logger(__name__)

search = Blueprint('search', __name__)


@search.route('/')
@require_auth
def search_redirect():
    """Redirect to dashboard since search form is now integrated there."""
    return redirect(url_for('main.dashboard'))



@search.route('/execute', methods=['POST'])
@require_auth
@rate_limit('search')
def execute_search():
    """Execute a search across selected engines."""
    # Don't log the full request form as it may contain sensitive data
    logger.info(f"Search request received")
    try:
        # Verify CSRF token if enabled
        if current_app.config.get('CSRF_ENABLED', True):
            from app.security import security_manager
            csrf_token = request.form.get('csrf_token')
            if not csrf_token or not security_manager.verify_csrf_token(csrf_token):
                logger.warning("Invalid CSRF token in search request")
                return jsonify({'error': 'Invalid CSRF token'}), 400
        
        # Get search parameters
        query = request.form.get('query', '').strip()
        
        # Enhanced validation using the global validator instance
        # Validate search query
        is_valid, error_msg = input_validator.validate_search_query(query)
        if not is_valid:
            logger.warning(f"Invalid search query: {query} - {error_msg}")
            return jsonify({'error': error_msg}), 400
        
        # Validate numeric inputs
        max_results_str = request.form.get('max_results', '1000')
        is_valid, error_msg = input_validator.validate_numeric_input(max_results_str, 1, 10000)
        if not is_valid:
            logger.warning(f"Invalid max_results: {max_results_str} - {error_msg}")
            return jsonify({'error': error_msg}), 400
        
        max_depth_str = request.form.get('max_depth', '10')
        is_valid, error_msg = input_validator.validate_numeric_input(max_depth_str, 1, 20)
        if not is_valid:
            logger.warning(f"Invalid max_depth: {max_depth_str} - {error_msg}")
            return jsonify({'error': error_msg}), 400
        
        # Validate filters
        engine_filter = request.form.get('engine_filter', '').strip()
        is_valid, error_msg = input_validator.validate_engine_filter(engine_filter)
        if not is_valid:
            logger.warning(f"Invalid engine_filter: {engine_filter} - {error_msg}")
            return jsonify({'error': error_msg}), 400
        
        match_type_filter = request.form.get('match_type', '').strip()
        is_valid, error_msg = input_validator.validate_match_type_filter(match_type_filter)
        if not is_valid:
            logger.warning(f"Invalid match_type_filter: {match_type_filter} - {error_msg}")
            return jsonify({'error': error_msg}), 400
        

        
        # Get search options
        case_sensitive = request.form.get('case_sensitive', 'false').lower() == 'true'
        search_in_names = request.form.get('search_in_names') in ['true', 'on', '1']
        search_in_keys = request.form.get('search_in_keys') in ['true', 'on', '1']
        search_in_values = request.form.get('search_in_values') in ['true', 'on', '1']
        search_in_metadata = request.form.get('search_in_metadata') in ['true', 'on', '1']
        max_results = int(request.form.get('max_results', 1000))
        max_depth = int(request.form.get('max_depth', 10))
        include_secret_data = request.form.get('include_secret_data') in ['true', 'on', '1']
        
        # Get performance optimization options
        enable_parallel = request.form.get('enable_parallel', 'true').lower() == 'true'
        parallel_searches = int(request.form.get('parallel_searches', '5'))
        batch_size = int(request.form.get('batch_size', '50'))
        
        # Get advanced filtering options
        # engine_filter = request.form.get('engine_filter', '').strip() # Moved up
        # match_type_filter = request.form.get('match_type', '').strip() # Moved up
        
        # Validate parameters
        # if max_results <= 0 or max_results > 10000: # Moved up
        #     return jsonify({'error': 'Invalid max_results value'}), 400 # Moved up
        
        # if max_depth <= 0 or max_depth > 20: # Moved up
        #     return jsonify({'error': 'Invalid max_depth value'}), 400 # Moved up
        
        # Get Vault client
        client = session_manager.get_vault_client()
        if not client:
            return jsonify({'error': 'Unable to create Vault client'}), 500
        
        # Create optimized search configuration
        config = SearchConfig(
            query=query,
            case_sensitive=case_sensitive,
            search_in_names=search_in_names,
            search_in_keys=search_in_keys,
            search_in_values=search_in_values,
            search_in_metadata=search_in_metadata,
            max_results=max_results,
            max_depth=max_depth,
            include_secret_data=include_secret_data,
            parallel_searches=parallel_searches,
            batch_size=batch_size,
            enable_parallel_processing=enable_parallel
        )
        
        # Debug logging for search configuration
        logger.debug(f"Search config: query='{query}', case_sensitive={case_sensitive}, "
                    f"search_in_names={search_in_names}, search_in_keys={search_in_keys}, "
                    f"search_in_values={search_in_values}, search_in_metadata={search_in_metadata}, "
                    f"max_results={max_results}, max_depth={max_depth}, "
                    f"include_secret_data={include_secret_data}")
        
        # Add advanced filters to config
        config.engine_filter = engine_filter
        config.match_type_filter = match_type_filter
        
        # Check cache first
        cached_results = search_cache.get(query, config.__dict__)
        if cached_results:
            logger.info(f"Cache hit for query: {query[:50]}...")
            
            # Store cached results
            search_id = str(uuid.uuid4())
            user_session_id = session.get('_id') or session.get('session_id') or str(uuid.uuid4())
            logger.debug(f"Storing cached search {search_id} with user_session_id: {user_session_id}")
            _search_results_storage[search_id] = {
                'results': [result.to_dict() for result in cached_results],
                'config': {
                    'query': query,
                    'case_sensitive': case_sensitive,
                    'search_in_names': search_in_names,
                    'search_in_keys': search_in_keys,
                    'search_in_values': search_in_values,
                    'search_in_metadata': search_in_metadata,
                    'max_results': max_results,
                    'max_depth': max_depth,
                    'include_secret_data': include_secret_data,
                    'duration': 0.0,  # Cached results have no duration
                    'total_results': len(cached_results),
                    'cached': True
                },
                'timestamp': time.time(),
                'user_session_id': user_session_id
            }
            session['current_search_id'] = search_id
            
            # Log cache hit
            audit_logger.log_search_operation(
                search_term=f"[REDACTED - length: {len(query)}]",
                engines=engine_manager.get_selected_paths(session),
                results_count=len(cached_results),
                success=True,
                duration=0.0
            )
            
            return jsonify({
                'success': True,
                'redirect_url': '/search/results',
                'cached': True
            })
        
        # Execute optimized search with performance tracking
        start_time = time.time()
        
        # Create optimized search engine and execute search
        search_engine = SearchEngine(client, engine_manager)
        search_results = search_engine.search(config, session)
        
        search_duration = time.time() - start_time
        
        # Log performance metrics
        logger.info(f"Search performance: {len(search_results)} results in {search_duration:.2f}s "
                   f"({len(search_results)/max(search_duration, 0.1):.1f} results/sec)")
        
        # Store results in server-side storage to avoid cookie size limits
        search_id = str(uuid.uuid4())
        user_session_id = session.get('_id') or session.get('session_id') or str(uuid.uuid4())  # Get or generate session ID
        
        logger.info(f"Storing search {search_id} with user_session_id: {user_session_id}")
        logger.info(f"Search results count: {len(search_results)}")
        logger.info(f"Current storage size before: {len(_search_results_storage)}")
        
        _search_results_storage[search_id] = {
            'results': [r.to_dict() for r in search_results],
            'config': {
                'query': query,
                'case_sensitive': case_sensitive,
                'search_in_names': search_in_names,
                'search_in_keys': search_in_keys,
                'search_in_values': search_in_values,
                'search_in_metadata': search_in_metadata,
                'max_results': max_results,
                'max_depth': max_depth,
                'include_secret_data': include_secret_data,
                'duration': search_duration,
                'total_results': len(search_results),
                'cached': False
            },
            'timestamp': time.time(),
            'user_session_id': user_session_id
        }
        
        logger.info(f"Storage size after storing: {len(_search_results_storage)}")
        logger.info(f"Stored search keys: {list(_search_results_storage.keys())}")
        
        # Store search ID in session
        session['current_search_id'] = search_id
        
        # Log search activity (without sensitive data)
        audit_logger.log_search_operation(
            search_term=f"[REDACTED - length: {len(query)}]",
            engines=engine_manager.get_selected_paths(session),
            results_count=len(search_results),
            success=True,
            duration=search_duration
        )
        
        return jsonify({
            'success': True,
            'search_id': search_id,
            'results_count': len(search_results),
            'duration': search_duration,
            'redirect_url': '/search/results'
        })
        
    except ValueError as e:
        logger.warning(f"Search validation error: {e}")
        return jsonify({'error': str(e)}), 400
        
    except Exception as e:
        logger.error(f"Search execution failed: {e}")
        return jsonify({'error': 'Search execution failed'}), 500


def format_results_for_display(results: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """Format search results for display in the template."""
    import re
    import urllib.parse
    
    formatted_results = []
    
    for result in results:
        # Create display fields
        
        # Get the raw display path
        raw_display_path = result.get('path', '').replace(result.get('engine_path', ''), '').strip('/') or '/'
        
        # Clean up double slashes
        cleaned_display_path = re.sub(r'/+', '/', raw_display_path)
        
        # Handle URL encoded paths
        if '%2F' in cleaned_display_path:
            # Decode URL encoded parts
            decoded_path = urllib.parse.unquote(cleaned_display_path)
            # Clean up any double slashes that might result from decoding
            display_path = re.sub(r'/+', '/', decoded_path).strip('/') or '/'
        else:
            display_path = cleaned_display_path
        
        # Determine match highlights
        match_highlights = []
        if result.get('match_type') == 'name':
            match_highlights.append('name')
        elif result.get('match_type') == 'key':
            match_highlights.append('key')
        elif result.get('match_type') == 'value':
            match_highlights.append('value')
        elif result.get('match_type') == 'metadata':
            match_highlights.append('metadata')
        
        # Format the result for display
        formatted_result = {
            'path': result.get('path', ''),
            'key': result.get('key', ''),
            'value': result.get('value', ''),
            'match_type': result.get('match_type', ''),
            'match_context': result.get('match_context', ''),
            'engine_path': result.get('engine_path', ''),
            'engine_type': result.get('engine_type', ''),
            'timestamp': result.get('timestamp', ''),
            'confidence': result.get('confidence', 1.0),
            'metadata': result.get('metadata', {}),
            # Display fields for template
            'display_path': display_path,
            'display_key': result.get('key', ''),
            'display_value': result.get('value', '') if result.get('include_secret_data', False) else '[REDACTED]',
            'match_highlights': {highlight: True for highlight in match_highlights}
        }
        
        formatted_results.append(formatted_result)
    
    return formatted_results


@search.route('/results')
@require_auth
def search_results():
    """Display search results."""
    try:
        # Get search ID from URL parameter or session
        search_id = request.args.get('search_id') or session.get('current_search_id')
        
        if not search_id or search_id not in _search_results_storage:
            return render_template('search/no_results.html', 
                                 message="No search results found. Please perform a search first.")
        
        # Verify the search belongs to the current user
        search_data = _search_results_storage[search_id]
        user_session_id = session.get('_id') or session.get('session_id')
        if search_data.get('user_session_id') != user_session_id:
            return render_template('search/no_results.html', 
                                 message="Access denied. These search results belong to another session.")
        
        # Get search data
        search_data = _search_results_storage[search_id]
        results = search_data['results']
        
        # Format results for display
        formatted_results = format_results_for_display(results, search_data['config']['query'])
        
        # Calculate statistics
        unique_paths = len(set(result.get('path', '') for result in results))
        engine_paths = list(set(result.get('engine_path', '') for result in results))
        
        statistics = {
            'total_results': len(results),
            'unique_paths': unique_paths,
            'engines_with_results': len(engine_paths),
            'engine_paths': engine_paths
        }
        
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = 20  # Results per page
        total_results = len(formatted_results)
        total_pages = (total_results + per_page - 1) // per_page
        
        # Calculate pagination
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_results = formatted_results[start_idx:end_idx]
        
        pagination = {
            'page': page,
            'per_page': per_page,
            'total_results': total_results,
            'total_pages': total_pages,
            'has_prev': page > 1,
            'has_next': page < total_pages
        }
        
        # Get sorting parameters
        sort_by = request.args.get('sort_by', 'path')
        sort_order = request.args.get('sort_order', 'asc')
        
        # Get Vault URL for direct links
        vault_url = session.get('vault_url', '')
        
        return render_template('search/results.html',
                             results=paginated_results,
                             search_config=search_data['config'],
                             statistics=statistics,
                             pagination=pagination,
                             sort_by=sort_by,
                             sort_order=sort_order,
                             vault_url=vault_url,
                             search_id=search_id,
                             timestamp=int(time.time()))
                             
    except Exception as e:
        logger.error(f"Error displaying search results: {e}")
        return render_template('errors/application_error.html', 
                             error="Failed to display search results",
                             details=str(e)), 500


@search.route('/export')
@require_auth
@rate_limit('export')
def export_results_simple():
    """Export search results in various formats (simplified route)."""
    try:
        # Get search ID from session
        search_id = session.get('current_search_id')
        
        if not search_id or search_id not in _search_results_storage:
            return jsonify({'error': 'No search results to export'}), 404
        
        # Get export format from query parameters
        export_format = request.args.get('format', 'json').lower()
        include_secrets = request.args.get('include_secrets', 'false').lower() == 'true'
        
        # Get search data
        search_data = _search_results_storage[search_id]
        
        # Simple export implementation
        if export_format == 'json':
            export_data = {
                'search_config': search_data['config'],
                'results': search_data['results'],
                'exported_at': datetime.now().isoformat()
            }
            return jsonify(export_data)
        elif export_format == 'csv':
            import csv
            from io import StringIO
            
            output = StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['Path', 'Key', 'Value', 'Match Type', 'Engine Path', 'Engine Type'])
            
            # Write data
            for result in search_data['results']:
                writer.writerow([
                    result.get('path', ''),
                    result.get('key', ''),
                    result.get('value', '') if include_secrets else '[REDACTED]',
                    result.get('match_type', ''),
                    result.get('engine_path', ''),
                    result.get('engine_type', '')
                ])
            
            from flask import Response
            filename = f"search_results_{search_id[:8]}.csv"
            return Response(output.getvalue(), 
                          mimetype='text/csv',
                          headers={'Content-Disposition': f'attachment; filename={filename}'})
        else:
            return jsonify({'error': 'Unsupported export format'}), 400
        
        # Log export activity
        audit_logger.log_data_access(
            action="export_results",
            resource_type="search_results",
            resource_id=search_id,
            success=True,
            details=f"Exported {len(search_data['results'])} results in {export_format} format"
        )
                             
    except Exception as e:
        logger.error(f"Error exporting results: {e}")
        return jsonify({'error': 'Failed to export results'}), 500


@search.route('/export/<search_id>')
@require_auth
def export_results(search_id):
    """Export search results in various formats."""
    try:
        if search_id not in _search_results_storage:
            return jsonify({'error': 'Search results not found'}), 404
        
        # Get export format from query parameters
        export_format = request.args.get('format', 'json').lower()
        include_secrets = request.args.get('include_secrets', 'false').lower() == 'true'
        
        # Get search data
        search_data = _search_results_storage[search_id]
        
        # Simple export implementation
        if export_format == 'json':
            export_data = {
                'search_config': search_data['config'],
                'results': search_data['results'],
                'exported_at': datetime.now().isoformat()
            }
            return jsonify(export_data)
        elif export_format == 'csv':
            import csv
            from io import StringIO
            
            output = StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['Path', 'Key', 'Value', 'Match Type', 'Engine Path', 'Engine Type'])
            
            # Write data
            for result in search_data['results']:
                writer.writerow([
                    result.get('path', ''),
                    result.get('key', ''),
                    result.get('value', '') if include_secrets else '[REDACTED]',
                    result.get('match_type', ''),
                    result.get('engine_path', ''),
                    result.get('engine_type', '')
                ])
            
            from flask import Response
            filename = f"search_results_{search_id[:8]}.csv"
            return Response(output.getvalue(), 
                          mimetype='text/csv',
                          headers={'Content-Disposition': f'attachment; filename={filename}'})
        else:
            return jsonify({'error': 'Unsupported export format'}), 400
        
        # Log export activity
        audit_logger.log_data_access(
            action="export_results",
            resource_type="search_results",
            resource_id=search_id,
            success=True,
            details=f"Exported {len(search_data['results'])} results in {export_format} format"
        )
                             
    except Exception as e:
        logger.error(f"Error exporting results: {e}")
        return jsonify({'error': 'Failed to export results'}), 500


@search.route('/clear', methods=['POST'])
@require_auth
def clear_search_results_simple():
    """Manually clear all search results for security (simplified route)."""
    try:
        global _search_results_storage
        cleared_count = len(_search_results_storage)
        _search_results_storage.clear()
        
        # Also clear the session search ID
        session.pop('current_search_id', None)
        
        logger.info(f"Manually cleared {cleared_count} search results")
        audit_logger.log_data_access(
            action="clear_search_results",
            resource_type="search_results",
            resource_id="all",
            success=True,
            details=f"Cleared {cleared_count} search results"
        )
        
        return jsonify({
            'success': True,
            'message': f'Cleared {cleared_count} search results'
        })
        
    except Exception as e:
        logger.error(f"Error clearing search results: {e}")
        return jsonify({'error': 'Failed to clear search results'}), 500


@search.route('/clear-results', methods=['POST'])
@require_auth
def clear_search_results():
    """Manually clear all search results for security."""
    try:
        global _search_results_storage
        cleared_count = len(_search_results_storage)
        _search_results_storage.clear()
        
        # Also clear the session search ID
        session.pop('current_search_id', None)
        
        logger.info(f"Manually cleared {cleared_count} search results")
        audit_logger.log_data_access(
            action="clear_search_results",
            resource_type="search_results",
            resource_id="all",
            success=True,
            details=f"Cleared {cleared_count} search results"
        )
        
        return jsonify({
            'success': True,
            'message': f'Cleared {cleared_count} search results'
        })
        
    except Exception as e:
        logger.error(f"Error clearing search results: {e}")
        return jsonify({'error': 'Failed to clear search results'}), 500


@search.route('/cached')
@require_auth
def get_cached_searches():
    """Get list of cached searches for the current user."""
    try:
        global _search_results_storage
        
        # Get current user session ID (try both field names for compatibility)
        user_session_id = session.get('_id') or session.get('session_id')
        
        # Debug logging
        logger.debug(f"Current user session ID: {user_session_id}")
        logger.debug(f"Total searches in storage: {len(_search_results_storage)}")
        
        # Filter searches for current user and format them
        cached_searches = []
        current_time = time.time()
        
        for search_id, search_data in _search_results_storage.items():
            search_user_id = search_data.get('user_session_id')
            logger.info(f"Search {search_id}: user_id={search_user_id}, query={search_data['config'].get('query', '')[:20]}...")
            logger.info(f"Current user session ID: {user_session_id}")
            logger.info(f"Match check: {search_user_id} == {user_session_id} = {search_user_id == user_session_id}")
            
            # Check if search belongs to current user (or show all if no session ID)
            if search_user_id == user_session_id or not user_session_id:
                # Check if search is still valid (not expired)
                if current_time - search_data['timestamp'] <= 1800:  # 30 minutes
                    cached_search = {
                        'id': search_id,
                        'query': search_data['config'].get('query', ''),
                        'timestamp': search_data['timestamp'],
                        'total_results': len(search_data['results']),
                        'duration': search_data['config'].get('duration', 0),
                        'engines_count': len(search_data['config'].get('selected_engines', [])) if 'selected_engines' in search_data['config'] else 0,
                        'expires_at': search_data['timestamp'] + 1800
                    }
                    cached_searches.append(cached_search)
                    logger.debug(f"Added search {search_id} to cached searches")
                else:
                    logger.debug(f"Search {search_id} is expired")
            else:
                logger.debug(f"Search {search_id} belongs to different user: {search_user_id} != {user_session_id}")
        
        # Sort by timestamp (most recent first)
        cached_searches.sort(key=lambda x: x['timestamp'], reverse=True)
        
        logger.info(f"Returning {len(cached_searches)} cached searches for user {user_session_id}")
        
        return jsonify({
            'success': True,
            'searches': cached_searches,
            'total': len(cached_searches)
        })
        
    except Exception as e:
        logger.error(f"Error getting cached searches: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get cached searches'
        }), 500





# Clean up old searches periodically
cleanup_old_searches()
