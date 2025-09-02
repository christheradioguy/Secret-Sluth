"""
Engine selection routes for Secret Sluth.

This module handles the engine selection interface where users can choose
which secret engines to include in their searches.
"""

from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from app.engine_discovery import EngineDiscovery, EngineDiscoveryError
from app.engine_cache import EngineCache
from app.engine_manager import engine_manager
from app.session_manager import session_manager
from app.middleware.auth_middleware import require_auth
from app.logging_config import get_logger

logger = get_logger(__name__)

engines = Blueprint('engines', __name__)


@engines.route('/')
@require_auth
def engines_redirect():
    """Redirect to dashboard since engine selection is now integrated there."""
    return redirect(url_for('main.dashboard'))

@engines.route('/selected')
@require_auth
def get_selected_engines():
    """Get the currently selected engines as JSON."""
    try:
        selected_engines = engine_manager.get_selected_paths(session)
        return jsonify({
            'success': True,
            'engines': selected_engines
        })
    except Exception as e:
        logger.error(f"Error getting selected engines: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get selected engines'
        }), 500

@engines.route('/select')
@require_auth
def select_engines():
    """Display the engine selection page."""
    try:
        # Get current selection from session using engine manager
        selected_engines = engine_manager.get_selected_paths(session)
        
        # Get all available engines
        client = session_manager.get_vault_client()
        if not client:
            return render_template('errors/application_error.html', 
                                error="Unable to create Vault client"), 400
        
        with client:
            # Initialize engine discovery
            engine_discovery = EngineDiscovery(client, max_workers=3, timeout=30)
            
            # Initialize cache (memory-only for now)
            engine_cache = EngineCache(cache_dir=None, default_ttl=300)
            
            # Get session info for cache key
            session_info = session_manager.get_session_info()
            vault_url = session_info['vault_url']
            
            # Get the encrypted token from session and decrypt it
            encrypted_token = session.get('vault_token')
            if not encrypted_token:
                return render_template('errors/application_error.html', 
                                    error="No token found in session"), 400
            
            from app.security import security_manager
            token = security_manager.decrypt_token(encrypted_token)
            
            # Try to get from cache first
            cached_engines = engine_cache.get(
                vault_url=vault_url,
                token=token,
                recursive=True,
                include_inaccessible=True
            )
            
            if cached_engines:
                logger.info(f"Using cached engine data: {len(cached_engines)} engines")
                engines = cached_engines
            else:
                # Perform discovery
                logger.info("Performing fresh engine discovery for selection page")
                engines = engine_discovery.discover_engines(
                    recursive=True,
                    include_inaccessible=True
                )
                
                # Cache the results
                engine_cache.set(
                    vault_url=vault_url,
                    token=token,
                    engines=engines,
                    recursive=True,
                    include_inaccessible=True
                )
            
            # Group engines by type for better organization
            engine_groups = {}
            for engine in engines:
                engine_type = engine.type
                if engine_type not in engine_groups:
                    engine_groups[engine_type] = []
                engine_groups[engine_type].append(engine)
            
            # Sort groups by type name
            sorted_groups = dict(sorted(engine_groups.items()))
            
            return render_template('engines/select.html', 
                                engine_groups=sorted_groups,
                                selected_engines=selected_engines)
            
    except EngineDiscoveryError as e:
        logger.error(f"Engine discovery failed: {e}")
        return render_template('errors/application_error.html', 
                            error=f"Engine discovery failed: {str(e)}"), 400
    
    except Exception as e:
        logger.error(f"Unexpected error in engine selection: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return render_template('errors/application_error.html', 
                            error=f"Unexpected error: {e}"), 500


@engines.route('/select', methods=['POST'])
@require_auth
def update_selection():
    """Update the selected engines in the session."""
    try:
        # Get selected engines from form data
        selected_engines = request.form.getlist('selected_engines[]')
        
        # Debug logging
        logger.info(f"Form data received: {dict(request.form)}")
        logger.info(f"Selected engines: {selected_engines}")
        logger.info(f"Form data keys: {list(request.form.keys())}")
        
        # Validate that all selected engines exist
        client = session_manager.get_vault_client()
        if not client:
            return jsonify({'status': 'error', 'message': 'Unable to create Vault client'}), 400
        
        with client:
            # Get all available engines to validate selection
            engine_discovery = EngineDiscovery(client, max_workers=3, timeout=30)
            all_engines = engine_discovery.discover_engines(
                recursive=True,
                include_inaccessible=True
            )
            
            # Use engine manager to validate selections
            validation = engine_manager.validate_selections(selected_engines, all_engines)
            
            if not validation['valid']:
                error_message = '; '.join(validation['errors'])
                return jsonify({
                    'status': 'error', 
                    'message': f'Validation failed: {error_message}'
                }), 400
            
            # Create and save selection state
            selection_state = engine_manager.create_selection_state(
                selected_engines, all_engines, user_id="default"
            )
            
            if not engine_manager.save_selection_state(session, selection_state):
                return jsonify({
                    'status': 'error', 
                    'message': 'Failed to save selection state'
                }), 500
            
            # Add warnings if any
            warnings = validation.get('warnings', [])
            message = f'Successfully selected {len(selected_engines)} engines'
            if warnings:
                message += f' (Warnings: {"; ".join(warnings)})'
            
            logger.info(f"Updated engine selection: {len(selected_engines)} engines selected")
            
            return jsonify({
                'status': 'success',
                'message': message,
                'selected_count': len(selected_engines),
                'warnings': warnings
            })
        
    except Exception as e:
        logger.error(f"Error updating engine selection: {e}")
        return jsonify({'status': 'error', 'message': f'Error updating selection: {e}'}), 500


@engines.route('/selection/status')
@require_auth
def get_selection_status():
    """Get the current engine selection status."""
    try:
        # Get selection summary from engine manager
        summary = engine_manager.get_selection_summary(session)
        selected_engines = engine_manager.get_selected_paths(session)
        
        # Get engine details for selected engines
        client = session_manager.get_vault_client()
        if not client:
            return jsonify({'status': 'error', 'message': 'Unable to create Vault client'}), 400
        
        with client:
            engine_discovery = EngineDiscovery(client, max_workers=3, timeout=30)
            all_engines = engine_discovery.discover_engines(
                recursive=True,
                include_inaccessible=True
            )
            
            # Create a map of engine paths to engine objects
            engine_map = {engine.path: engine for engine in all_engines}
            
            # Get details for selected engines
            selected_details = []
            for path in selected_engines:
                if path in engine_map:
                    engine = engine_map[path]
                    selected_details.append({
                        'path': engine.path,
                        'type': engine.type,
                        'description': engine.description,
                        'secret_count': engine.secret_count,
                        'tags': engine.tags
                    })
            
            return jsonify({
                'status': 'success',
                'selected_engines': selected_details,
                'selected_count': len(selected_engines),
                'total_available': len(all_engines),
                'summary': summary
            })
        
    except Exception as e:
        logger.error(f"Error getting selection status: {e}")
        return jsonify({'status': 'error', 'message': f'Error getting status: {e}'}), 500


@engines.route('/selection/clear', methods=['POST'])
@require_auth
def clear_selection():
    """Clear the current engine selection."""
    try:
        if engine_manager.clear_selection_state(session):
            return jsonify({
                'status': 'success',
                'message': 'Engine selection cleared successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to clear engine selection'
            }), 500
            
    except Exception as e:
        logger.error(f"Error clearing selection: {e}")
        return jsonify({'status': 'error', 'message': f'Error clearing selection: {e}'}), 500
