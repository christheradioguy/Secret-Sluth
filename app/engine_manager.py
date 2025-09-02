"""
Engine Selection State Management for Secret Sluth.

This module handles the management of selected secret engines, including:
- Storage and retrieval of selected engines in session
- Validation of engine selections
- Persistence of selection state
- Recovery of selection state
- Enforcement of selection limits and constraints
"""

import json
from typing import List, Dict, Optional, Set, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from app.logging_config import get_logger
from app.engine_discovery import EngineMetadata

logger = get_logger(__name__)


@dataclass
class EngineSelection:
    """Represents a selected engine with metadata."""
    path: str
    type: str
    selected_at: datetime
    selected_by: str  # User identifier
    priority: int = 0  # Selection priority (0 = normal, 1 = high, etc.)
    notes: str = ""  # User notes about this selection


@dataclass
class SelectionState:
    """Represents the complete state of engine selections."""
    selected_engines: List[EngineSelection]
    last_updated: datetime
    version: str = "1.0"
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class EngineManager:
    """
    Manages engine selection state and provides validation and persistence.
    """
    
    def __init__(self, max_selections: int = 100, max_engines_per_type: int = 50):
        """
        Initialize the engine manager.
        
        Args:
            max_selections: Maximum number of engines that can be selected
            max_engines_per_type: Maximum engines per engine type
        """
        self.max_selections = max_selections
        self.max_engines_per_type = max_engines_per_type
        self.logger = get_logger(__name__)
    
    def validate_selection(self, engine_path: str, available_engines: List[EngineMetadata]) -> Dict[str, Any]:
        """
        Validate if an engine can be selected.
        
        Args:
            engine_path: Path of the engine to validate
            available_engines: List of available engines
            
        Returns:
            Dict with validation result and any error messages
        """
        # Check if engine exists in available engines
        engine_exists = any(engine.path == engine_path for engine in available_engines)
        if not engine_exists:
            return {
                'valid': False,
                'error': f'Engine {engine_path} is not available'
            }
        
        # Find the engine metadata
        engine_meta = next((engine for engine in available_engines if engine.path == engine_path), None)
        if not engine_meta:
            return {
                'valid': False,
                'error': f'Engine {engine_path} metadata not found'
            }
        
        # Check if engine is accessible (be more lenient for non-KV engines)
        if engine_meta.type == 'kv' and not engine_meta.permissions.get('read', False):
            return {
                'valid': False,
                'error': f'KV engine {engine_path} is not accessible (no read permission)'
            }
        elif not engine_meta.permissions.get('read', False):
            # For non-KV engines, just warn but allow selection
            return {
                'valid': True,
                'engine': engine_meta,
                'warning': f'Engine {engine_path} may not be fully accessible'
            }
        
        return {
            'valid': True,
            'engine': engine_meta
        }
    
    def validate_selections(self, selected_paths: List[str], available_engines: List[EngineMetadata]) -> Dict[str, Any]:
        """
        Validate a list of engine selections.
        
        Args:
            selected_paths: List of engine paths to validate
            available_engines: List of available engines
            
        Returns:
            Dict with validation results
        """
        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'valid_selections': [],
            'invalid_selections': []
        }
        
        # Check selection limits
        if len(selected_paths) > self.max_selections:
            results['valid'] = False
            results['errors'].append(f'Too many selections: {len(selected_paths)} > {self.max_selections}')
        
        # Check per-type limits
        engine_types = {}
        for path in selected_paths:
            engine_meta = next((engine for engine in available_engines if engine.path == path), None)
            if engine_meta:
                engine_type = engine_meta.type
                engine_types[engine_type] = engine_types.get(engine_type, 0) + 1
                
                if engine_types[engine_type] > self.max_engines_per_type:
                    results['warnings'].append(
                        f'Many {engine_type} engines selected: {engine_types[engine_type]}'
                    )
        
        # Validate each selection
        for path in selected_paths:
            validation = self.validate_selection(path, available_engines)
            if validation['valid']:
                results['valid_selections'].append(path)
                # Add warnings if any
                if 'warning' in validation:
                    results['warnings'].append(validation['warning'])
            else:
                results['invalid_selections'].append(path)
                results['errors'].append(validation['error'])
                results['valid'] = False
        
        return results
    
    def create_selection_state(self, selected_paths: List[str], available_engines: List[EngineMetadata], 
                             user_id: str = "default") -> SelectionState:
        """
        Create a selection state from selected engine paths.
        
        Args:
            selected_paths: List of selected engine paths
            available_engines: List of available engines
            user_id: Identifier for the user making selections
            
        Returns:
            SelectionState object
        """
        selected_engines = []
        now = datetime.now()
        
        for path in selected_paths:
            engine_meta = next((engine for engine in available_engines if engine.path == path), None)
            if engine_meta:
                selection = EngineSelection(
                    path=path,
                    type=engine_meta.type,
                    selected_at=now,
                    selected_by=user_id
                )
                selected_engines.append(selection)
        
        return SelectionState(
            selected_engines=selected_engines,
            last_updated=now,
            metadata={
                'total_selections': len(selected_engines),
                'engine_types': list(set(sel.type for sel in selected_engines)),
                'user_id': user_id
            }
        )
    
    def save_selection_state(self, session: Dict, selection_state: SelectionState) -> bool:
        """
        Save selection state to session.
        
        Args:
            session: Flask session object
            selection_state: SelectionState to save
            
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            # Convert to serializable format
            state_dict = {
                'selected_engines': [
                    {
                        'path': sel.path,
                        'type': sel.type,
                        'selected_at': sel.selected_at.isoformat(),
                        'selected_by': sel.selected_by,
                        'priority': sel.priority,
                        'notes': sel.notes
                    }
                    for sel in selection_state.selected_engines
                ],
                'last_updated': selection_state.last_updated.isoformat(),
                'version': selection_state.version,
                'metadata': selection_state.metadata
            }
            
            session['engine_selection_state'] = state_dict
            session['selected_engines'] = [sel.path for sel in selection_state.selected_engines]
            
            self.logger.info(f"Saved selection state: {len(selection_state.selected_engines)} engines")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save selection state: {e}")
            return False
    
    def load_selection_state(self, session: Dict) -> Optional[SelectionState]:
        """
        Load selection state from session.
        
        Args:
            session: Flask session object
            
        Returns:
            SelectionState if found, None otherwise
        """
        try:
            state_dict = session.get('engine_selection_state')
            if not state_dict:
                return None
            
            # Convert back from serializable format
            selected_engines = []
            for engine_dict in state_dict.get('selected_engines', []):
                selection = EngineSelection(
                    path=engine_dict['path'],
                    type=engine_dict['type'],
                    selected_at=datetime.fromisoformat(engine_dict['selected_at']),
                    selected_by=engine_dict['selected_by'],
                    priority=engine_dict.get('priority', 0),
                    notes=engine_dict.get('notes', '')
                )
                selected_engines.append(selection)
            
            return SelectionState(
                selected_engines=selected_engines,
                last_updated=datetime.fromisoformat(state_dict['last_updated']),
                version=state_dict.get('version', '1.0'),
                metadata=state_dict.get('metadata', {})
            )
            
        except Exception as e:
            self.logger.error(f"Failed to load selection state: {e}")
            return None
    
    def get_selected_paths(self, session: Dict) -> List[str]:
        """
        Get list of selected engine paths from session.
        
        Args:
            session: Flask session object
            
        Returns:
            List of selected engine paths
        """
        return session.get('selected_engines', [])
    
    def clear_selection_state(self, session: Dict) -> bool:
        """
        Clear selection state from session.
        
        Args:
            session: Flask session object
            
        Returns:
            True if cleared successfully, False otherwise
        """
        try:
            session.pop('engine_selection_state', None)
            session.pop('selected_engines', None)
            self.logger.info("Cleared selection state")
            return True
        except Exception as e:
            self.logger.error(f"Failed to clear selection state: {e}")
            return False
    
    def update_selection_priority(self, session: Dict, engine_path: str, priority: int) -> bool:
        """
        Update the priority of a selected engine.
        
        Args:
            session: Flask session object
            engine_path: Path of the engine to update
            priority: New priority value
            
        Returns:
            True if updated successfully, False otherwise
        """
        try:
            selection_state = self.load_selection_state(session)
            if not selection_state:
                return False
            
            # Find and update the selection
            for selection in selection_state.selected_engines:
                if selection.path == engine_path:
                    selection.priority = priority
                    selection_state.last_updated = datetime.now()
                    return self.save_selection_state(session, selection_state)
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to update selection priority: {e}")
            return False
    
    def add_selection_notes(self, session: Dict, engine_path: str, notes: str) -> bool:
        """
        Add or update notes for a selected engine.
        
        Args:
            session: Flask session object
            engine_path: Path of the engine to add notes to
            notes: Notes to add
            
        Returns:
            True if updated successfully, False otherwise
        """
        try:
            selection_state = self.load_selection_state(session)
            if not selection_state:
                return False
            
            # Find and update the selection
            for selection in selection_state.selected_engines:
                if selection.path == engine_path:
                    selection.notes = notes
                    selection_state.last_updated = datetime.now()
                    return self.save_selection_state(session, selection_state)
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to add selection notes: {e}")
            return False
    
    def get_selection_summary(self, session: Dict) -> Dict[str, Any]:
        """
        Get a summary of the current selection state.
        
        Args:
            session: Flask session object
            
        Returns:
            Dict with selection summary
        """
        selection_state = self.load_selection_state(session)
        if not selection_state:
            return {
                'total_selected': 0,
                'engine_types': [],
                'last_updated': None,
                'has_high_priority': False,
                'has_notes': False
            }
        
        engine_types = list(set(sel.type for sel in selection_state.selected_engines))
        has_high_priority = any(sel.priority > 0 for sel in selection_state.selected_engines)
        has_notes = any(sel.notes for sel in selection_state.selected_engines)
        
        return {
            'total_selected': len(selection_state.selected_engines),
            'engine_types': engine_types,
            'last_updated': selection_state.last_updated,
            'has_high_priority': has_high_priority,
            'has_notes': has_notes,
            'metadata': selection_state.metadata
        }


# Global engine manager instance
engine_manager = EngineManager()
