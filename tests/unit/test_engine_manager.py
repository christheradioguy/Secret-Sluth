"""
Unit tests for engine manager functionality.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime
from app.engine_manager import EngineManager, EngineSelection, SelectionState, engine_manager
from app.engine_discovery import EngineMetadata


@pytest.fixture
def sample_engines():
    """Create sample engine metadata for testing."""
    return [
        EngineMetadata(
            path='secret/',
            type='kv',
            description='KV Store',
            accessor='kv_123456',
            options={'version': '2'},
            config={'max_lease_ttl': 0},
            permissions={'read': True, 'write': False, 'delete': False, 'list': True},
            secret_count=10,
            tags=['type:kv', 'readable']
        ),
        EngineMetadata(
            path='database/',
            type='database',
            description='Database',
            accessor='database_789012',
            options={},
            config={'max_lease_ttl': 0},
            permissions={'read': True, 'write': True, 'delete': False, 'list': True},
            secret_count=None,
            tags=['type:database', 'readable', 'writable']
        ),
        EngineMetadata(
            path='inaccessible/',
            type='ssh',
            description='Inaccessible Engine',
            accessor='ssh_345678',
            options={},
            config={'max_lease_ttl': 0},
            permissions={'read': False, 'write': False, 'delete': False, 'list': False},
            secret_count=0,
            tags=['type:ssh', 'inaccessible']
        )
    ]


@pytest.fixture
def engine_manager_instance():
    """Create an engine manager instance for testing."""
    return EngineManager(max_selections=5, max_engines_per_type=3)


class TestEngineSelection:
    """Test EngineSelection dataclass."""
    
    def test_engine_selection_creation(self):
        """Test creating an EngineSelection instance."""
        now = datetime.now()
        selection = EngineSelection(
            path='secret/',
            type='kv',
            selected_at=now,
            selected_by='test_user',
            priority=1,
            notes='Test selection'
        )
        
        assert selection.path == 'secret/'
        assert selection.type == 'kv'
        assert selection.selected_at == now
        assert selection.selected_by == 'test_user'
        assert selection.priority == 1
        assert selection.notes == 'Test selection'


class TestSelectionState:
    """Test SelectionState dataclass."""
    
    def test_selection_state_creation(self):
        """Test creating a SelectionState instance."""
        now = datetime.now()
        selections = [
            EngineSelection('secret/', 'kv', now, 'test_user'),
            EngineSelection('database/', 'database', now, 'test_user')
        ]
        
        state = SelectionState(
            selected_engines=selections,
            last_updated=now,
            version='1.0',
            metadata={'test': 'data'}
        )
        
        assert len(state.selected_engines) == 2
        assert state.last_updated == now
        assert state.version == '1.0'
        assert state.metadata['test'] == 'data'
    
    def test_selection_state_default_metadata(self):
        """Test SelectionState with default metadata."""
        now = datetime.now()
        state = SelectionState(
            selected_engines=[],
            last_updated=now
        )
        
        assert state.metadata == {}


class TestEngineManager:
    """Test EngineManager class."""
    
    def test_engine_manager_initialization(self, engine_manager_instance):
        """Test engine manager initialization."""
        assert engine_manager_instance.max_selections == 5
        assert engine_manager_instance.max_engines_per_type == 3
    
    def test_validate_selection_valid(self, engine_manager_instance, sample_engines):
        """Test validation of a valid engine selection."""
        result = engine_manager_instance.validate_selection('secret/', sample_engines)
        
        assert result['valid'] is True
        assert 'engine' in result
        assert result['engine'].path == 'secret/'
    
    def test_validate_selection_invalid_path(self, engine_manager_instance, sample_engines):
        """Test validation of an invalid engine path."""
        result = engine_manager_instance.validate_selection('invalid/', sample_engines)
        
        assert result['valid'] is False
        assert 'error' in result
        assert 'not available' in result['error']
    
    def test_validate_selection_inaccessible(self, engine_manager_instance, sample_engines):
        """Test validation of an inaccessible engine."""
        result = engine_manager_instance.validate_selection('inaccessible/', sample_engines)
        
        assert result['valid'] is False
        assert 'error' in result
        assert 'not accessible' in result['error']
    
    def test_validate_selections_valid(self, engine_manager_instance, sample_engines):
        """Test validation of multiple valid selections."""
        selected_paths = ['secret/', 'database/']
        result = engine_manager_instance.validate_selections(selected_paths, sample_engines)
        
        assert result['valid'] is True
        assert len(result['valid_selections']) == 2
        assert len(result['invalid_selections']) == 0
        assert len(result['errors']) == 0
    
    def test_validate_selections_with_invalid(self, engine_manager_instance, sample_engines):
        """Test validation of selections with invalid engines."""
        selected_paths = ['secret/', 'invalid/', 'inaccessible/']
        result = engine_manager_instance.validate_selections(selected_paths, sample_engines)
        
        assert result['valid'] is False
        assert len(result['valid_selections']) == 1
        assert len(result['invalid_selections']) == 2
        assert len(result['errors']) == 2
    
    def test_validate_selections_exceed_limit(self, engine_manager_instance, sample_engines):
        """Test validation when exceeding selection limit."""
        # Create more engines to test limit
        many_engines = sample_engines + [
            EngineMetadata(
                f'engine{i}/', 'kv', '', 
                f'accessor_{i}', {}, {'max_lease_ttl': 0},
                {'read': True}, 0, None, None, []
            )
            for i in range(10)
        ]
        
        selected_paths = [f'engine{i}/' for i in range(6)]  # Exceeds max_selections=5
        result = engine_manager_instance.validate_selections(selected_paths, many_engines)
        
        assert result['valid'] is False
        assert len(result['errors']) > 0
        assert 'Too many selections' in result['errors'][0]
    
    def test_create_selection_state(self, engine_manager_instance, sample_engines):
        """Test creating a selection state."""
        selected_paths = ['secret/', 'database/']
        state = engine_manager_instance.create_selection_state(
            selected_paths, sample_engines, user_id='test_user'
        )
        
        assert len(state.selected_engines) == 2
        assert state.metadata['total_selections'] == 2
        assert state.metadata['user_id'] == 'test_user'
        assert 'kv' in state.metadata['engine_types']
        assert 'database' in state.metadata['engine_types']
    
    def test_save_and_load_selection_state(self, engine_manager_instance, sample_engines):
        """Test saving and loading selection state."""
        # Create a selection state
        selected_paths = ['secret/', 'database/']
        state = engine_manager_instance.create_selection_state(
            selected_paths, sample_engines, user_id='test_user'
        )
        
        # Mock session
        session = {}
        
        # Save state
        success = engine_manager_instance.save_selection_state(session, state)
        assert success is True
        assert 'engine_selection_state' in session
        assert 'selected_engines' in session
        
        # Load state
        loaded_state = engine_manager_instance.load_selection_state(session)
        assert loaded_state is not None
        assert len(loaded_state.selected_engines) == 2
        assert loaded_state.metadata['user_id'] == 'test_user'
    
    def test_get_selected_paths(self, engine_manager_instance):
        """Test getting selected paths from session."""
        session = {'selected_engines': ['secret/', 'database/']}
        paths = engine_manager_instance.get_selected_paths(session)
        
        assert paths == ['secret/', 'database/']
    
    def test_get_selected_paths_empty(self, engine_manager_instance):
        """Test getting selected paths from empty session."""
        session = {}
        paths = engine_manager_instance.get_selected_paths(session)
        
        assert paths == []
    
    def test_clear_selection_state(self, engine_manager_instance, sample_engines):
        """Test clearing selection state."""
        # Create and save a selection state
        state = engine_manager_instance.create_selection_state(
            ['secret/'], sample_engines, user_id='test_user'
        )
        session = {}
        engine_manager_instance.save_selection_state(session, state)
        
        # Clear the state
        success = engine_manager_instance.clear_selection_state(session)
        assert success is True
        assert 'engine_selection_state' not in session
        assert 'selected_engines' not in session
    
    def test_update_selection_priority(self, engine_manager_instance, sample_engines):
        """Test updating selection priority."""
        # Create and save a selection state
        state = engine_manager_instance.create_selection_state(
            ['secret/'], sample_engines, user_id='test_user'
        )
        session = {}
        engine_manager_instance.save_selection_state(session, state)
        
        # Update priority
        success = engine_manager_instance.update_selection_priority(session, 'secret/', 2)
        assert success is True
        
        # Verify update
        loaded_state = engine_manager_instance.load_selection_state(session)
        assert loaded_state is not None
        selection = next(sel for sel in loaded_state.selected_engines if sel.path == 'secret/')
        assert selection.priority == 2
    
    def test_add_selection_notes(self, engine_manager_instance, sample_engines):
        """Test adding selection notes."""
        # Create and save a selection state
        state = engine_manager_instance.create_selection_state(
            ['secret/'], sample_engines, user_id='test_user'
        )
        session = {}
        engine_manager_instance.save_selection_state(session, state)
        
        # Add notes
        success = engine_manager_instance.add_selection_notes(session, 'secret/', 'Important engine')
        assert success is True
        
        # Verify notes
        loaded_state = engine_manager_instance.load_selection_state(session)
        assert loaded_state is not None
        selection = next(sel for sel in loaded_state.selected_engines if sel.path == 'secret/')
        assert selection.notes == 'Important engine'
    
    def test_get_selection_summary(self, engine_manager_instance, sample_engines):
        """Test getting selection summary."""
        # Create and save a selection state
        state = engine_manager_instance.create_selection_state(
            ['secret/'], sample_engines, user_id='test_user'
        )
        session = {}
        engine_manager_instance.save_selection_state(session, state)
        
        # Get summary
        summary = engine_manager_instance.get_selection_summary(session)
        
        assert summary['total_selected'] == 1
        assert 'kv' in summary['engine_types']
        assert summary['has_high_priority'] is False
        assert summary['has_notes'] is False
        assert summary['last_updated'] is not None
    
    def test_get_selection_summary_empty(self, engine_manager_instance):
        """Test getting selection summary for empty session."""
        session = {}
        summary = engine_manager_instance.get_selection_summary(session)
        
        assert summary['total_selected'] == 0
        assert summary['engine_types'] == []
        assert summary['last_updated'] is None
        assert summary['has_high_priority'] is False
        assert summary['has_notes'] is False


class TestGlobalEngineManager:
    """Test the global engine manager instance."""
    
    def test_global_engine_manager(self):
        """Test that the global engine manager is properly initialized."""
        assert engine_manager is not None
        assert isinstance(engine_manager, EngineManager)
        assert engine_manager.max_selections == 100
        assert engine_manager.max_engines_per_type == 50
