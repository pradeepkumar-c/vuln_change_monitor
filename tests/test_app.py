
from unittest.mock import patch, MagicMock
from app import db_init


@patch("app.db")
@patch("app.app")
def test_db_init_success(mock_app, mock_db):
    mock_context = MagicMock()
    mock_app.app_context.return_value.__enter__.return_value = mock_context

    db_init()

    mock_app.app_context.assert_called_once()
    mock_db.init_app.assert_called_once_with(mock_app)
    mock_db.create_all.assert_called_once()

@patch("app.db")
@patch("app.app")
def test_db_init_exception(mock_app, mock_db):
    mock_context = MagicMock()
    mock_app.app_context.return_value.__enter__.return_value = mock_context

    mock_db.create_all.side_effect = Exception("DB error")

    db_init()

    mock_db.init_app.assert_called_once()
    mock_db.create_all.assert_called_once()
