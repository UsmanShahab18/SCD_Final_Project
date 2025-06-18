import unittest
from unittest.mock import patch, MagicMock
from app import app, FALLBACK_DATA_FILE, write_users_to_file
import json

class FlaskAppLoginTest(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        self.user = {
            "id": 1,
            "username": "testuser",
            "password": "$pbkdf2-sha256$29000$Wqz8Y..."  # pre-hashed password using werkzeug
        }
        self.admin_username = "admin"
        self.admin_password = "admin"

    @patch("app.mysql")
    def test_user_login_success_from_db(self, mock_mysql):
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = self.user
        mock_mysql.connection.cursor.return_value = mock_cursor

        response = self.app.post('/login', data={
            'form_type': 'user',
            'user_username': self.user["username"],
            'user_password': 'password123'  # must match hashed password
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Logged in successfully', response.data)

    @patch("app.mysql", side_effect=Exception("DB Down"))
    @patch("app.read_users_from_file")
    def test_user_login_success_from_fallback_file(self, mock_read_file, mock_mysql):
        mock_read_file.return_value = [self.user]

        response = self.app.post('/login', data={
            'form_type': 'user',
            'user_username': self.user["username"],
            'user_password': 'password123'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Logged in successfully', response.data)

    def test_invalid_user_login(self):
        response = self.app.post('/login', data={
            'form_type': 'user',
            'user_username': 'unknown',
            'user_password': 'wrongpass'
        }, follow_redirects=True)

        self.assertIn(b'Incorrect username or password', response.data)

    def test_admin_login_success(self):
        response = self.app.post('/login', data={
            'form_type': 'admin',
            'admin_username': self.admin_username,
            'admin_password': self.admin_password
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Admin login successful', response.data)

    def test_admin_login_failure(self):
        response = self.app.post('/login', data={
            'form_type': 'admin',
            'admin_username': 'admin',
            'admin_password': 'wrong'
        }, follow_redirects=True)

        self.assertIn(b'Incorrect admin username or password', response.data)

    def test_missing_fields(self):
        response = self.app.post('/login', data={
            'form_type': 'user'
        }, follow_redirects=True)

        self.assertIn(b'Username and password are required', response.data)

if __name__ == '__main__':
    unittest.main()
 