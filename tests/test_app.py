import os
import tempfile
import unittest

from app import create_app


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.db_fd)
        from app.config import Config
        Config.DATABASE = self.db_path
        Config.MONITOR_API_KEY = "test-key"
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except FileNotFoundError:
            pass

    def login(self):
        response = self.client.post(
            "/login",
            data={"username": "admin", "password": "Admin@12345"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        return response

    def test_login_and_dashboard(self):
        response = self.login()
        self.assertIn(b"Enterprise PC Monitoring", response.data)
        self.assertIn(b"Endpoint Inventory", response.data)
        self.assertIn(b"SOC Command Center", response.data)

    def test_update_requires_key(self):
        response = self.client.post("/api/update", json={"pc_name": "TEST-PC"})
        self.assertEqual(response.status_code, 401)

    def test_update_ingests_endpoint(self):
        payload = {
            "api_key": "test-key",
            "pc_name": "TEST-PC",
            "ip": "192.168.1.10",
            "cpu": 12,
            "ram": 20,
            "disk": 30,
            "department": "Test",
            "processes": [],
            "services": [],
            "security_events": [],
            "network_connections": [],
            "software_inventory": [],
            "defender_status": "Healthy",
        }
        response = self.client.post("/api/update", json=payload)
        self.assertEqual(response.status_code, 200)
        self.login()
        dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"TEST-PC", dashboard.data)

    def test_protected_api_requires_authentication(self):
        response = self.client.get("/api/pcs")
        self.assertEqual(response.status_code, 401)

    def test_authenticated_api_access(self):
        self.login()
        response = self.client.get("/api/pcs")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
