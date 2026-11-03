import copy
import hashlib
import secrets
import sys
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import app as activity_app


class TeacherAuthTests(unittest.TestCase):
    def setUp(self):
        self.original_activities = copy.deepcopy(activity_app.activities)
        self.original_credentials = activity_app.teacher_credentials.copy()
        activity_app.activities.clear()
        activity_app.activities["Test Activity"] = {
            "description": "Test",
            "schedule": "Fridays",
            "max_participants": 3,
            "participants": [],
        }
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256", b"test-password", salt, activity_app.PASSWORD_HASH_ITERATIONS
        )
        activity_app.teacher_credentials.clear()
        activity_app.teacher_credentials["teacher"] = (
            f"pbkdf2_sha256${activity_app.PASSWORD_HASH_ITERATIONS}"
            f"${salt.hex()}${digest.hex()}"
        )
        self.client = TestClient(activity_app.app)

    def tearDown(self):
        activity_app.activities.clear()
        activity_app.activities.update(self.original_activities)
        activity_app.teacher_credentials.clear()
        activity_app.teacher_credentials.update(self.original_credentials)

    def test_activity_list_is_public(self):
        response = self.client.get("/activities")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test Activity", response.json())

    def test_signup_and_unregister_require_teacher_login(self):
        signup = self.client.post(
            "/activities/Test%20Activity/signup", params={"email": "student@test.edu"}
        )
        unregister = self.client.delete(
            "/activities/Test%20Activity/unregister",
            params={"email": "student@test.edu"},
        )
        self.assertEqual(signup.status_code, 401)
        self.assertEqual(unregister.status_code, 401)
        self.assertEqual(
            activity_app.activities["Test Activity"]["participants"], []
        )

    def test_teacher_can_sign_up_and_unregister_students(self):
        login = self.client.post(
            "/auth/login",
            json={"username": "teacher", "password": "test-password"},
        )
        self.assertEqual(login.status_code, 200)
        self.assertTrue(self.client.get("/auth/status").json()["authenticated"])

        signup = self.client.post(
            "/activities/Test%20Activity/signup", params={"email": "student@test.edu"}
        )
        unregister = self.client.delete(
            "/activities/Test%20Activity/unregister",
            params={"email": "student@test.edu"},
        )
        self.assertEqual(signup.status_code, 200)
        self.assertEqual(unregister.status_code, 200)

    def test_invalid_login_and_logout_do_not_authorize_changes(self):
        invalid_login = self.client.post(
            "/auth/login",
            json={"username": "teacher", "password": "incorrect"},
        )
        self.assertEqual(invalid_login.status_code, 401)

        login = self.client.post(
            "/auth/login",
            json={"username": "teacher", "password": "test-password"},
        )
        self.assertEqual(login.status_code, 200)
        self.assertEqual(self.client.post("/auth/logout").status_code, 200)
        self.assertFalse(self.client.get("/auth/status").json()["authenticated"])
        response = self.client.post(
            "/activities/Test%20Activity/signup", params={"email": "student@test.edu"}
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
