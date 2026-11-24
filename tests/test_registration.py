import unittest
from unittest.mock import Mock, patch

from app import User, app, db


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def register(self, email, password):
        return self.client.post(
            "/register",
            data={"name": "Test Student", "email": email, "password": password},
            follow_redirects=True,
        )

    def assert_registration_rejected(self, email, password, message):
        with patch.object(db.session, "add") as add, patch.object(db.session, "commit") as commit:
            response = self.register(email, password)

        self.assertIn(message, response.get_data(as_text=True))
        add.assert_not_called()
        commit.assert_not_called()

    def test_accepts_uni_edu_email(self):
        query = Mock()
        query.filter_by.return_value.first.return_value = None

        with app.app_context(), patch.object(User, "query", query), \
                patch.object(db.session, "add") as add, \
                patch.object(db.session, "commit") as commit:
            response = self.register("Student@UNI.EDU", "Correct-Horse-Battery")

        self.assertIn("Registration successful", response.get_data(as_text=True))
        user = add.call_args.args[0]
        self.assertEqual(user.email, "student@uni.edu")
        commit.assert_called_once()

    def test_rejects_non_uni_domain(self):
        self.assert_registration_rejected(
            "student@example.com", "Correct-Horse-Battery",
            "Please use your @uni.edu email address.",
        )

    def test_rejects_uni_domain_lookalike(self):
        self.assert_registration_rejected(
            "student@uni.edu.attacker", "Correct-Horse-Battery",
            "Please use your @uni.edu email address.",
        )

    def test_rejects_short_weak_password(self):
        self.assert_registration_rejected(
            "student@uni.edu", "12345678",
            "Password must be at least 12 characters.",
        )

    def test_rejects_password_below_minimum(self):
        self.assert_registration_rejected(
            "student@uni.edu", "Short-Pass1",
            "Password must be at least 12 characters.",
        )


if __name__ == "__main__":
    unittest.main()
