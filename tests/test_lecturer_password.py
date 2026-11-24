import unittest
from unittest.mock import Mock, patch

from app import User, app, db


class LecturerPasswordCommandTests(unittest.TestCase):
    def test_resets_password_using_hidden_confirmation_prompt(self):
        lecturer = User(name="Test Lecturer", email="lecturer@uni.edu",
                        password_hash="", role="lecturer")
        query = Mock()
        query.filter_by.return_value.first.return_value = lecturer

        with app.app_context(), \
                patch.object(User, "query", query), \
                patch.object(db.session, "commit") as commit:
            result = app.test_cli_runner().invoke(
                args=["reset-lecturer-password", "LECTURER@UNI.EDU"],
                input="Long-Enough-Passphrase!\nLong-Enough-Passphrase!\n",
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(lecturer.check_password("Long-Enough-Passphrase!"))
        query.filter_by.assert_called_once_with(
            email="lecturer@uni.edu", role="lecturer"
        )
        commit.assert_called_once()

    def test_does_not_prompt_when_lecturer_is_not_found(self):
        query = Mock()
        query.filter_by.return_value.first.return_value = None

        with app.app_context(), \
                patch.object(User, "query", query), \
                patch.object(db.session, "commit") as commit:
            result = app.test_cli_runner().invoke(
                args=["reset-lecturer-password", "missing@uni.edu"]
            )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("No lecturer account found", result.output)
        commit.assert_not_called()

    def test_rejects_short_password(self):
        lecturer = User(name="Test Lecturer", email="lecturer@uni.edu",
                        password_hash="", role="lecturer")
        query = Mock()
        query.filter_by.return_value.first.return_value = lecturer

        with app.app_context(), \
                patch.object(User, "query", query), \
                patch.object(db.session, "commit") as commit:
            result = app.test_cli_runner().invoke(
                args=["reset-lecturer-password", "lecturer@uni.edu"],
                input="short\nshort\n",
            )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("at least 12 characters", result.output)
        commit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
