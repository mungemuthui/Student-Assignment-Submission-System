import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app import User, app, db, login_manager


class MarkingTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        self.lecturer = User(id=17, name="Test Lecturer", email="lecturer@uni.edu",
                             password_hash="", role="lecturer")
        self.submission = SimpleNamespace(
            assignment_id=4,
            assignment=SimpleNamespace(lecturer_id=17),
            score=None,
            feedback=None,
            marked_at=None,
        )

    def post_mark(self, data, lecturer_id=17):
        self.submission.assignment.lecturer_id = lecturer_id
        with self.client.session_transaction() as session:
            session["_user_id"] = str(self.lecturer.id)
            session["_fresh"] = True

        with patch.object(login_manager, "_user_callback", return_value=self.lecturer), \
                patch.object(db, "get_or_404", return_value=self.submission), \
                patch.object(db.session, "commit") as commit:
            response = self.client.post(
                "/lecturer/submissions/9/mark",
                data=data,
                follow_redirects=False,
            )
        return response, commit

    def test_lecturer_can_save_mark_and_feedback(self):
        response, commit = self.post_mark({"score": "87.5", "feedback": "Good work"})

        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertIn("Mark saved.", str(session["_flashes"]))
        self.assertEqual(self.submission.score, 87.5)
        self.assertEqual(self.submission.feedback, "Good work")
        self.assertIsNotNone(self.submission.marked_at)
        commit.assert_called_once()

    def test_rejects_marks_outside_range(self):
        response, commit = self.post_mark({"score": "101", "feedback": ""})

        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertIn("Mark must be between 0 and 100.", str(session["_flashes"]))
        commit.assert_not_called()

    def test_lecturer_cannot_mark_another_lecturers_submission(self):
        response, commit = self.post_mark({"score": "75"}, lecturer_id=18)

        self.assertEqual(response.status_code, 403)
        commit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
