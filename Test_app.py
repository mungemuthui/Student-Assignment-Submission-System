"""Tests for the Student Assignment Submission System.

Run with:  python3 -m unittest -v test_app
"""
import os
import tempfile
import threading
import unittest
import uuid
from contextlib import closing
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode

# Point the app at throwaway storage before it is imported.
TMP = tempfile.mkdtemp(prefix="sas-test-")
os.environ["SAS_DB"] = os.path.join(TMP, "test.db")
os.environ["SAS_UPLOADS"] = os.path.join(TMP, "uploads")

import app  # noqa: E402


def multipart(fields, file_name, file_bytes):
    boundary = "----testboundary" + uuid.uuid4().hex
    body = b""
    for key, value in fields.items():
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n'
                 f"{value}\r\n").encode()
    body += (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
             f'filename="{file_name}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()
    body += file_bytes + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


class UnitTests(unittest.TestCase):
    def test_password_hash_round_trip(self):
        stored = app.hash_password("correct horse")
        self.assertTrue(app.verify_password("correct horse", stored))
        self.assertFalse(app.verify_password("wrong password", stored))

    def test_multipart_parsing_keeps_binary_content(self):
        payload = b"line one\r\n--not-a-boundary\r\nline two\r\n"
        body, ctype = multipart({"title": "Essay"}, "essay.txt", payload)
        fields, files = app.parse_multipart(ctype, body)
        self.assertEqual(fields["title"], "Essay")
        self.assertEqual(files["file"], ("essay.txt", payload))

    def test_filename_sanitising_removes_paths(self):
        cleaned = app.sanitize_filename("../../etc/passwd")
        self.assertNotIn("/", cleaned)
        self.assertEqual(cleaned, "passwd")

    def test_account_validation(self):
        self.assertEqual(app.validate_account("", "a@b.co", "longpassword"), "Please enter your name.")
        self.assertEqual(app.validate_account("A", "not-an-email", "longpassword"),
                         "Please enter a valid email address.")
        self.assertEqual(app.validate_account("A", "a@b.co", "short"),
                         "Password must be at least 8 characters.")
        self.assertEqual(app.validate_account("A", "a@b.co", "longpassword"), "")
        self.assertEqual(
            app.validate_account("A", "Student@UNI.EDU", "Correct-Horse-Battery",
                                 student_registration=True),
            "",
        )
        self.assertEqual(
            app.validate_account("A", "student@example.com", "Correct-Horse-Battery",
                                 student_registration=True),
            "Please use your @uni.edu email address.",
        )
        self.assertEqual(
            app.validate_account("A", "student@uni.edu.attacker", "Correct-Horse-Battery",
                                 student_registration=True),
            "Please use your @uni.edu email address.",
        )
        self.assertEqual(
            app.validate_account("A", "student@uni.edu", "12345678",
                                 student_registration=True),
            "Password must be at least 12 characters.",
        )
        self.assertEqual(
            app.validate_account("A", "student@uni.edu", "Short-Pass1",
                                 student_registration=True),
            "Password must be at least 12 characters.",
        )


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.init_db()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    # ----- helpers

    def call(self, method, path, body=None, headers=None, cookie=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = dict(headers or {})
        if cookie:
            headers["Cookie"] = cookie
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, resp, data

    def form(self, method, path, fields, cookie=None):
        return self.call(method, path, urlencode(fields).encode(),
                         {"Content-Type": "application/x-www-form-urlencoded"}, cookie)

    def register(self, name, email, password="Correct-Horse-Battery"):
        status, resp, _ = self.form("POST", "/register",
                                    {"name": name, "email": email, "password": password})
        self.assertEqual(status, 303)
        return resp.getheader("Set-Cookie").split(";")[0]

    def login(self, email, password="password123"):
        status, resp, _ = self.form("POST", "/login", {"email": email, "password": password})
        self.assertEqual(status, 303)
        return resp.getheader("Set-Cookie").split(";")[0]

    def make_lecturer(self, name, email, password="password123"):
        with closing(app.connect()) as conn:
            conn.execute("INSERT INTO users (name, email, password_hash, role, created_at) "
                         "VALUES (?, ?, ?, 'lecturer', ?)",
                         (name, email, app.hash_password(password), app.now_iso()))
            conn.commit()
        return self.login(email, password)

    def assignment_id(self, title):
        with closing(app.connect()) as conn:
            row = conn.execute("SELECT id FROM assignments WHERE title = ?", (title,)).fetchone()
        return row["id"]

    def create_assignment(self, lecturer_cookie, title, due):
        status, resp, _ = self.form("POST", "/lecturer/assignments",
                                    {"title": title, "description": "Write 500 words.",
                                     "due_at": due}, lecturer_cookie)
        self.assertEqual(status, 303, resp.getheader("Location"))
        return self.assignment_id(title)

    def submit(self, aid, student_cookie, filename, payload):
        body, ctype = multipart({}, filename, payload)
        return self.call("POST", f"/assignments/{aid}/submit", body,
                         {"Content-Type": ctype}, student_cookie)

    # ----- the full workflow

    def test_full_workflow(self):
        tag = uuid.uuid4().hex[:8]
        student_email = f"stu-{tag}@uni.edu"
        other_email = f"other-{tag}@uni.edu"
        lecturer_email = f"lec-{tag}@uni.test"

        # Unauthenticated users are sent to the login page.
        status, resp, _ = self.call("GET", "/assignments")
        self.assertEqual(status, 303)
        self.assertTrue(resp.getheader("Location").startswith("/login"))

        # Students register and are logged in.
        student = self.register("Sam Student", student_email)
        other = self.register("Olu Other", other_email)
        status, _, body = self.call("GET", "/assignments", cookie=student)
        self.assertEqual(status, 200)

        # Students cannot reach lecturer pages.
        status, _, _ = self.call("GET", "/lecturer/assignments/new", cookie=student)
        self.assertEqual(status, 403)

        # Lecturer logs in and creates assignments (one future, one past for late testing).
        lecturer = self.make_lecturer("Dr Lee", lecturer_email)
        open_title = f"Essay {tag}"
        late_title = f"Lab {tag}"
        open_id = self.create_assignment(lecturer, open_title, "2030-01-01T12:00")
        late_id = self.create_assignment(lecturer, late_title, "2020-01-01T12:00")

        # Students see the assignments.
        status, _, body = self.call("GET", "/assignments", cookie=student)
        self.assertIn(open_title.encode(), body)
        self.assertIn(late_title.encode(), body)

        # Students submit an allowed file.
        payload = b"%PDF-1.4 fake essay content"
        status, resp, _ = self.submit(open_id, student, "essay.pdf", payload)
        self.assertEqual(status, 303)
        self.assertTrue(resp.getheader("Location").startswith("/my-submissions"))

        # Disallowed file types are rejected with a message.
        status, resp, _ = self.submit(open_id, student, "malware.exe", b"MZ")
        self.assertEqual(status, 303)
        self.assertIn("not%20allowed", resp.getheader("Location"))

        # Submission status is visible to the student.
        status, _, body = self.call("GET", "/my-submissions", cookie=student)
        self.assertEqual(status, 200)
        self.assertIn(b"essay.pdf", body)
        self.assertIn(b"Submitted on time", body)
        self.assertIn(b"Not submitted", body)  # the lab has nothing yet

        # A late submission is flagged as late.
        status, _, _ = self.submit(late_id, student, "lab.txt", b"late work")
        self.assertEqual(status, 303)
        status, _, body = self.call("GET", "/my-submissions", cookie=student)
        self.assertIn(b"Submitted late", body)

        # Lecturer sees all submissions for their assignment, with the student's details.
        status, _, body = self.call("GET", f"/lecturer/assignments/{open_id}/submissions",
                                    cookie=lecturer)
        self.assertEqual(status, 200)
        self.assertIn(student_email.encode(), body)
        self.assertIn(b"essay.pdf", body)

        # Another student cannot see the lecturer's submissions or download the file.
        status, _, _ = self.call("GET", f"/lecturer/assignments/{open_id}/submissions", cookie=other)
        self.assertEqual(status, 403)
        with closing(app.connect()) as conn:
            sid = conn.execute("SELECT id FROM submissions WHERE assignment_id = ?",
                               (open_id,)).fetchone()["id"]
        status, _, _ = self.call("GET", f"/submissions/{sid}/download", cookie=other)
        self.assertEqual(status, 403)

        # The owner (student) and the lecturer can download the exact bytes.
        status, _, data = self.call("GET", f"/submissions/{sid}/download", cookie=student)
        self.assertEqual(status, 200)
        self.assertEqual(data, payload)
        status, _, data = self.call("GET", f"/submissions/{sid}/download", cookie=lecturer)
        self.assertEqual(status, 200)
        self.assertEqual(data, payload)

        # Logging out ends the session.
        status, _, _ = self.call("POST", "/logout", cookie=student)
        self.assertEqual(status, 303)
        status, resp, _ = self.call("GET", "/my-submissions", cookie=student)
        self.assertEqual(status, 303)

    def test_invalid_registration_does_not_create_user(self):
        test_cases = (
            (f"wrong-domain-{uuid.uuid4().hex}@example.com",
             "Correct-Horse-Battery", "Please use your @uni.edu email address."),
            (f"short-password-{uuid.uuid4().hex}@uni.edu",
             "12345678", "Password must be at least 12 characters."),
        )

        for email, password, expected_error in test_cases:
            status, _, body = self.form(
                "POST", "/register",
                {"name": "Test Student", "email": email, "password": password},
            )
            self.assertEqual(status, 400)
            self.assertIn(expected_error.encode(), body)
            with closing(app.connect()) as conn:
                user = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            self.assertIsNone(user)


if __name__ == "__main__":
    unittest.main()
