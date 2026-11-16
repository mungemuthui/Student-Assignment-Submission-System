# Student-Assignment-Submission-System
Software Configuration Management (SCM) – Practical Application 

# The system should allow students to:
•	Register and log in.
•	View available assignments.
•	Submit an assignment.
•	View their submission status.
The system should also allow a lecturer to:
•	Log in.
•	Create an assignment.
•	View students' submissions.

Student Assignment Submission System

A web application that lets students register, log in, view assignments, submit work, and track their submission status. Lecturers log in, create assignments, and view student submissions.

Built with Python 3.9+ and its standard library only (http.server, sqlite3, hashlib). There are no packages to install.

Quick start

# 1. Create the first lecturer account (students register themselves)
python3 app.py create-lecturer "Dr Jane Doe" jane@uni.edu "a-strong-password"

# 2. Start the server
python3 app.py
# Open http://127.0.0.1:8000

Set PORT, SAS_DB, or SAS_UPLOADS in the environment to change the port, database file, or upload folder.

Run the tests

python3 -m unittest -v test_app

The tests cover password hashing, multipart upload parsing, filename sanitising, account validation, and an end-to-end workflow against a live local server (registration, login, role checks, assignment creation, submission, late flagging, lecturer access, file download, and logout).

Requirements mapping







Requirement



Where it is handled





Student register and log in



/register, /login, register_submit, login_submit





Lecturer log in



/login (lecturer accounts created via CLI)





View available assignments



/assignments





Submit an assignment



/assignments/<id> form, POST /assignments/<id>/submit





View submission status



/my-submissions (Submitted on time / Submitted late / Not submitted)





Lecturer creates an assignment



/lecturer/assignments/new, POST /lecturer/assignments





Lecturer views students' submissions



/lecturer/assignments/<id>/submissions



Project layout

app.py          Server, routes, database schema, HTML templates
test_app.py     Unit and end-to-end tests
README.md       This file
.gitignore      Keeps the database, uploads, and caches out of version control

Runtime files created automatically: sas.db (SQLite database) and uploads/ (submitted files).

Business rules





Students can self-register. Lecturers are created by an administrator through the command line.



Lecturers see only the assignments they created and can only view submissions for those assignments.



Students see only their own submissions and can download only their own files.



Allowed file types: .pdf, .docx, .zip, .txt, .py, .java, .c, .cpp, .js. Maximum size 10 MB.



Deadlines are stored in UTC and entered as UTC. A submission after the due date is accepted and flagged as late.



Passwords are hashed with PBKDF2-HMAC-SHA256 (200,000 iterations and a random salt per user).



Sessions use a random token in an HttpOnly, SameSite=Lax cookie.



Known limitations

These are deliberate scope limits for the project. Each one is a candidate change request (CR) for the SCM demonstration.





No CSRF tokens on forms. SameSite=Lax cookies reduce the risk, but a token is the proper fix.



No login rate limiting or account lockout.



Sessions do not expire automatically.



Deadlines are UTC only. Timezone handling and late penalties are not implemented.



Lecturers cannot grade or leave feedback yet.



The server listens on 127.0.0.1 only and is not hardened for public deployment. It has no HTTPS.



Uploaded files are not virus-scanned. Only the extension is checked, not the file contents.



Source control notes

Commit the baseline first, then make each change on a feature branch tied to a CR ID (for example, CR-003: add grading). Tag releases with semantic versions. Do not commit sas.db or uploads/.
