# Student Assignment Submission System

## Setup

    python -m venv venv
    source venv/bin/activate        # Windows: venv\Scripts\activate
    pip install -r requirements.txt

## Create a lecturer account

    flask --app app create-lecturer "Dr Jane Doe" jane@university.edu

## Reset a lecturer password

From the folder containing `app.py`, run:

    flask --app app reset-lecturer-password jane@university.edu

Enter and confirm the new password at the hidden prompt. It must be at least 12
characters long.

## Run

    python app.py

Open http://127.0.0.1:5000

Students register at /register. Lecturers log in at /login with the account created above.
After signing in, lecturers can create assignments from the dashboard, review submissions,
download student files, and save a mark out of 100 with optional feedback. Students can see
their marks and feedback on the My Submissions page.

Set a real secret key in production: `export SECRET_KEY="your-long-random-string"`.

## Structure

    app.py                 Models, routes, CLI command
    templates/             Jinja2 HTML templates
    uploads/               Submitted files (created automatically)
    submissions.db         SQLite database (created automatically)
