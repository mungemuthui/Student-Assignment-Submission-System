import os
import uuid
from datetime import datetime
from functools import wraps
from math import isfinite

import click
from flask import (Flask, render_template, redirect, url_for, flash,
                   request, abort, send_from_directory)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user,
                         logout_user, login_required, current_user)
from sqlalchemy import inspect, text
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"pdf", "docx", "zip", "txt"}
MIN_PASSWORD_LENGTH = 12

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-me"),
    SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(BASE_DIR, "submissions.db"),
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16 MB upload limit
)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "error"


# ---------- Models ----------

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="student")  # "student" or "lecturer"

    assignments = db.relationship("Assignment", backref="lecturer", lazy=True)
    submissions = db.relationship("Submission", backref="student", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_lecturer(self):
        return self.role == "lecturer"


class Assignment(db.Model):
    __tablename__ = "assignments"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default="")
    due_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    lecturer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    submissions = db.relationship("Submission", backref="assignment", lazy=True,
                                  cascade="all, delete-orphan")

    def is_past_due(self):
        return self.due_date is not None and datetime.utcnow() > self.due_date

    def submission_for(self, student):
        return next((s for s in self.submissions if s.student_id == student.id), None)


class Submission(db.Model):
    __tablename__ = "submissions"
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey("assignments.id"), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_late = db.Column(db.Boolean, default=False)
    score = db.Column(db.Float, nullable=True)
    feedback = db.Column(db.Text, nullable=True)
    marked_at = db.Column(db.DateTime, nullable=True)

    @property
    def status(self):
        return "Submitted late" if self.is_late else "Submitted"


# ---------- Helpers ----------

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def role_required(role):
    """Restrict a view to users with the given role ('student' or 'lecturer')."""
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user.role != role:
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


# ---------- Shared routes ----------

@app.route("/")
def index():
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
    if current_user.is_lecturer:
        return redirect(url_for("lecturer_dashboard"))
    return redirect(url_for("student_assignments"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name:
            flash("Full name is required.", "error")
        elif not email:
            flash("Email is required.", "error")
        elif email.count("@") != 1 or email.rsplit("@", 1)[1] != "uni.edu":
            flash("Please use your @uni.edu email address.", "error")
        elif len(password) < MIN_PASSWORD_LENGTH:
            flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.", "error")
        elif User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
        else:
            user = User(name=name, email=email, role="student")
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("index"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/submissions/<int:submission_id>/download")
@login_required
def download_submission(submission_id):
    sub = db.get_or_404(Submission, submission_id)
    # Only the owning student or a lecturer may download a file
    if not (current_user.is_lecturer or sub.student_id == current_user.id):
        abort(403)
    return send_from_directory(app.config["UPLOAD_FOLDER"], sub.stored_filename,
                               as_attachment=True, download_name=sub.original_filename)


# ---------- Student routes ----------

@app.route("/assignments")
@role_required("student")
def student_assignments():
    assignments = Assignment.query.order_by(Assignment.due_date.asc()).all()
    return render_template("student_assignments.html", assignments=assignments)


@app.route("/assignments/<int:assignment_id>/submit", methods=["GET", "POST"])
@role_required("student")
def submit_assignment(assignment_id):
    assignment = db.get_or_404(Assignment, assignment_id)
    existing = assignment.submission_for(current_user)

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            flash("Please choose a file to upload.", "error")
        elif not allowed_file(file.filename):
            flash("File type not allowed. Allowed types: " +
                  ", ".join(sorted(ALLOWED_EXTENSIONS)), "error")
        else:
            safe_name = secure_filename(file.filename)
            stored = f"{uuid.uuid4().hex}_{safe_name}"
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], stored))

            if existing:
                # Resubmission replaces the previous file
                old_path = os.path.join(app.config["UPLOAD_FOLDER"], existing.stored_filename)
                if os.path.exists(old_path):
                    os.remove(old_path)
                submission = existing
            else:
                submission = Submission(assignment_id=assignment.id, student_id=current_user.id)
                db.session.add(submission)

            submission.original_filename = safe_name
            submission.stored_filename = stored
            submission.submitted_at = datetime.utcnow()
            submission.is_late = assignment.is_past_due()
            db.session.commit()

            flash("Assignment submitted successfully.", "success")
            return redirect(url_for("my_submissions"))

    return render_template("submit.html", assignment=assignment, existing=existing)


@app.route("/my-submissions")
@role_required("student")
def my_submissions():
    assignments = Assignment.query.order_by(Assignment.due_date.asc()).all()
    rows = [{"assignment": a, "submission": a.submission_for(current_user)} for a in assignments]
    return render_template("my_submissions.html", rows=rows)


# ---------- Lecturer routes ----------

@app.route("/lecturer")
@role_required("lecturer")
def lecturer_dashboard():
    assignments = (Assignment.query.filter_by(lecturer_id=current_user.id)
                   .order_by(Assignment.created_at.desc()).all())
    return render_template("lecturer_dashboard.html", assignments=assignments)


@app.route("/lecturer/assignments/new", methods=["GET", "POST"])
@role_required("lecturer")
def create_assignment():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        due_raw = request.form.get("due_date", "")

        due_date = None
        if due_raw:
            try:
                due_date = datetime.strptime(due_raw, "%Y-%m-%dT%H:%M")
            except ValueError:
                flash("Invalid due date format.", "error")
                return render_template("create_assignment.html")

        if not title:
            flash("Title is required.", "error")
        else:
            assignment = Assignment(title=title, description=description,
                                    due_date=due_date, lecturer_id=current_user.id)
            db.session.add(assignment)
            db.session.commit()
            flash("Assignment created.", "success")
            return redirect(url_for("lecturer_dashboard"))

    return render_template("create_assignment.html")


@app.route("/lecturer/assignments/<int:assignment_id>/submissions")
@role_required("lecturer")
def view_submissions(assignment_id):
    assignment = db.get_or_404(Assignment, assignment_id)
    if assignment.lecturer_id != current_user.id:
        abort(403)
    return render_template("view_submissions.html", assignment=assignment)


@app.route("/lecturer/submissions/<int:submission_id>/mark", methods=["POST"])
@role_required("lecturer")
def mark_submission(submission_id):
    submission = db.get_or_404(Submission, submission_id)
    if submission.assignment.lecturer_id != current_user.id:
        abort(403)

    score_raw = request.form.get("score", "").strip()
    try:
        score = float(score_raw)
    except ValueError:
        flash("Enter a numeric mark from 0 to 100.", "error")
        return redirect(url_for("view_submissions",
                                assignment_id=submission.assignment_id))

    if not isfinite(score) or not 0 <= score <= 100:
        flash("Mark must be between 0 and 100.", "error")
        return redirect(url_for("view_submissions",
                                assignment_id=submission.assignment_id))

    submission.score = score
    submission.feedback = request.form.get("feedback", "").strip() or None
    submission.marked_at = datetime.utcnow()
    db.session.commit()
    flash("Mark saved.", "success")
    return redirect(url_for("view_submissions",
                            assignment_id=submission.assignment_id))


# ---------- CLI ----------

@app.cli.command("create-lecturer")
@click.argument("name")
@click.argument("email")
@click.password_option()
def create_lecturer(name, email, password):
    """Create a lecturer account: flask --app app create-lecturer "Name" email"""
    email = email.strip().lower()
    if User.query.filter_by(email=email).first():
        click.echo("A user with that email already exists.")
        return
    lecturer = User(name=name, email=email, role="lecturer")
    lecturer.set_password(password)
    db.session.add(lecturer)
    db.session.commit()
    click.echo(f"Lecturer '{name}' created.")


@app.cli.command("reset-lecturer-password")
@click.argument("email")
def reset_lecturer_password(email):
    """Set a lecturer's password using a hidden, confirmed prompt."""
    email = email.strip().lower()
    lecturer = User.query.filter_by(email=email, role="lecturer").first()
    if lecturer is None:
        raise click.ClickException("No lecturer account found for that email.")

    password = click.prompt(
        "New password",
        hide_input=True,
        confirmation_prompt=True,
    )
    if len(password) < MIN_PASSWORD_LENGTH:
        raise click.ClickException(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )

    lecturer.set_password(password)
    db.session.commit()
    click.echo(f"Password updated for lecturer '{lecturer.name}'.")


with app.app_context():
    db.create_all()
    submission_columns = {
        column["name"] for column in inspect(db.engine).get_columns("submissions")
    }
    if "score" not in submission_columns:
        db.session.execute(text("ALTER TABLE submissions ADD COLUMN score FLOAT"))
    if "feedback" not in submission_columns:
        db.session.execute(text("ALTER TABLE submissions ADD COLUMN feedback TEXT"))
    if "marked_at" not in submission_columns:
        db.session.execute(text("ALTER TABLE submissions ADD COLUMN marked_at DATETIME"))
    db.session.commit()

if __name__ == "__main__":
    app.run(debug=True)
