import os
from functools import wraps

from flask import (
    Flask, render_template, render_template_string, request,
    redirect, url_for, session, abort, flash
)
from werkzeug.security import check_password_hash
from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv

from db import get_db_connection


# =========================================================
# 1. APPLICATION CONFIGURATION
# =========================================================

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("SECRET_KEY is missing from .env")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv(
        "SESSION_COOKIE_SECURE", "False"
    ).lower() == "true",
    PERMANENT_SESSION_LIFETIME=1800
)


# =========================================================
# 2. ROLE CONFIGURATION
# =========================================================

ROLE_ALIASES = {
    "ADMIN": "SUPER_ADMIN"
}

ROLE_MENUS = {
    "STUDENT": [
        {"id": "overview", "label": "Dashboard", "icon": "⌂",
         "url": "/dashboard"},
        {"id": "profile", "label": "My Profile", "icon": "◉",
         "url": "/student/profile"},
        {"id": "my_faculty", "label": "My Faculty", "icon": "♙",
         "url": "/student/my-faculty"},
        {"id": "attendance", "label": "My Attendance", "icon": "▤",
         "url": "/student/attendance"},
        {"id": "events", "label": "Events", "icon": "▦",
         "url": "/student/events"},
        {"id": "clubs", "label": "Clubs", "icon": "♧",
         "url": "/student/clubs"},
        {"id": "announcements", "label": "Faculty Messages", "icon": "✉",
         "url": "/student/messages"},
        {"id": "feedback", "label": "Feedback", "icon": "✉",
         "url": "/student/feedback"}
    ],

    "FACULTY": [
        {"id": "overview", "label": "Dashboard", "icon": "⌂",
         "url": "/dashboard"},
        {"id": "profile", "label": "My Profile", "icon": "◉",
         "url": "/faculty/profile"},
        {"id": "students", "label": "Students", "icon": "♙",
         "url": "/faculty/students"},
        {"id": "announcements", "label": "Announcements", "icon": "✉",
         "url": "/faculty/announcements"},
        {"id": "activities", "label": "Activities", "icon": "▦",
         "url": "/faculty/activities"}
    ],

    "HOD": [],
    "OPERATOR": [],
    "SUPER_ADMIN": []
}

ROLE_TEMPLATES = {
    "STUDENT": "student_dashboard.html",
    "FACULTY": "faculty_dashboard.html",
    "HOD": "hod_dashboard.html",
    "OPERATOR": "operator_dashboard.html",
    "SUPER_ADMIN": "superadmin_dashboard.html"
}


# =========================================================
# 3. AUTHENTICATION DECORATORS
# =========================================================

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("home"))

        return function(*args, **kwargs)

    return wrapper


def role_required(*allowed_roles):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("home"))

            if session.get("role") not in allowed_roles:
                abort(403)

            return function(*args, **kwargs)

        return wrapper

    return decorator


# =========================================================
# 4. DATABASE HELPERS
# =========================================================

def fetch_all(query, params=()):
    connection = get_db_connection()

    if connection is None:
        raise RuntimeError("Database connection failed.")

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params)
        return cursor.fetchall()

    finally:
        if cursor:
            cursor.close()

        connection.close()


def fetch_one(query, params=()):
    connection = get_db_connection()

    if connection is None:
        raise RuntimeError("Database connection failed.")

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params)
        return cursor.fetchone()

    finally:
        if cursor:
            cursor.close()

        connection.close()


# =========================================================
# 5. LOGGED-IN USER DETAILS
# =========================================================

def get_logged_in_student():
    student_id = session.get("student_id")

    if not student_id:
        return None

    return fetch_one("""
        SELECT
            s.*,
            d.dept_name AS department,
            s.year_of_study AS year,
            s.mobile_number AS phone
        FROM students s
        LEFT JOIN departments d
            ON d.dept_id = s.dept_id
        WHERE s.student_id = %s
        LIMIT 1
    """, (student_id,))


def get_logged_in_faculty():
    faculty_id = session.get("faculty_id")

    if not faculty_id:
        return None

    return fetch_one("""
        SELECT
            f.*,
            d.dept_name AS department
        FROM faculty f
        LEFT JOIN departments d
            ON d.dept_id = f.dept_id
        WHERE f.faculty_id = %s
        LIMIT 1
    """, (faculty_id,))


# =========================================================
# 6. HOME AND LOGIN
# =========================================================

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    role = request.form.get("role", "").strip().upper()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not role or not username or not password:
        return render_template(
            "login.html",
            error="Please fill in all fields."
        )

    selected_role = ROLE_ALIASES.get(role, role)

    connection = get_db_connection()

    if connection is None:
        return render_template(
            "login.html",
            error="Database connection failed."
        )

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                user_id,
                username,
                password_hash,
                role,
                student_id,
                faculty_id,
                is_active
            FROM user_accounts
            WHERE username = %s
            LIMIT 1
        """, (username,))

        account = cursor.fetchone()

        if not account:
            return render_template(
                "login.html",
                error="Invalid username or password."
            )

        if not account["is_active"]:
            return render_template(
                "login.html",
                error="Your account is inactive."
            )

        if not check_password_hash(
            account["password_hash"], password
        ):
            return render_template(
                "login.html",
                error="Invalid username or password."
            )

        actual_role = ROLE_ALIASES.get(
            account["role"].upper(),
            account["role"].upper()
        )

        if selected_role != actual_role:
            return render_template(
                "login.html",
                error="Incorrect login role selected."
            )

        if actual_role not in ROLE_TEMPLATES:
            return render_template(
                "login.html",
                error="Account role is not configured."
            )

        # Preserve the existing account and password.
        session.clear()
        session.permanent = True

        session["user_id"] = account["user_id"]
        session["username"] = account["username"]
        session["role"] = actual_role
        session["student_id"] = account["student_id"]
        session["faculty_id"] = account["faculty_id"]

        if actual_role == "SUPER_ADMIN":
            return redirect(url_for("superadmin_dashboard"))

        return redirect(url_for("dashboard"))

    except Exception:
        app.logger.exception("Login error")

        return render_template(
            "login.html",
            error="Login failed. Please try again."
        )

    finally:
        if cursor:
            cursor.close()

        connection.close()


# =========================================================
# 7. MAIN DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():
    role = session.get("role")

    if role == "SUPER_ADMIN":
        return redirect(url_for("superadmin_dashboard"))

    if role == "OPERATOR":
        return redirect(url_for("operator_dashboard"))

    template = ROLE_TEMPLATES.get(role)

    if not template:
        abort(403)

    student = None
    faculty = None
    faculty_stats = {}

    try:
        if role == "STUDENT":
            student = get_logged_in_student()

            if not student:
                abort(404)

        elif role == "FACULTY":
            faculty = get_logged_in_faculty()

            if not faculty:
                abort(404)

            faculty_stats["students"] = fetch_one("""
                SELECT COUNT(*) AS total
                FROM students
                WHERE dept_id = %s
            """, (faculty["dept_id"],))["total"]

            faculty_stats["announcements"] = fetch_one("""
                SELECT COUNT(*) AS total
                FROM faculty_announcements
                WHERE faculty_id = %s
            """, (faculty["faculty_id"],))["total"]

            faculty_stats["activities"] = fetch_one("""
                SELECT COUNT(*) AS total
                FROM events
                WHERE is_active = TRUE
            """)["total"]

    except HTTPException:
        raise

    except Exception:
        app.logger.exception("Dashboard loading error")
        abort(500)

    return render_template(
        template,
        page_title=role.replace("_", " ").title(),
        nav_items=ROLE_MENUS[role],
        active_page="overview",
        student=student or {},
        faculty=faculty or {},
        faculty_stats=faculty_stats
    )


# =========================================================
# 8. STUDENT PROFILE
# =========================================================

@app.route("/student/profile")
@login_required
@role_required("STUDENT")
def student_profile():
    try:
        student = get_logged_in_student()

        if not student:
            abort(404)

    except HTTPException:
        raise

    except Exception:
        app.logger.exception("Student profile error")
        abort(500)

    return render_template(
        "student_profile.html",
        student=student,
        page_title="My Profile",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="profile"
    )


# =========================================================
# 9. STUDENT MY FACULTY
# =========================================================

@app.route("/student/my-faculty")
@login_required
@role_required("STUDENT")
def student_my_faculty():
    try:
        student = get_logged_in_student()

        if not student:
            abort(404)

        faculty_list = fetch_all("""
            SELECT
                faculty_id,
                faculty_name,
                designation,
                email,
                mobile_number
            FROM faculty
            WHERE dept_id = %s
            ORDER BY faculty_name
        """, (student["dept_id"],))

    except HTTPException:
        raise

    except Exception:
        app.logger.exception("Student My Faculty loading error")
        abort(500)

    html = r"""
    {% extends "base.html" %}

    {% block title %}My Faculty | Campus Connect{% endblock %}

    {% block content %}
    <style>
    .my-faculty-page{
        max-width:1150px;
        margin:auto;
        padding:10px 0 30px;
    }

    .my-faculty-heading{margin-bottom:22px}
    .my-faculty-heading h1{margin:0 0 7px;font-size:28px}
    .my-faculty-heading p{margin:0;color:#64748b}

    .faculty-grid{
        display:grid;
        grid-template-columns:repeat(auto-fit,minmax(270px,1fr));
        gap:18px;
    }

    .faculty-card{
        background:white;
        border:1px solid #e2e8f0;
        border-radius:14px;
        padding:20px;
    }

    .faculty-card-top{
        display:flex;
        gap:13px;
        align-items:center;
        margin-bottom:16px;
    }

    .faculty-avatar{
        width:48px;
        height:48px;
        border-radius:50%;
        display:flex;
        align-items:center;
        justify-content:center;
        background:#e8efff;
        color:#2456b3;
        font-weight:700;
        font-size:19px;
    }

    .faculty-card h2{font-size:17px;margin:0 0 4px}
    .faculty-designation{font-size:13px;color:#64748b}

    .faculty-detail{
        display:flex;
        gap:9px;
        padding:9px 0;
        border-top:1px solid #edf0f5;
        font-size:14px;
        overflow-wrap:anywhere;
    }

    .faculty-detail strong{min-width:65px;color:#64748b}
    .faculty-detail a{color:#2563eb;text-decoration:none}

    .faculty-empty{
        padding:34px;
        text-align:center;
        border:1px dashed #cbd5e1;
        border-radius:14px;
    }
    </style>

    <section class="my-faculty-page">
        <div class="my-faculty-heading">
            <h1>My Faculty</h1>
            <p>Faculty members from your department.</p>
        </div>

        {% if faculty_list %}
        <div class="faculty-grid">

            {% for faculty in faculty_list %}
            <article class="faculty-card">

                <div class="faculty-card-top">
                    <div class="faculty-avatar">
                        {{ faculty.faculty_name[:1]|upper }}
                    </div>

                    <div>
                        <h2>{{ faculty.faculty_name }}</h2>
                        <div class="faculty-designation">
                            {{ faculty.designation or "Faculty Member" }}
                        </div>
                    </div>
                </div>

                <div class="faculty-detail">
                    <strong>Email</strong>
                    <span>
                        {% if faculty.email %}
                        <a href="mailto:{{ faculty.email }}">
                            {{ faculty.email }}
                        </a>
                        {% else %}
                        Not provided
                        {% endif %}
                    </span>
                </div>

                <div class="faculty-detail">
                    <strong>Phone</strong>
                    <span>
                        {% if faculty.mobile_number %}
                        <a href="tel:{{ faculty.mobile_number }}">
                            {{ faculty.mobile_number }}
                        </a>
                        {% else %}
                        Not provided
                        {% endif %}
                    </span>
                </div>

            </article>
            {% endfor %}

        </div>
        {% else %}
        <div class="faculty-empty">
            <h2>No faculty details found</h2>
            <p>No faculty members are currently listed for your department.</p>
        </div>
        {% endif %}
    </section>
    {% endblock %}
    """

    return render_template_string(
        html,
        student=student,
        faculty_list=faculty_list,
        page_title="My Faculty",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="my_faculty"
    )


# =========================================================
# 10. STUDENT SUBJECT-WISE ATTENDANCE
# =========================================================

@app.route("/student/attendance")
@login_required
@role_required("STUDENT")
def student_attendance():
    try:
        student = get_logged_in_student()

        if not student:
            abort(404)

        student_id = student["student_id"]

        subjects = fetch_all("""
            SELECT
                sub.subject_id,
                sub.subject_code,
                sub.subject_name,
                a.total_classes,
                a.attended_classes
            FROM attendance a
            INNER JOIN subjects sub
                ON sub.subject_id = a.subject_id
            WHERE a.student_id = %s
            ORDER BY sub.subject_name
        """, (student_id,))

        total_classes = 0
        total_attended = 0

        for subject in subjects:
            subject["total_classes"] = int(
                subject["total_classes"] or 0
            )

            subject["attended_classes"] = int(
                subject["attended_classes"] or 0
            )

            subject["absent_classes"] = max(
                0,
                subject["total_classes"] -
                subject["attended_classes"]
            )

            subject["percentage"] = round(
                subject["attended_classes"] /
                subject["total_classes"] * 100,
                1
            ) if subject["total_classes"] else 0

            total_classes += subject["total_classes"]
            total_attended += subject["attended_classes"]

        overall_percentage = round(
            total_attended / total_classes * 100,
            1
        ) if total_classes else 0

    except HTTPException:
        raise

    except Exception:
        app.logger.exception("Student attendance loading error")
        abort(500)

    html = r"""
    {% extends "base.html" %}

    {% block title %}My Attendance | Campus Connect{% endblock %}

    {% block content %}
    <style>
    .attendance-page{
        max-width:1150px;
        margin:auto;
        padding:10px 0 32px;
    }

    .attendance-heading{margin-bottom:22px}
    .attendance-heading h1{margin:0 0 7px;font-size:28px}
    .attendance-heading p{margin:0;color:#64748b}

    .attendance-summary{
        display:grid;
        grid-template-columns:repeat(auto-fit,minmax(165px,1fr));
        gap:14px;
        margin-bottom:22px;
    }

    .attendance-stat{
        background:white;
        border:1px solid #e2e8f0;
        border-radius:15px;
        padding:18px;
    }

    .attendance-stat span{
        display:block;
        color:#64748b;
        font-size:13px;
        margin-bottom:8px;
    }

    .attendance-stat strong{font-size:25px}
    .good{color:#15945b}
    .low{color:#dc5555}

    .attendance-panel{
        background:white;
        border:1px solid #e2e8f0;
        border-radius:16px;
        padding:20px;
    }

    .attendance-panel h2{font-size:19px;margin:0 0 17px}

    .subject-list{
        display:grid;
        grid-template-columns:repeat(auto-fit,minmax(270px,1fr));
        gap:15px;
    }

    .subject-card{
        border:1px solid #e2e8f0;
        border-radius:13px;
        padding:16px;
    }

    .subject-top{
        display:flex;
        justify-content:space-between;
        gap:12px;
        margin-bottom:13px;
    }

    .subject-top h3{font-size:16px;margin:0 0 4px}
    .subject-code{font-size:12px;color:#64748b}

    .subject-percent{
        font-weight:750;
        font-size:20px;
        white-space:nowrap;
    }

    .attendance-track{
        height:8px;
        background:#e2e8f0;
        border-radius:30px;
        overflow:hidden;
        margin:12px 0;
    }

    .attendance-fill{
        height:100%;
        border-radius:30px;
    }

    .subject-counts{
        display:flex;
        flex-wrap:wrap;
        gap:8px 14px;
        color:#64748b;
        font-size:12px;
    }

    .empty-attendance{
        padding:25px;
        text-align:center;
        color:#64748b;
        border:1px dashed #cbd5e1;
        border-radius:12px;
    }
    </style>

    <div class="attendance-page">

        <div class="attendance-heading">
            <h1>My Attendance</h1>
            <p>View your subject-wise attendance summary.</p>
        </div>

        <div class="attendance-summary">

            <div class="attendance-stat">
                <span>Overall Attendance</span>
                <strong class="{{ 'good' if overall_percentage >= 75 else 'low' }}">
                    {{ overall_percentage }}%
                </strong>
            </div>

            <div class="attendance-stat">
                <span>Attended Classes</span>
                <strong>{{ total_attended }}</strong>
            </div>

            <div class="attendance-stat">
                <span>Total Classes</span>
                <strong>{{ total_classes }}</strong>
            </div>

            <div class="attendance-stat">
                <span>Absent Classes</span>
                <strong>{{ total_classes - total_attended }}</strong>
            </div>

        </div>

        <section class="attendance-panel">
            <h2>Subject-wise Attendance</h2>

            {% if subjects %}
            <div class="subject-list">

                {% for subject in subjects %}
                <article class="subject-card">

                    <div class="subject-top">
                        <div>
                            <h3>{{ subject.subject_name }}</h3>
                            <div class="subject-code">
                                {{ subject.subject_code }}
                            </div>
                        </div>

                        <div class="subject-percent {{ 'good' if subject.percentage >= 75 else 'low' }}">
                            {{ subject.percentage }}%
                        </div>
                    </div>

                    <div class="attendance-track">
                        <div
                            class="attendance-fill"
                            style="width:{{ subject.percentage }}%;background:{{ '#15945b' if subject.percentage >= 75 else '#dc5555' }}">
                        </div>
                    </div>

                    <div class="subject-counts">
                        <span><b>{{ subject.attended_classes }}</b> attended</span>
                        <span><b>{{ subject.total_classes }}</b> total</span>
                        <span><b>{{ subject.absent_classes }}</b> absent</span>
                    </div>

                </article>
                {% endfor %}

            </div>
            {% else %}
            <div class="empty-attendance">
                No attendance records have been added for your account yet.
            </div>
            {% endif %}

        </section>
    </div>
    {% endblock %}
    """

    return render_template_string(
        html,
        student=student,
        subjects=subjects,
        total_classes=total_classes,
        total_attended=total_attended,
        overall_percentage=overall_percentage,
        page_title="My Attendance",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="attendance"
    )


# =========================================================
# 11. STUDENT CLUBS
# =========================================================

@app.route("/student/clubs")
@login_required
@role_required("STUDENT")
def student_clubs():
    student_id = session.get("student_id")

    if not student_id:
        abort(403)

    try:
        clubs = fetch_all("""
            SELECT
                c.club_id,
                c.club_name,
                c.description,
                c.coordinator,
                c.is_active,
                EXISTS (
                    SELECT 1
                    FROM club_memberships cm
                    WHERE cm.club_id = c.club_id
                      AND cm.student_id = %s
                ) AS is_joined
            FROM clubs c
            WHERE c.is_active = TRUE
            ORDER BY c.club_name
        """, (student_id,))

        memberships = fetch_all("""
            SELECT
                cm.membership_id,
                cm.club_id,
                cm.membership_type,
                c.club_name
            FROM club_memberships cm
            INNER JOIN clubs c
                ON c.club_id = cm.club_id
            WHERE cm.student_id = %s
            ORDER BY c.club_name
        """, (student_id,))

    except Exception:
        app.logger.exception("Student clubs loading error")
        abort(500)

    return render_template(
        "student_clubs.html",
        clubs=clubs,
        memberships=memberships,
        page_title="Explore Clubs",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="clubs"
    )


@app.route("/student/clubs/<int:club_id>/join", methods=["POST"])
@login_required
@role_required("STUDENT")
def student_club_join(club_id):
    student_id = session.get("student_id")

    if not student_id:
        abort(403)

    connection = get_db_connection()

    if connection is None:
        abort(500)

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT club_id
            FROM clubs
            WHERE club_id = %s
              AND is_active = TRUE
            FOR UPDATE
        """, (club_id,))

        club = cursor.fetchone()

        if not club:
            connection.rollback()
            abort(404)

        cursor.execute("""
            SELECT membership_id
            FROM club_memberships
            WHERE student_id = %s
              AND club_id = %s
            LIMIT 1
        """, (student_id, club_id))

        existing = cursor.fetchone()

        if existing:
            connection.rollback()
            flash("You have already joined this club.", "info")

        else:
            cursor.execute("""
                INSERT INTO club_memberships
                    (student_id, club_id, membership_type)
                VALUES (%s, %s, %s)
            """, (student_id, club_id, "MEMBER"))

            connection.commit()
            flash("You have successfully joined the club!", "success")

    except HTTPException:
        connection.rollback()
        raise

    except Exception:
        connection.rollback()
        app.logger.exception("Club joining error")
        flash("Unable to join this club. Please try again.", "error")

    finally:
        if cursor:
            cursor.close()

        connection.close()

    return redirect(url_for("student_clubs"))


# =========================================================
# 12. STUDENT EVENTS
# =========================================================

@app.route("/student/events")
@login_required
@role_required("STUDENT")
def student_events():
    student_id = session.get("student_id")

    if not student_id:
        abort(403)

    try:
        events = fetch_all("""
            SELECT
                e.event_id,
                e.event_name,
                e.description,
                DATE_FORMAT(e.event_date, '%d %b %Y') AS event_date,
                e.venue,
                e.is_active,
                EXISTS (
                    SELECT 1
                    FROM event_registrations er
                    WHERE er.event_id = e.event_id
                      AND er.student_id = %s
                ) AS is_registered
            FROM events e
            WHERE e.is_active = TRUE
            ORDER BY e.event_date
        """, (student_id,))

    except Exception:
        app.logger.exception("Student events loading error")
        abort(500)

    return render_template(
        "student_events.html",
        events=events,
        page_title="Campus Events",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="events"
    )


@app.route(
    "/student/events/<int:event_id>/register",
    methods=["POST"]
)
@login_required
@role_required("STUDENT")
def student_event_register(event_id):
    student_id = session.get("student_id")

    if not student_id:
        abort(403)

    connection = get_db_connection()

    if connection is None:
        abort(500)

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT event_id
            FROM events
            WHERE event_id = %s
              AND is_active = TRUE
            FOR UPDATE
        """, (event_id,))

        event = cursor.fetchone()

        if not event:
            connection.rollback()
            abort(404)

        cursor.execute("""
            SELECT registration_id
            FROM event_registrations
            WHERE event_id = %s
              AND student_id = %s
            LIMIT 1
        """, (event_id, student_id))

        existing = cursor.fetchone()

        if existing:
            connection.rollback()
            flash("You are already registered for this event.", "info")

        else:
            cursor.execute("""
                INSERT INTO event_registrations
                    (event_id, student_id)
                VALUES (%s, %s)
            """, (event_id, student_id))

            connection.commit()
            flash("Event registration successful!", "success")

    except HTTPException:
        connection.rollback()
        raise

    except Exception:
        connection.rollback()
        app.logger.exception("Event registration error")
        flash("Unable to register. Please try again.", "error")

    finally:
        if cursor:
            cursor.close()

        connection.close()

    return redirect(url_for("student_events"))


# =========================================================
# 13. FACULTY PROFILE
# =========================================================

@app.route("/faculty/profile")
@login_required
@role_required("FACULTY")
def faculty_profile():
    try:
        faculty = get_logged_in_faculty()

        if not faculty:
            abort(404)

    except HTTPException:
        raise

    except Exception:
        app.logger.exception("Faculty profile loading error")
        abort(500)

    return render_template(
        "faculty_profile.html",
        faculty=faculty,
        page_title="My Profile",
        nav_items=ROLE_MENUS["FACULTY"],
        active_page="profile"
    )


# =========================================================
# 14. FACULTY STUDENTS
# =========================================================

@app.route("/faculty/students")
@login_required
@role_required("FACULTY")
def faculty_students():
    try:
        faculty = get_logged_in_faculty()

        if not faculty:
            abort(404)

        search = request.args.get("q", "").strip()

        students = fetch_all("""
            SELECT
                s.student_id,
                s.student_code,
                s.roll_number,
                s.student_name,
                s.mobile_number,
                s.year_of_study,
                s.semester,
                d.dept_name,
                sec.section_name,
                sec.academic_year
            FROM students s
            LEFT JOIN departments d
                ON d.dept_id = s.dept_id
            LEFT JOIN sections sec
                ON sec.section_id = s.section_id
            WHERE s.dept_id = %s
              AND (
                    s.student_name LIKE %s
                    OR s.roll_number LIKE %s
                    OR s.student_code LIKE %s
              )
            ORDER BY sec.section_name, s.roll_number
        """, (
            faculty["dept_id"],
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        ))

    except HTTPException:
        raise

    except Exception:
        app.logger.exception("Faculty students loading error")
        abort(500)

    return render_template(
        "faculty_students.html",
        faculty=faculty,
        students=students,
        search=search,
        page_title="Students",
        nav_items=ROLE_MENUS["FACULTY"],
        active_page="students"
    )


# =========================================================
# 15. FACULTY ANNOUNCEMENTS
# =========================================================


# =========================================================
# 15. FACULTY ANNOUNCEMENTS
# =========================================================

@app.route("/faculty/announcements", methods=["GET", "POST"])
@login_required
@role_required("FACULTY")
def faculty_announcements():

    try:
        faculty = get_logged_in_faculty()

        if not faculty:
            abort(404)

        # Always use the logged-in faculty member's department.
        department = fetch_one("""
            SELECT dept_id, dept_name
            FROM departments
            WHERE dept_id = %s
        """, (faculty["dept_id"],))

        if not department:
            abort(404)

        subjects = fetch_all("""
            SELECT subject_id, subject_code, subject_name
            FROM subjects
            WHERE dept_id = %s
            ORDER BY subject_order, subject_name
        """, (faculty["dept_id"],))

        if request.method == "POST":

            title = request.form.get("title", "").strip()
            message = request.form.get("message", "").strip()
            year_value = request.form.get(
                "year_of_study", ""
            ).strip()
            subject_value = request.form.get(
                "subject_id", ""
            ).strip()

            if not title or not message:
                flash("Title and message are required.", "error")

            elif len(title) > 200:
                flash("Title cannot exceed 200 characters.", "error")

            elif len(message) > 10000:
                flash("Message is too long.", "error")

            else:
                year = None
                subject_id = None
                validation_error = None

                if year_value:
                    try:
                        year = int(year_value)

                        if year not in (1, 2, 3, 4):
                            validation_error = "Select a valid study year."

                    except ValueError:
                        validation_error = "Invalid study year."

                if subject_value and not validation_error:
                    try:
                        subject_id = int(subject_value)

                        valid_subject = fetch_one("""
                            SELECT subject_id
                            FROM subjects
                            WHERE subject_id = %s
                              AND dept_id = %s
                        """, (
                            subject_id,
                            faculty["dept_id"]
                        ))

                        if not valid_subject:
                            validation_error = (
                                "Please select a subject from your department."
                            )

                    except ValueError:
                        validation_error = "Invalid subject selected."

                if validation_error:
                    flash(validation_error, "error")

                else:
                    connection = get_db_connection()

                    if connection is None:
                        abort(500)

                    cursor = None

                    try:
                        cursor = connection.cursor()

                        cursor.execute("""
                            INSERT INTO faculty_announcements (
                                faculty_id,
                                dept_id,
                                year_of_study,
                                subject_id,
                                title,
                                message
                            )
                            VALUES (%s, %s, %s, %s, %s, %s)
                        """, (
                            faculty["faculty_id"],
                            faculty["dept_id"],
                            year,
                            subject_id,
                            title,
                            message
                        ))

                        connection.commit()

                        flash(
                            "Announcement published successfully!",
                            "success"
                        )

                    except Exception:
                        connection.rollback()
                        app.logger.exception(
                            "Announcement publishing error"
                        )
                        flash(
                            "Unable to publish announcement.",
                            "error"
                        )

                    finally:
                        if cursor:
                            cursor.close()
                        connection.close()

            return redirect(url_for("faculty_announcements"))

        announcements = fetch_all("""
            SELECT
                a.announcement_id,
                a.title,
                a.message,
                a.year_of_study,
                a.subject_id,
                a.created_at,
                sub.subject_name,
                sub.subject_code
            FROM faculty_announcements a
            LEFT JOIN subjects sub
                ON sub.subject_id = a.subject_id
            WHERE a.faculty_id = %s
            ORDER BY a.created_at DESC
        """, (faculty["faculty_id"],))

        # The template gets a department list containing
        # only the faculty member's own department.
        departments = [department]

    except HTTPException:
        raise

    except Exception:
        app.logger.exception("Faculty announcements loading error")
        abort(500)

    # Inline page avoids depending on an outdated department dropdown.
    html = r"""
    {% extends "base.html" %}

    {% block title %}Announcements | Campus Connect{% endblock %}

    {% block content %}
    <style>
    .announcement-page{
        max-width:1100px;
        margin:auto;
        padding:15px 0 35px;
    }
    .announcement-panel{
        background:white;
        border:1px solid #e2e8f0;
        border-radius:15px;
        padding:22px;
        margin-bottom:22px;
    }
    .announcement-page h1{font-size:27px;margin-bottom:8px}
    .announcement-page h2{font-size:19px;margin:0 0 16px}
    .announcement-muted{color:#64748b}
    .announcement-form{
        display:grid;
        grid-template-columns:repeat(2,minmax(0,1fr));
        gap:16px;
    }
    .announcement-form .full{grid-column:1/-1}
    .announcement-form label{
        display:block;
        font-weight:600;
        margin-bottom:7px;
    }
    .announcement-form input,
    .announcement-form select,
    .announcement-form textarea{
        width:100%;
        padding:11px 12px;
        border:1px solid #cbd5e1;
        border-radius:8px;
        font:inherit;
        box-sizing:border-box;
    }
    .announcement-form textarea{min-height:130px;resize:vertical}
    .announcement-form button{
        background:#2563eb;
        color:white;
        border:0;
        border-radius:8px;
        padding:12px 20px;
        cursor:pointer;
        font-weight:600;
    }
    .announcement-item{
        padding:17px 0;
        border-bottom:1px solid #e2e8f0;
    }
    .announcement-item:last-child{border-bottom:0}
    .announcement-item h3{margin:0 0 8px;font-size:17px}
    .announcement-item p{white-space:pre-wrap;line-height:1.6}
    .announcement-flash{
        padding:11px 14px;
        border-radius:8px;
        margin-bottom:12px;
        background:#eff6ff;
        color:#1d4ed8;
    }
    @media(max-width:650px){
        .announcement-form{grid-template-columns:1fr}
        .announcement-form .full{grid-column:auto}
    }
    </style>

    <section class="announcement-page">
        <h1>Faculty Announcements</h1>
        <p class="announcement-muted">
            Publish announcements for students in your department.
        </p>

        {% with notices = get_flashed_messages(with_categories=true) %}
            {% for category, notice in notices %}
                <div class="announcement-flash">{{ notice }}</div>
            {% endfor %}
        {% endwith %}

        <div class="announcement-panel">
            <h2>Create Announcement</h2>

            <form method="POST" class="announcement-form">

                <div>
                    <label>Department</label>
                    <select disabled>
                        {% for dept in departments %}
                        <option selected>{{ dept.dept_name }}</option>
                        {% endfor %}
                    </select>
                    <small class="announcement-muted">
                        Announcements are restricted to your department.
                    </small>
                </div>

                <div>
                    <label for="year_of_study">Target Study Year</label>
                    <select name="year_of_study" id="year_of_study">
                        <option value="">All years</option>
                        <option value="1">1st Year</option>
                        <option value="2">2nd Year</option>
                        <option value="3">3rd Year</option>
                        <option value="4">4th Year</option>
                    </select>
                </div>

                <div class="full">
                    <label for="subject_id">Subject</label>
                    <select name="subject_id" id="subject_id">
                        <option value="">General announcement</option>
                        {% for subject in subjects %}
                        <option value="{{ subject.subject_id }}">
                            {{ subject.subject_code }} -
                            {{ subject.subject_name }}
                        </option>
                        {% endfor %}
                    </select>
                    {% if not subjects %}
                    <small class="announcement-muted">
                        No subjects are registered for your department.
                        You can still publish a general announcement.
                    </small>
                    {% endif %}
                </div>

                <div class="full">
                    <label for="title">Announcement Title</label>
                    <input
                        type="text"
                        id="title"
                        name="title"
                        maxlength="200"
                        required
                    >
                </div>

                <div class="full">
                    <label for="message">Message</label>
                    <textarea
                        id="message"
                        name="message"
                        maxlength="10000"
                        required
                    ></textarea>
                </div>

                <div class="full">
                    <button type="submit">Publish Announcement</button>
                </div>

            </form>
        </div>

        <div class="announcement-panel">
            <h2>My Published Announcements</h2>

            {% for item in announcements %}
            <article class="announcement-item">
                <h3>{{ item.title }}</h3>

                <p>{{ item.message }}</p>

                <small class="announcement-muted">
                    {{ item.subject_name or "General announcement" }}
                    |
                    {{ ("Year " ~ item.year_of_study)
                       if item.year_of_study else "All years" }}
                    |
                    {{ item.created_at }}
                </small>
            </article>
            {% else %}
            <p class="announcement-muted">
                You have not published any announcements yet.
            </p>
            {% endfor %}
        </div>
    </section>
    {% endblock %}
    """

    return render_template_string(
        html,
        faculty=faculty,
        departments=departments,
        subjects=subjects,
        announcements=announcements,
        page_title="Announcements",
        nav_items=ROLE_MENUS["FACULTY"],
        active_page="announcements"
    )


# =========================================================
# 16. FACULTY ACTIVITIES
# =========================================================

@app.route("/faculty/activities")
@login_required
@role_required("FACULTY")
def faculty_activities():
    try:
        faculty = get_logged_in_faculty()

        if not faculty:
            abort(404)

        activities = fetch_all("""
            SELECT
                event_id,
                event_name,
                description,
                event_date,
                venue
            FROM events
            WHERE is_active = TRUE
            ORDER BY event_date DESC
        """)

    except HTTPException:
        raise

    except Exception:
        app.logger.exception("Faculty activities loading error")
        abort(500)

    return render_template(
        "faculty_activities.html",
        faculty=faculty,
        activities=activities,
        page_title="Campus Activities",
        nav_items=ROLE_MENUS["FACULTY"],
        active_page="activities"
    )


# =========================================================
# 17. STUDENT FACULTY MESSAGES
# =========================================================

# =========================================================
# 17. STUDENT FACULTY MESSAGES
# =========================================================


@app.route("/student/messages")
@login_required
@role_required("STUDENT")
def student_messages():

    connection = None
    cursor = None

    try:
        # Get logged-in student details
        student = get_logged_in_student()

        if not student:
            flash("Student profile not found.", "error")
            return redirect(url_for("dashboard"))

        connection = get_db_connection()

        if connection is None:
            abort(500)

        cursor = connection.cursor(dictionary=True)

        # Fetch announcements for the student's department and year
        cursor.execute("""
            SELECT
                a.announcement_id,
                a.title,
                a.message,
                a.created_at,
                a.year_of_study,
                a.subject_id,

                sub.subject_name,
                sub.subject_code,

                f.faculty_name,
                f.designation,
                f.email AS faculty_email,
                f.mobile_number AS faculty_mobile

            FROM faculty_announcements a

            INNER JOIN faculty f
                ON f.faculty_id = a.faculty_id

            LEFT JOIN subjects sub
                ON sub.subject_id = a.subject_id

            WHERE a.dept_id = %s
              AND (
                    a.year_of_study IS NULL
                    OR a.year_of_study = %s
              )

            ORDER BY a.created_at DESC
        """, (
            student["dept_id"],
            student["year_of_study"]
        ))

        messages = cursor.fetchall()

        # Professional student announcement page
        page = """
        {% extends 'base.html' %}

        {% block content %}

        <style>
            .messages-page {
                max-width: 1050px;
                margin: 30px auto;
                padding: 20px;
            }

            .messages-heading {
                margin-bottom: 28px;
            }

            .messages-heading h2 {
                color: #172554;
                font-size: 27px;
                font-weight: 700;
                margin-bottom: 7px;
            }

            .messages-heading p {
                color: #64748b;
                font-size: 14px;
                margin: 0;
            }

            .message-card {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 14px;
                margin-bottom: 22px;
                overflow: hidden;
                box-shadow: 0 4px 14px rgba(15, 23, 42, .05);
                transition: box-shadow .2s ease;
            }

            .message-card:hover {
                box-shadow: 0 8px 22px rgba(15, 23, 42, .09);
            }

            .message-top {
                padding: 20px 24px;
                background: #f8faff;
                border-bottom: 1px solid #e2e8f0;
            }

            .message-label {
                color: #2563eb;
                font-size: 12px;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: .7px;
            }

            .message-top h3 {
                color: #172554;
                font-size: 20px;
                font-weight: 700;
                margin: 9px 0 0;
            }

            .message-body {
                padding: 22px 24px;
                color: #334155;
                font-size: 15px;
                line-height: 1.8;
                white-space: pre-wrap;
                overflow-wrap: anywhere;
            }

            .message-footer {
                padding: 17px 24px;
                border-top: 1px solid #e2e8f0;
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
                gap: 16px;
            }

            .faculty-info strong {
                display: block;
                color: #172554;
                font-size: 14px;
            }

            .faculty-info span {
                display: block;
                color: #64748b;
                font-size: 12px;
                margin-top: 4px;
            }

            .message-contact {
                color: #64748b;
                font-size: 12px;
                margin-top: 6px;
            }

            .subject-tag {
                display: inline-block;
                background: #eff6ff;
                color: #1d4ed8;
                padding: 7px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
            }

            .message-date {
                color: #64748b;
                font-size: 12px;
                margin-top: 9px;
                text-align: right;
            }

            .empty-messages {
                padding: 45px 20px;
                text-align: center;
                background: #f8fafc;
                border: 1px dashed #cbd5e1;
                border-radius: 14px;
                color: #64748b;
            }

            .empty-messages h3 {
                color: #172554;
                margin-bottom: 8px;
            }

            @media(max-width: 600px) {
                .messages-page {
                    padding: 12px;
                    margin: 15px auto;
                }

                .message-top,
                .message-body,
                .message-footer {
                    padding: 17px;
                }

                .message-date {
                    text-align: left;
                }
            }
        </style>

        <div class="messages-page">

            <div class="messages-heading">
                <h2>Faculty Announcements</h2>
                <p>
                    Important updates and notices from your department faculty.
                </p>
            </div>

            {% if messages %}

                {% for msg in messages %}

                <article class="message-card">

                    <div class="message-top">
                        <div class="message-label">
                            Department Announcement
                        </div>

                        <h3>{{ msg.title }}</h3>
                    </div>

                    <div class="message-body">{{ msg.message }}</div>

                    <div class="message-footer">

                        <div class="faculty-info">

                            <strong>{{ msg.faculty_name }}</strong>

                            <span>
                                {{ msg.designation or 'Faculty Member' }}
                            </span>

                            {% if msg.faculty_email %}
                            <div class="message-contact">
                                Email: {{ msg.faculty_email }}
                            </div>
                            {% endif %}

                            {% if msg.faculty_mobile %}
                            <div class="message-contact">
                                Mobile: {{ msg.faculty_mobile }}
                            </div>
                            {% endif %}

                        </div>

                        <div>

                            {% if msg.subject_name %}

                            <span class="subject-tag">
                                {{ msg.subject_name }}
                                {% if msg.subject_code %}
                                    · {{ msg.subject_code }}
                                {% endif %}
                            </span>

                            {% else %}

                            <span class="subject-tag">
                                General Announcement
                            </span>

                            {% endif %}

                            <div class="message-date">
                                Posted: {{ msg.created_at }}
                            </div>

                        </div>

                    </div>

                </article>

                {% endfor %}

            {% else %}

                <div class="empty-messages">
                    <h3>No announcements yet</h3>
                    <p>
                        Your department faculty have not posted
                        any announcements for your year.
                    </p>
                </div>

            {% endif %}

        </div>

        {% endblock %}
        """

        return render_template_string(
            page,
            student=student,
            messages=messages
        )

    except HTTPException:
        raise

    except Exception as error:
        print("Student messages error:", repr(error))
        flash("Unable to load faculty messages.", "error")
        return redirect(url_for("dashboard"))

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()

# =========================================================
# 18. STUDENT FEEDBACK
# =========================================================

@app.route("/student/feedback", methods=["GET", "POST"])
@login_required
@role_required("STUDENT")
def student_feedback():
    student_id = session.get("student_id")

    if not student_id:
        abort(403)

    error = None
    success = None

    if request.method == "POST":
        feedback_message = request.form.get(
            "feedback", ""
        ).strip()

        if not feedback_message:
            error = "Please enter your feedback."

        elif len(feedback_message) > 3000:
            error = "Feedback cannot exceed 3000 characters."

        else:
            connection = get_db_connection()

            if connection is None:
                error = "Database connection failed."

            else:
                cursor = None

                try:
                    cursor = connection.cursor()

                    cursor.execute("""
                        INSERT INTO feedback
                            (student_id, feedback_message)
                        VALUES (%s, %s)
                    """, (student_id, feedback_message))

                    connection.commit()

                    return redirect(url_for("student_feedback"))

                except Exception:
                    connection.rollback()
                    app.logger.exception("Feedback submission error")
                    error = "Could not submit feedback. Please try again."

                finally:
                    if cursor:
                        cursor.close()

                    connection.close()

    try:
        feedback_history = fetch_all("""
            SELECT
                feedback_id,
                feedback_message,
                created_at
            FROM feedback
            WHERE student_id = %s
            ORDER BY created_at DESC
        """, (student_id,))

    except Exception:
        app.logger.exception("Feedback history loading error")
        abort(500)

    return render_template(
        "student_feedback.html",
        error=error,
        success=success,
        feedback_history=feedback_history,
        page_title="Feedback",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="feedback"
    )


# =========================================================
# 19. SUPER ADMIN - VIEW STUDENTS
# =========================================================

@app.route("/superadmin/students")
@login_required
@role_required("SUPER_ADMIN")
def superadmin_students():
    search = request.args.get("q", "").strip()

    try:
        students = fetch_all("""
            SELECT
                s.student_id,
                s.student_code,
                s.roll_number,
                s.student_name,
                s.mobile_number,
                s.year_of_study,
                s.semester,
                d.dept_name,
                sec.section_name
            FROM students s
            LEFT JOIN departments d
                ON d.dept_id = s.dept_id
            LEFT JOIN sections sec
                ON sec.section_id = s.section_id
            WHERE s.student_name LIKE %s
               OR s.student_code LIKE %s
               OR s.roll_number LIKE %s
               OR d.dept_name LIKE %s
            ORDER BY s.student_name
        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        ))

    except Exception:
        app.logger.exception("Super Admin students loading error")
        abort(500)

    return render_template(
        "superadmin_students.html",
        students=students,
        search=search,
        total=len(students)
    )


# =========================================================
# 20. SUPER ADMIN - VIEW FACULTY
# =========================================================

@app.route("/superadmin/faculty")
@login_required
@role_required("SUPER_ADMIN")
def superadmin_faculty():
    search = request.args.get("q", "").strip()

    try:
        faculty_members = fetch_all("""
            SELECT
                f.faculty_id,
                f.faculty_name,
                f.designation,
                f.mobile_number,
                f.email,
                d.dept_name
            FROM faculty f
            LEFT JOIN departments d
                ON d.dept_id = f.dept_id
            WHERE f.faculty_name LIKE %s
               OR f.email LIKE %s
               OR d.dept_name LIKE %s
            ORDER BY f.faculty_name
        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        ))

    except Exception:
        app.logger.exception("Super Admin faculty loading error")
        abort(500)

    return render_template(
        "superadmin_faculty.html",
        faculty_members=faculty_members,
        search=search,
        total=len(faculty_members)
    )


# =========================================================
# 21. SUPER ADMIN - VIEW DEPARTMENTS
# =========================================================

@app.route("/superadmin/departments")
@login_required
@role_required("SUPER_ADMIN")
def superadmin_departments():
    search = request.args.get("q", "").strip()

    try:
        departments = fetch_all("""
            SELECT dept_id, dept_name
            FROM departments
            WHERE dept_name LIKE %s
            ORDER BY dept_name
        """, (f"%{search}%",))

    except Exception:
        app.logger.exception("Super Admin departments loading error")
        abort(500)

    return render_template(
        "superadmin_departments.html",
        departments=departments,
        search=search,
        total=len(departments)
    )


# =========================================================
# 22. SUPER ADMIN DASHBOARD
# =========================================================

@app.route("/superadmin/dashboard")
@login_required
@role_required("SUPER_ADMIN")
def superadmin_dashboard():
    stats = {
        "students": 0,
        "faculty": 0,
        "departments": 0,
        "sections": 0,
        "users": 0
    }

    connection = get_db_connection()

    if connection is None:
        abort(500)

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        tables = {
            "students": "students",
            "faculty": "faculty",
            "departments": "departments",
            "sections": "sections",
            "users": "user_accounts"
        }

        for key, table in tables.items():
            cursor.execute(
                f"SELECT COUNT(*) AS total FROM `{table}`"
            )

            stats[key] = cursor.fetchone()["total"]

    except Exception:
        app.logger.exception("Super Admin dashboard loading error")
        abort(500)

    finally:
        if cursor:
            cursor.close()

        connection.close()

    return render_template(
        "superadmin_dashboard.html",
        stats=stats,
        page_title="Super Admin Dashboard"
    )


# =========================================================
# 23. OPERATOR DASHBOARD
# =========================================================

@app.route("/operator/dashboard")
@login_required
@role_required("OPERATOR")
def operator_dashboard():
    try:
        stats = {
            "students": fetch_one("""
                SELECT COUNT(*) AS total FROM students
            """)["total"],

            "faculty": fetch_one("""
                SELECT COUNT(*) AS total FROM faculty
            """)["total"],

            "clubs": fetch_one("""
                SELECT COUNT(*) AS total FROM clubs
            """)["total"],

            "departments": fetch_one("""
                SELECT COUNT(*) AS total FROM departments
            """)["total"]
        }

    except Exception:
        app.logger.exception("Operator dashboard loading error")
        abort(500)

    return render_template(
        "operator_dashboard.html",
        stats=stats
    )


# =========================================================
# 24. OPERATOR RECORD MANAGEMENT CONFIGURATION
# =========================================================

OPERATOR_TABLES = {
    "students": {
        "label": "Student",
        "pk": "student_id",
        "title": "Student Records"
    },

    "faculty": {
        "label": "Faculty",
        "pk": "faculty_id",
        "title": "Faculty Records"
    },

    "clubs": {
        "label": "Club",
        "pk": "club_id",
        "title": "Club Records"
    },

    "departments": {
        "label": "Department",
        "pk": "dept_id",
        "title": "Department Records"
    }
}


# =========================================================
# 25. OPERATOR TABLE COLUMN HELPER
# =========================================================

def operator_table_columns(table):
    if table not in OPERATOR_TABLES:
        abort(404)

    connection = get_db_connection()

    if connection is None:
        raise RuntimeError("Database connection failed.")

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(f"SHOW COLUMNS FROM `{table}`")
        return cursor.fetchall()

    finally:
        if cursor:
            cursor.close()

        connection.close()


# =========================================================
# 26. OPERATOR FORM FIELD GENERATOR
# =========================================================

def operator_form_fields(table):
    columns = operator_table_columns(table)
    fields = []

    for column in columns:
        name = column["Field"]
        extra = (column.get("Extra") or "").lower()

        if name == OPERATOR_TABLES[table]["pk"]:
            continue

        if "auto_increment" in extra:
            continue

        if name in ("created_at", "updated_at"):
            continue

        col_type = (column.get("Type") or "varchar").lower()

        if any(
            value in col_type
            for value in ("int", "decimal", "float", "double")
        ):
            input_type = "number"

        elif "date" in col_type and "datetime" not in col_type:
            input_type = "date"

        else:
            input_type = "text"

        fields.append({
            "name": name,
            "label": name.replace("_", " ").title(),
            "required": (
                column.get("Null") == "NO"
                and column.get("Default") is None
                and "auto_increment" not in extra
            ),
            "type": input_type,
            "column_type": col_type,
            "options": []
        })

    connection = get_db_connection()

    if connection is None:
        raise RuntimeError("Database connection failed.")

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        for field in fields:

            if field["name"] == "dept_id":
                cursor.execute("""
                    SELECT
                        dept_id AS id,
                        dept_name AS label
                    FROM departments
                    ORDER BY dept_name
                """)

                field["options"] = cursor.fetchall()
                field["type"] = "select"

            elif field["name"] == "section_id":
                cursor.execute("""
                    SELECT
                        section_id AS id,
                        section_name AS label
                    FROM sections
                    ORDER BY section_name
                """)

                field["options"] = cursor.fetchall()
                field["type"] = "select"

    finally:
        if cursor:
            cursor.close()

        connection.close()

    return fields


# =========================================================
# 27. OPERATOR GET RECORD
# =========================================================

def operator_get_record(table, record_id):
    if table not in OPERATOR_TABLES:
        abort(404)

    pk = OPERATOR_TABLES[table]["pk"]

    return fetch_one(
        f"SELECT * FROM `{table}` WHERE `{pk}` = %s",
        (record_id,)
    )


# =========================================================
# 28. OPERATOR RECORD LIST PAGE
# =========================================================

def operator_records_page(
    table,
    search="",
    message=None,
    error=None
):
    if table not in OPERATOR_TABLES:
        abort(404)

    config = OPERATOR_TABLES[table]
    pk = config["pk"]

    columns = operator_table_columns(table)

    visible_columns = [
        column["Field"]
        for column in columns
        if "blob" not in (column.get("Type") or "").lower()
    ]

    searchable = [
        column["Field"]
        for column in columns
        if any(
            value in (column.get("Type") or "").lower()
            for value in ("char", "text")
        )
    ]

    where = ""
    params = []

    if search and searchable:
        where = " WHERE " + " OR ".join(
            f"CAST(`{name}` AS CHAR) LIKE %s"
            for name in searchable
        )

        params = [f"%{search}%"] * len(searchable)

    records = fetch_all(
        f"""
            SELECT *
            FROM `{table}`
            {where}
            ORDER BY `{pk}` DESC
        """,
        tuple(params)
    )

    return render_template_string(r"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>{{ title }} | Campus Connect</title>

    <style>
    *{box-sizing:border-box}

    body{
        font-family:Arial,sans-serif;
        background:#f3f6fb;
        margin:0;
        padding:24px;
        color:#172033;
    }

    main{
        max-width:1400px;
        margin:auto;
        background:white;
        padding:24px;
        border-radius:14px;
        box-shadow:0 4px 18px #0000000c;
        overflow-x:auto;
    }

    h1{margin:18px 0}

    .top,.actions,.search{
        display:flex;
        gap:9px;
        flex-wrap:wrap;
        align-items:center;
    }

    .top{justify-content:space-between}

    a,button{
        display:inline-block;
        background:#2563eb;
        color:white;
        padding:9px 13px;
        border:0;
        border-radius:7px;
        text-decoration:none;
        cursor:pointer;
        font-size:14px;
    }

    .secondary{background:#475569}
    .danger{background:#dc2626}

    input{
        padding:10px;
        border:1px solid #cbd5e1;
        border-radius:7px;
        min-width:220px;
    }

    table{
        width:100%;
        border-collapse:collapse;
        margin-top:18px;
        white-space:nowrap;
    }

    th,td{
        padding:11px;
        border-bottom:1px solid #e5e7eb;
        text-align:left;
    }

    th{background:#eff6ff}

    td form{display:inline}

    .notice{
        padding:12px;
        margin:12px 0;
        border-radius:7px;
        background:#ecfdf5;
        color:#065f46;
    }

    .error{
        background:#fef2f2;
        color:#991b1b;
    }
    </style>
    </head>

    <body>
    <main>

        <div class="top">
            <a class="secondary"
               href="{{ url_for('operator_dashboard') }}">
                ← Dashboard
            </a>

            <a href="{{ add_url }}">
                + Add {{ singular }}
            </a>
        </div>

        <div class="search" style="margin-top:18px">
            <a href="{{ url_for('operator_students') }}">Students</a>
            <a href="{{ url_for('operator_faculty') }}">Faculty</a>
            <a href="{{ url_for('operator_clubs') }}">Clubs</a>
            <a href="{{ url_for('operator_departments') }}">Departments</a>
        </div>

        <h1>{{ title }}</h1>

        {% if message %}
        <div class="notice">{{ message }}</div>
        {% endif %}

        {% if error %}
        <div class="notice error">{{ error }}</div>
        {% endif %}

        <form class="search" method="get">
            <input
                name="q"
                value="{{ search }}"
                placeholder="Search records"
            >

            <button type="submit">Search</button>

            <a class="secondary" href="{{ list_url }}">Clear</a>
        </form>

        <p>Total records shown: {{ records|length }}</p>

        <table>
            <thead>
                <tr>
                    {% for col in visible_columns %}
                    <th>{{ col.replace('_',' ').title() }}</th>
                    {% endfor %}

                    <th>Actions</th>
                </tr>
            </thead>

            <tbody>
                {% for record in records %}
                <tr>

                    {% for col in visible_columns %}
                    <td>
                        {{ record[col] if record[col] is not none else '' }}
                    </td>
                    {% endfor %}

                    <td>
                        <div class="actions">

                            <a href="{{ url_for(
                                edit_endpoint,
                                record_id=record[pk]
                            ) }}">
                                Edit
                            </a>

                            <form
                                method="post"
                                action="{{ url_for(
                                    delete_endpoint,
                                    record_id=record[pk]
                                ) }}"
                                onsubmit="return confirm(
                                    'Delete this record? This cannot be undone.'
                                );"
                            >
                                <button class="danger" type="submit">
                                    Delete
                                </button>
                            </form>

                        </div>
                    </td>

                </tr>

                {% else %}
                <tr>
                    <td colspan="{{ visible_columns|length + 1 }}">
                        No records found.
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

    </main>
    </body>
    </html>
    """,
        title=config["title"],
        singular=config["label"],
        records=records,
        visible_columns=visible_columns,
        pk=pk,
        search=search,
        add_url=url_for(f"operator_{table}_add"),
        list_url=url_for(f"operator_{table}"),
        edit_endpoint=f"operator_{table}_edit",
        delete_endpoint=f"operator_{table}_delete",
        message=message,
        error=error
    )


# =========================================================
# 29. OPERATOR ADD / EDIT FORM
# =========================================================

def operator_record_form(table, record=None, error=None):
    config = OPERATOR_TABLES[table]
    fields = operator_form_fields(table)

    return render_template_string(r"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>{{ heading }} | Campus Connect</title>

    <style>
    *{box-sizing:border-box}

    body{
        font-family:Arial;
        background:#f3f6fb;
        margin:0;
        padding:24px;
        color:#172033;
    }

    main{
        max-width:850px;
        margin:auto;
        background:white;
        padding:26px;
        border-radius:14px;
    }

    h1{margin-top:18px}

    .grid{
        display:grid;
        grid-template-columns:repeat(auto-fit,minmax(230px,1fr));
        gap:16px;
    }

    label{
        display:block;
        font-weight:600;
        margin-bottom:6px;
    }

    input,select{
        width:100%;
        padding:11px;
        border:1px solid #cbd5e1;
        border-radius:7px;
    }

    button,a{
        display:inline-block;
        padding:10px 15px;
        border:0;
        border-radius:7px;
        background:#2563eb;
        color:white;
        text-decoration:none;
        cursor:pointer;
        margin-top:18px;
    }

    .back{background:#475569}

    .error{
        background:#fef2f2;
        color:#991b1b;
        padding:12px;
        border-radius:7px;
    }
    </style>
    </head>

    <body>
    <main>

        <a class="back" href="{{ list_url }}">
            ← Back to {{ singular }} Records
        </a>

        <h1>{{ heading }}</h1>

        {% if error %}
        <p class="error">{{ error }}</p>
        {% endif %}

        <form method="post">
            <div class="grid">

                {% for field in fields %}
                <div>

                    <label for="{{ field.name }}">
                        {{ field.label }}
                        {% if field.required %} * {% endif %}
                    </label>

                    {% if field.type == 'select' %}

                    <select
                        id="{{ field.name }}"
                        name="{{ field.name }}"
                        {% if field.required %}required{% endif %}
                    >
                        <option value="">
                            Select {{ field.label }}
                        </option>

                        {% for option in field.options %}
                        <option
                            value="{{ option.id }}"
                            {% if record and
                                record[field.name]|string ==
                                option.id|string
                            %}selected{% endif %}
                        >
                            {{ option.label }}
                        </option>
                        {% endfor %}
                    </select>

                    {% else %}

                    <input
                        id="{{ field.name }}"
                        name="{{ field.name }}"
                        type="{{ field.type }}"
                        value="{{ record[field.name] if record and record[field.name] is not none else '' }}"
                        {% if field.required %}required{% endif %}
                        {% if field.type == 'number' and 'int' in field.column_type %}
                        step="1"
                        {% elif field.type == 'number' %}
                        step="any"
                        {% endif %}
                    >

                    {% endif %}

                </div>
                {% endfor %}

            </div>

            <button type="submit">Save {{ singular }}</button>
        </form>

    </main>
    </body>
    </html>
    """,
        heading=("Edit " if record else "Add ") + config["label"],
        fields=fields,
        record=record,
        error=error,
        list_url=url_for(f"operator_{table}"),
        singular=config["label"]
    )


# =========================================================
# 30. OPERATOR SAVE RECORD
# =========================================================

def operator_save_record(table, record_id=None):
    if table not in OPERATOR_TABLES:
        abort(404)

    fields = operator_form_fields(table)
    values = {}

    for field in fields:
        value = request.form.get(
            field["name"], ""
        ).strip()

        if value == "":
            if field["required"]:
                return None, f"{field['label']} is required."

            continue

        values[field["name"]] = value

    if not values:
        return None, "Please enter the record details."

    connection = get_db_connection()

    if connection is None:
        raise RuntimeError("Database connection failed.")

    cursor = None

    try:
        cursor = connection.cursor()

        if record_id is None:
            names = list(values.keys())

            sql = (
                f"INSERT INTO `{table}` "
                f"({', '.join(f'`{name}`' for name in names)}) "
                f"VALUES ({', '.join(['%s'] * len(names))})"
            )

            cursor.execute(
                sql,
                tuple(values[name] for name in names)
            )

        else:
            pk = OPERATOR_TABLES[table]["pk"]

            cursor.execute(
                f"SELECT `{pk}` FROM `{table}` WHERE `{pk}` = %s",
                (record_id,)
            )

            if not cursor.fetchone():
                connection.rollback()
                return None, "Record not found."

            assignments = ", ".join(
                f"`{name}` = %s"
                for name in values
            )

            cursor.execute(
                f"""
                    UPDATE `{table}`
                    SET {assignments}
                    WHERE `{pk}` = %s
                """,
                tuple(values[name] for name in values) + (record_id,)
            )

        connection.commit()
        return True, None

    except Exception as exc:
        connection.rollback()
        app.logger.exception(
            "Operator record save failed for %s",
            table
        )

        return None, str(exc)

    finally:
        if cursor:
            cursor.close()

        connection.close()


# =========================================================
# 31. OPERATOR CRUD ROUTE FACTORY
# =========================================================

def register_operator_routes(table):
    config = OPERATOR_TABLES[table]
    endpoint_prefix = f"operator_{table}"

    def list_view():
        return operator_records_page(
            table,
            request.args.get("q", "").strip(),
            request.args.get("message"),
            request.args.get("error")
        )

    def add_view():
        if request.method == "POST":
            success, error = operator_save_record(table)

            if success:
                return redirect(url_for(
                    endpoint_prefix,
                    message=f"{config['label']} added successfully."
                ))

            return operator_record_form(
                table,
                error=error
            )

        return operator_record_form(table)

    def edit_view(record_id):
        record = operator_get_record(table, record_id)

        if not record:
            abort(404)

        if request.method == "POST":
            success, error = operator_save_record(
                table,
                record_id
            )

            if success:
                return redirect(url_for(
                    endpoint_prefix,
                    message=f"{config['label']} updated successfully."
                ))

            return operator_record_form(
                table,
                record=record,
                error=error
            )

        return operator_record_form(
            table,
            record=record
        )

    def delete_view(record_id):
        connection = None
        cursor = None

        try:
            connection = get_db_connection()

            if connection is None:
                raise RuntimeError("Database connection failed.")

            cursor = connection.cursor()

            pk = config["pk"]

            cursor.execute(
                f"DELETE FROM `{table}` WHERE `{pk}` = %s",
                (record_id,)
            )

            if cursor.rowcount == 0:
                connection.rollback()

                return redirect(url_for(
                    endpoint_prefix,
                    error="Record was not found."
                ))

            connection.commit()

            return redirect(url_for(
                endpoint_prefix,
                message=f"{config['label']} deleted successfully."
            ))

        except Exception:
            if connection:
                connection.rollback()

            app.logger.exception(
                "Operator deletion failed for %s",
                table
            )

            return redirect(url_for(
                endpoint_prefix,
                error=(
                    "Could not delete this record. It may be linked "
                    "to other records in the database."
                )
            ))

        finally:
            if cursor:
                cursor.close()

            if connection:
                connection.close()

    list_view.__name__ = f"{endpoint_prefix}_list_view"
    add_view.__name__ = f"{endpoint_prefix}_add_view"
    edit_view.__name__ = f"{endpoint_prefix}_edit_view"
    delete_view.__name__ = f"{endpoint_prefix}_delete_view"

    app.add_url_rule(
        f"/operator/{table}",
        endpoint=endpoint_prefix,
        view_func=login_required(
            role_required("OPERATOR")(list_view)
        ),
        methods=["GET"]
    )

    app.add_url_rule(
        f"/operator/{table}/add",
        endpoint=f"{endpoint_prefix}_add",
        view_func=login_required(
            role_required("OPERATOR")(add_view)
        ),
        methods=["GET", "POST"]
    )

    app.add_url_rule(
        f"/operator/{table}/edit/<int:record_id>",
        endpoint=f"{endpoint_prefix}_edit",
        view_func=login_required(
            role_required("OPERATOR")(edit_view)
        ),
        methods=["GET", "POST"]
    )

    app.add_url_rule(
        f"/operator/{table}/delete/<int:record_id>",
        endpoint=f"{endpoint_prefix}_delete",
        view_func=login_required(
            role_required("OPERATOR")(delete_view)
        ),
        methods=["POST"]
    )


# Register the operator management routes once.
for operator_table in OPERATOR_TABLES:
    register_operator_routes(operator_table)


# =========================================================
# 32. LOGOUT
# =========================================================

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# =========================================================
# 33. ERROR HANDLERS
# =========================================================

@app.errorhandler(403)
def forbidden(error):
    return render_template(
        "error.html",
        code=403,
        message="You do not have permission to access this page."
    ), 403


@app.errorhandler(404)
def not_found(error):
    return render_template(
        "error.html",
        code=404,
        message="The requested page or record was not found."
    ), 404


@app.errorhandler(500)
def server_error(error):
    app.logger.error("Server error: %s", error)

    return render_template(
        "error.html",
        code=500,
        message=(
            "Something went wrong. Please check the Flask terminal "
            "for the detailed error."
        )
    ), 500


# =========================================================
# 34. RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(
        debug=os.getenv(
            "FLASK_DEBUG", "False"
        ).lower() == "true",
        host="127.0.0.1",
        port=5000
    )