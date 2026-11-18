
from werkzeug.security import generate_password_hash
from db import get_db_connection

PASSWORD = "Campus@123"

conn = get_db_connection()
cursor = conn.cursor(dictionary=True)

try:
    # Generate missing student accounts
    cursor.execute("""
        SELECT s.student_id, s.student_code
        FROM students s
        LEFT JOIN user_accounts u
          ON u.student_id = s.student_id
        WHERE u.user_id IS NULL
    """)
    students = cursor.fetchall()

    for s in students:
        cursor.execute("""
            INSERT INTO user_accounts
            (username, password_hash, role, student_id, faculty_id, is_active)
            VALUES (%s, %s, 'STUDENT', %s, NULL, 1)
        """, (
            s["student_code"],
            generate_password_hash(PASSWORD),
            s["student_id"]
        ))
        conn.commit()

    # Generate missing faculty accounts
    cursor.execute("""
        SELECT f.faculty_id
        FROM faculty f
        LEFT JOIN user_accounts u
          ON u.faculty_id = f.faculty_id
        WHERE u.user_id IS NULL
        ORDER BY f.faculty_id
    """)
    faculty = cursor.fetchall()

    for index, f in enumerate(faculty, start=1):
        username = f"FACULTY{f['faculty_id']:03d}"

        cursor.execute("""
            INSERT INTO user_accounts
            (username, password_hash, role, student_id, faculty_id, is_active)
            VALUES (%s, %s, 'FACULTY', NULL, %s, 1)
        """, (
            username,
            generate_password_hash(PASSWORD),
            f["faculty_id"]
        ))
        conn.commit()

    # Create operator if missing
    cursor.execute("""
        SELECT user_id FROM user_accounts
        WHERE username = 'operator'
    """)

    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO user_accounts
            (username, password_hash, role, student_id, faculty_id, is_active)
            VALUES (%s, %s, 'OPERATOR', NULL, NULL, 1)
        """, ("operator", generate_password_hash(PASSWORD)))
        conn.commit()

    print("ALL MISSING ACCOUNTS GENERATED SUCCESSFULLY")

except Exception as e:
    conn.rollback()
    print("ERROR:", e)

finally:
    cursor.close()
    conn.close()
