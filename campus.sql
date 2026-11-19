
CREATE DATABASE campus_connect;

USE campus_connect;

SELECT DATABASE();

CREATE TABLE departments (
    dept_id INT AUTO_INCREMENT PRIMARY KEY,
    dept_name VARCHAR(100) NOT NULL UNIQUE,
    dept_code VARCHAR(20) UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO departments (dept_id, dept_name, dept_code)
VALUES
(1, 'Computer Science and Engineering', 'CSE'),
(2, 'CSE Artificial Intelligence and Machine Learning', 'AIML'),
(3, 'CSE Data Science', 'DS'),
(4, 'CSE Cyber Security', 'CYBER'),
(5, 'CSE Internet of Things', 'IOT'),
(6, 'CSE Artificial Intelligence', 'AI');

SELECT * FROM departments;

CREATE TABLE sections (
    section_id INT AUTO_INCREMENT PRIMARY KEY,
    dept_id INT NOT NULL,
    section_name CHAR(1) NOT NULL,
    section_order INT NOT NULL,
    academic_year INT DEFAULT 2,
    student_capacity INT DEFAULT 60,

    FOREIGN KEY (dept_id)
        REFERENCES departments(dept_id),

    UNIQUE (dept_id, section_name, academic_year)
);

CREATE TABLE students (
    student_id INT AUTO_INCREMENT PRIMARY KEY,
    student_code VARCHAR(30) UNIQUE NOT NULL,
    roll_number VARCHAR(30) UNIQUE NOT NULL,
    student_name VARCHAR(100) NOT NULL,
    dept_id INT NOT NULL,
    section_id INT NOT NULL,
    year_of_study INT DEFAULT 2,
    semester INT DEFAULT 3,
    mobile_number VARCHAR(15),

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (dept_id)
        REFERENCES departments(dept_id),

    FOREIGN KEY (section_id)
        REFERENCES sections(section_id)
);

CREATE TABLE faculty (
    faculty_id INT AUTO_INCREMENT PRIMARY KEY,
    faculty_name VARCHAR(100) NOT NULL,
    dept_id INT NOT NULL,
    designation VARCHAR(100),
    email VARCHAR(100) UNIQUE,
    mobile_number VARCHAR(15),
    linkedin VARCHAR(255),
    degrees VARCHAR(255),

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (dept_id)
        REFERENCES departments(dept_id)
);

CREATE TABLE subjects (
    subject_id INT AUTO_INCREMENT PRIMARY KEY,
    dept_id INT NOT NULL,
    subject_code VARCHAR(30) UNIQUE NOT NULL,
    subject_name VARCHAR(150) NOT NULL,
    subject_order INT,

    FOREIGN KEY (dept_id)
        REFERENCES departments(dept_id)
);

CREATE TABLE user_accounts (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,

    role ENUM(
        'STUDENT',
        'FACULTY',
        'HOD',
        'OPERATOR',
        'ADMIN'
    ) NOT NULL,

    student_id INT UNIQUE NULL,
    faculty_id INT UNIQUE NULL,

    is_active TINYINT(1) DEFAULT 1,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (student_id)
        REFERENCES students(student_id),

    FOREIGN KEY (faculty_id)
        REFERENCES faculty(faculty_id)
);

CREATE TABLE faculty_subject_sections (
    assignment_id INT AUTO_INCREMENT PRIMARY KEY,
    faculty_id INT NOT NULL,
    subject_id INT NOT NULL,
    section_id INT NOT NULL,
    semester INT NOT NULL,

    FOREIGN KEY (faculty_id)
        REFERENCES faculty(faculty_id),

    FOREIGN KEY (subject_id)
        REFERENCES subjects(subject_id),

    FOREIGN KEY (section_id)
        REFERENCES sections(section_id)
);

CREATE TABLE attendance (
    attendance_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    subject_id INT NOT NULL,

    total_classes INT NOT NULL DEFAULT 0,
    attended_classes INT NOT NULL DEFAULT 0,

    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (student_id)
        REFERENCES students(student_id),

    FOREIGN KEY (subject_id)
        REFERENCES subjects(subject_id),

    UNIQUE (student_id, subject_id),

    CHECK (attended_classes <= total_classes)
);

CREATE TABLE events (
    event_id INT AUTO_INCREMENT PRIMARY KEY,
    event_name VARCHAR(150) NOT NULL,
    description TEXT,
    event_date DATE,
    venue VARCHAR(150),
    created_by INT NULL,
    is_active TINYINT(1) DEFAULT 1,

    FOREIGN KEY (created_by)
        REFERENCES user_accounts(user_id)
);

CREATE TABLE event_registrations (
    registration_id INT AUTO_INCREMENT PRIMARY KEY,
    event_id INT NOT NULL,
    student_id INT NOT NULL,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (event_id)
        REFERENCES events(event_id),

    FOREIGN KEY (student_id)
        REFERENCES students(student_id),

    UNIQUE (event_id, student_id)
);

CREATE TABLE clubs (
    club_id INT AUTO_INCREMENT PRIMARY KEY,
    club_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    coordinator VARCHAR(100),
    is_active TINYINT(1) DEFAULT 1
);

CREATE TABLE club_memberships (
    membership_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    club_id INT NOT NULL,
    membership_type VARCHAR(30) DEFAULT 'MEMBER',

    FOREIGN KEY (student_id)
        REFERENCES students(student_id),

    FOREIGN KEY (club_id)
        REFERENCES clubs(club_id),

    UNIQUE (student_id, club_id)
);

CREATE TABLE faculty_announcements (
    announcement_id INT AUTO_INCREMENT PRIMARY KEY,
    faculty_id INT NOT NULL,
    dept_id INT NOT NULL,
    year_of_study INT,
    subject_id INT,
    title VARCHAR(200) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (faculty_id)
        REFERENCES faculty(faculty_id),

    FOREIGN KEY (dept_id)
        REFERENCES departments(dept_id),

    FOREIGN KEY (subject_id)
        REFERENCES subjects(subject_id)
);

CREATE TABLE feedback (
    feedback_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    feedback_message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (student_id)
        REFERENCES students(student_id)
);
