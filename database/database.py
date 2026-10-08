import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE = "database/users.db"


# ============================================================
# CREATE DATABASE
# ============================================================

def create_database():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    # --------------------------------------------------------
    # USERS TABLE
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)

    # --------------------------------------------------------
    # ADD PASSWORD RECOVERY COLUMNS
    # --------------------------------------------------------
    # These ALTER statements allow the feature to work with
    # your existing users.db without deleting existing users.

    cursor.execute("PRAGMA table_info(users)")

    columns = [
        column[1]
        for column in cursor.fetchall()
    ]

    if "security_question" not in columns:

        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN security_question TEXT
        """)

    if "security_answer" not in columns:

        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN security_answer TEXT
        """)

    # --------------------------------------------------------
    # FILES TABLE
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            encrypted_filename TEXT NOT NULL,
            encryption_key TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    """)

    # --------------------------------------------------------
    # FILE SHARES TABLE
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            owner_id INTEGER NOT NULL,
            shared_with_id INTEGER NOT NULL,
            permission TEXT NOT NULL DEFAULT 'read',
            shared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES files(id),
            FOREIGN KEY (owner_id) REFERENCES users(id),
            FOREIGN KEY (shared_with_id) REFERENCES users(id)
        )
    """)

    # --------------------------------------------------------
    # ACCESS LOGS TABLE
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            file_id INTEGER,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            ip_address TEXT,
            access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (file_id) REFERENCES files(id)
        )
    """)

    connection.commit()
    connection.close()


# ============================================================
# REGISTER USER
# ============================================================

def register_user(
    username,
    password,
    security_question,
    security_answer
):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    # Hash password
    hashed_password = generate_password_hash(
        password
    )

    # Hash security answer
    hashed_security_answer = generate_password_hash(
        security_answer.lower().strip()
    )

    try:

        cursor.execute(
            """
            INSERT INTO users
            (
                username,
                password,
                security_question,
                security_answer
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                username,
                hashed_password,
                security_question,
                hashed_security_answer
            )
        )

        connection.commit()

        result = True

    except sqlite3.IntegrityError:

        result = False

    connection.close()

    return result


# ============================================================
# GET USER
# ============================================================

def get_user(username):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    )

    user = cursor.fetchone()

    connection.close()

    return user


# ============================================================
# GET SECURITY QUESTION
# ============================================================

def get_security_question(username):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT security_question
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    result = cursor.fetchone()

    connection.close()

    if result:
        return result[0]

    return None


# ============================================================
# VERIFY SECURITY ANSWER
# ============================================================

def verify_security_answer(
    username,
    security_answer
):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT security_answer
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    result = cursor.fetchone()

    connection.close()

    if not result or not result[0]:

        return False

    stored_hash = result[0]

    return check_password_hash(
        stored_hash,
        security_answer.lower().strip()
    )


# ============================================================
# UPDATE PASSWORD
# ============================================================

def update_password(
    username,
    new_password
):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    hashed_password = generate_password_hash(
        new_password
    )

    cursor.execute(
        """
        UPDATE users
        SET password = ?
        WHERE username = ?
        """,
        (
            hashed_password,
            username
        )
    )

    updated = cursor.rowcount > 0

    connection.commit()

    connection.close()

    return updated


# ============================================================
# SAVE FILE
# ============================================================

def save_file(
    filename,
    encrypted_filename,
    encryption_key,
    owner_id
):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO files
        (
            filename,
            encrypted_filename,
            encryption_key,
            owner_id
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            filename,
            encrypted_filename,
            encryption_key,
            owner_id
        )
    )

    connection.commit()
    connection.close()


# ============================================================
# GET USER FILES
# ============================================================

def get_user_files(owner_id):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            filename,
            encrypted_filename,
            upload_time
        FROM files
        WHERE owner_id = ?
        ORDER BY upload_time DESC
        """,
        (owner_id,)
    )

    files = cursor.fetchall()

    connection.close()

    return files


# ============================================================
# GET FILE
# ============================================================

def get_file(file_id, owner_id):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            filename,
            encrypted_filename,
            encryption_key
        FROM files
        WHERE id = ?
        AND owner_id = ?
        """,
        (
            file_id,
            owner_id
        )
    )

    file = cursor.fetchone()

    connection.close()

    return file


# ============================================================
# DELETE FILE
# ============================================================

def delete_file(file_id, owner_id):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    # Remove sharing permissions
    cursor.execute(
        """
        DELETE FROM file_shares
        WHERE file_id = ?
        AND owner_id = ?
        """,
        (
            file_id,
            owner_id
        )
    )

    # Delete the file record
    cursor.execute(
        """
        DELETE FROM files
        WHERE id = ?
        AND owner_id = ?
        """,
        (
            file_id,
            owner_id
        )
    )

    deleted = cursor.rowcount > 0

    connection.commit()
    connection.close()

    return deleted


# ============================================================
# DELETE USER ACCOUNT
# ============================================================

def delete_user_account(user_id):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    try:

        # ----------------------------------------------------
        # Get all files owned by this user
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT id, encrypted_filename
            FROM files
            WHERE owner_id = ?
            """,
            (user_id,)
        )

        owned_files = cursor.fetchall()

        file_ids = [
            file[0]
            for file in owned_files
        ]

        # ----------------------------------------------------
        # Remove access logs belonging to the user
        # ----------------------------------------------------

        cursor.execute(
            """
            DELETE FROM access_logs
            WHERE user_id = ?
            """,
            (user_id,)
        )

        # ----------------------------------------------------
        # Remove access logs connected to files
        # owned by the deleted user
        # ----------------------------------------------------

        if file_ids:

            placeholders = ",".join(
                ["?"] * len(file_ids)
            )

            cursor.execute(
                f"""
                DELETE FROM access_logs
                WHERE file_id IN ({placeholders})
                """,
                file_ids
            )

        # ----------------------------------------------------
        # Remove all sharing permissions involving user
        # ----------------------------------------------------

        cursor.execute(
            """
            DELETE FROM file_shares
            WHERE owner_id = ?
            OR shared_with_id = ?
            """,
            (
                user_id,
                user_id
            )
        )

        # ----------------------------------------------------
        # Remove files owned by user
        # ----------------------------------------------------

        cursor.execute(
            """
            DELETE FROM files
            WHERE owner_id = ?
            """,
            (user_id,)
        )

        # ----------------------------------------------------
        # Finally remove the user account
        # ----------------------------------------------------

        cursor.execute(
            """
            DELETE FROM users
            WHERE id = ?
            """,
            (user_id,)
        )

        deleted = cursor.rowcount > 0

        connection.commit()

        return deleted, owned_files

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


# ============================================================
# SAVE SHARE
# ============================================================

def save_share(
    file_id,
    owner_id,
    shared_with_id,
    permission="read",
    duration_hours=24
):

    from datetime import datetime, timedelta

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    expires_at = datetime.now() + timedelta(
        hours=duration_hours
    )

    cursor.execute(
        """
        INSERT INTO file_shares
        (
            file_id,
            owner_id,
            shared_with_id,
            permission,
            expires_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            file_id,
            owner_id,
            shared_with_id,
            permission,
            expires_at
        )
    )

    connection.commit()
    connection.close()


# ============================================================
# GET OTHER USERS
# ============================================================

def get_other_users(current_user_id):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, username
        FROM users
        WHERE id != ?
        ORDER BY username
        """,
        (current_user_id,)
    )

    users = cursor.fetchall()

    connection.close()

    return users


# ============================================================
# GET SHARED FILES
# ============================================================

def get_shared_files(user_id):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            files.id,
            files.filename,
            files.encrypted_filename,
            files.owner_id,
            users.username,
            file_shares.permission,
            file_shares.shared_at
        FROM file_shares
        JOIN files
            ON file_shares.file_id = files.id
        JOIN users
            ON file_shares.owner_id = users.id
        WHERE file_shares.shared_with_id = ?
        ORDER BY file_shares.shared_at DESC
        """,
        (user_id,)
    )

    shared_files = cursor.fetchall()

    connection.close()

    return shared_files


# ============================================================
# GET SHARED FILE
# ============================================================

def get_shared_file(file_id, user_id):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            files.id,
            files.filename,
            files.encrypted_filename,
            files.encryption_key,
            file_shares.permission,
            file_shares.expires_at
        FROM file_shares
        JOIN files
            ON file_shares.file_id = files.id
        WHERE file_shares.file_id = ?
        AND file_shares.shared_with_id = ?
        """,
        (
            file_id,
            user_id
        )
    )

    file = cursor.fetchone()

    connection.close()

    return file


# ============================================================
# REVOKE SHARE
# ============================================================

def revoke_share(
    file_id,
    owner_id,
    shared_with_id
):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM file_shares
        WHERE file_id = ?
        AND owner_id = ?
        AND shared_with_id = ?
        """,
        (
            file_id,
            owner_id,
            shared_with_id
        )
    )

    connection.commit()

    connection.close()


# ============================================================
# GET MY SHARED FILES
# ============================================================

def get_my_shared_files(owner_id):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            file_shares.file_id,
            files.filename,
            users.username,
            file_shares.shared_with_id,
            file_shares.permission,
            file_shares.shared_at,
            file_shares.expires_at
        FROM file_shares
        JOIN files
            ON file_shares.file_id = files.id
        JOIN users
            ON file_shares.shared_with_id = users.id
        WHERE file_shares.owner_id = ?
        ORDER BY file_shares.shared_at DESC
        """,
        (owner_id,)
    )

    shared_files = cursor.fetchall()

    connection.close()

    return shared_files


# ============================================================
# LOG ACCESS
# ============================================================

def log_access(
    user_id,
    file_id,
    action,
    status,
    risk_score=0,
    ip_address=None
):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO access_logs
        (
            user_id,
            file_id,
            action,
            status,
            risk_score,
            ip_address
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            file_id,
            action,
            status,
            risk_score,
            ip_address
        )
    )

    connection.commit()
    connection.close()


# ============================================================
# GET ACCESS LOGS
# ============================================================

def get_access_logs(user_id):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            access_logs.id,
            users.username,
            files.filename,
            access_logs.action,
            access_logs.status,
            access_logs.risk_score,
            access_logs.ip_address,
            access_logs.access_time
        FROM access_logs
        JOIN users
            ON access_logs.user_id = users.id
        LEFT JOIN files
            ON access_logs.file_id = files.id
        WHERE access_logs.user_id = ?
        ORDER BY access_logs.access_time DESC
        """,
        (user_id,)
    )

    logs = cursor.fetchall()

    connection.close()

    return logs


# ============================================================
# CALCULATE RISK SCORE
# ============================================================

def calculate_risk_score(user_id, file_id):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    # Count denied attempts for this user
    # during the last 10 minutes

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM access_logs
        WHERE user_id = ?
        AND status = 'DENIED'
        AND access_time >= datetime('now', '-10 minutes')
        """,
        (user_id,)
    )

    failed_attempts = cursor.fetchone()[0]

    # Count recent shared-download attempts
    # during the last 5 minutes

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM access_logs
        WHERE user_id = ?
        AND action = 'SHARED_DOWNLOAD'
        AND access_time >= datetime('now', '-5 minutes')
        """,
        (user_id,)
    )

    recent_attempts = cursor.fetchone()[0]

    connection.close()

    # Start with zero risk

    risk_score = 0

    # Each denied attempt adds 20 points

    risk_score += failed_attempts * 20

    # Repeated access attempts increase risk

    if recent_attempts > 5:

        risk_score += 20

    elif recent_attempts > 3:

        risk_score += 10

    # Maximum risk = 100

    risk_score = min(
        risk_score,
        100
    )

    return risk_score