from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file
)

from database.database import (
    create_database,
    register_user,
    get_user,
    save_file,
    get_user_files,
    get_file,
    delete_file,
    delete_user_account,
    get_other_users,
    save_share,
    get_shared_files,
    get_shared_file,
    revoke_share,
    get_my_shared_files,
    log_access,
    get_access_logs,
    calculate_risk_score,
    get_security_question,
    verify_security_answer,
    update_password
)

from werkzeug.security import check_password_hash

from encryption import (
    generate_key,
    encrypt_file,
    decrypt_file
)

import base64
import os

from datetime import datetime


app = Flask(__name__)


# ============================================================
# SECRET KEY
# ============================================================

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "secure-cloud-data-sharing-development-key"
)


# ============================================================
# CREATE DATABASE
# ============================================================

create_database()


# ============================================================
# LOGIN
# ============================================================

@app.route("/", methods=["GET", "POST"])
def login():

    message = ""

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        user = get_user(username)

        if user and check_password_hash(
            user[2],
            password
        ):

            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[3]

            return redirect(
                url_for("dashboard")
            )

        else:

            message = "Invalid username or password."

    return render_template(
        "login.html",
        message=message
    )


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    message = ""

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        security_question = request.form[
            "security_question"
        ]

        security_answer = request.form[
            "security_answer"
        ]

        # ----------------------------------------------------
        # Basic validation
        # ----------------------------------------------------

        if not username.strip():

            message = "Username is required."

            return render_template(
                "register.html",
                message=message
            )

        if not password:

            message = "Password is required."

            return render_template(
                "register.html",
                message=message
            )

        if not security_question.strip():

            message = "Please select a security question."

            return render_template(
                "register.html",
                message=message
            )

        if not security_answer.strip():

            message = "Security answer is required."

            return render_template(
                "register.html",
                message=message
            )

        # ----------------------------------------------------
        # Register user
        # ----------------------------------------------------

        success = register_user(
            username.strip(),
            password,
            security_question,
            security_answer
        )

        if success:

            return redirect(
                url_for("login")
            )

        else:

            message = "Username already exists."

    return render_template(
        "register.html",
        message=message
    )


# ============================================================
# FORGOT PASSWORD
# ============================================================

@app.route(
    "/forgot-password",
    methods=["GET", "POST"]
)
def forgot_password():

    message = ""

    if request.method == "POST":

        username = request.form[
            "username"
        ].strip()

        if not username:

            message = "Please enter your username."

            return render_template(
                "forgot_password.html",
                message=message
            )

        security_question = get_security_question(
            username
        )

        if security_question is None:

            message = (
                "Username not found or password recovery "
                "has not been configured for this account."
            )

            return render_template(
                "forgot_password.html",
                message=message
            )

        # ----------------------------------------------------
        # Store username temporarily in session
        # ----------------------------------------------------

        session["reset_username"] = username

        return render_template(
            "reset_password.html",
            username=username,
            security_question=security_question,
            message=""
        )

    return render_template(
        "forgot_password.html",
        message=message
    )


# ============================================================
# RESET PASSWORD
# ============================================================

@app.route(
    "/reset-password",
    methods=["POST"]
)
def reset_password():

    username = session.get(
        "reset_username"
    )

    if not username:

        flash(
            "Password reset session expired. Please try again.",
            "error"
        )

        return redirect(
            url_for("forgot_password")
        )

    security_answer = request.form[
        "security_answer"
    ]

    new_password = request.form[
        "new_password"
    ]

    confirm_password = request.form[
        "confirm_password"
    ]

    # --------------------------------------------------------
    # Check security answer
    # --------------------------------------------------------

    answer_correct = verify_security_answer(
        username,
        security_answer
    )

    if not answer_correct:

        security_question = get_security_question(
            username
        )

        return render_template(
            "reset_password.html",
            username=username,
            security_question=security_question,
            message="Incorrect security answer."
        )

    # --------------------------------------------------------
    # Validate new password
    # --------------------------------------------------------

    if not new_password:

        security_question = get_security_question(
            username
        )

        return render_template(
            "reset_password.html",
            username=username,
            security_question=security_question,
            message="Please enter a new password."
        )

    if len(new_password) < 6:

        security_question = get_security_question(
            username
        )

        return render_template(
            "reset_password.html",
            username=username,
            security_question=security_question,
            message="Password must contain at least 6 characters."
        )

    # --------------------------------------------------------
    # Confirm password
    # --------------------------------------------------------

    if new_password != confirm_password:

        security_question = get_security_question(
            username
        )

        return render_template(
            "reset_password.html",
            username=username,
            security_question=security_question,
            message="Passwords do not match."
        )

    # --------------------------------------------------------
    # Update password
    # --------------------------------------------------------

    updated = update_password(
        username,
        new_password
    )

    if updated:

        # Remove temporary reset information
        session.pop(
            "reset_username",
            None
        )

        flash(
            "Password reset successfully. You can now log in.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    security_question = get_security_question(
        username
    )

    return render_template(
        "reset_password.html",
        username=username,
        security_question=security_question,
        message="Unable to update password. Please try again."
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    files = get_user_files(
        session["user_id"]
    )

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
        files=files
    )


# ============================================================
# UPLOAD FILE
# ============================================================

@app.route("/upload", methods=["GET", "POST"])
def upload():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    if request.method == "POST":

        file = request.files.get("file")

        if file and file.filename != "":

            original_path = (
                f"uploads/{file.filename}"
            )

            file.save(
                original_path
            )

            # Generate AES-256 encryption key

            key = generate_key()

            # Encrypted file path

            encrypted_path = (
                f"uploads/{file.filename}.encrypted"
            )

            # Encrypt file

            encrypt_file(
                original_path,
                encrypted_path,
                key
            )

            # Encode encryption key

            encoded_key = base64.b64encode(
                key
            ).decode("utf-8")

            # Save file information

            save_file(
                file.filename,
                f"{file.filename}.encrypted",
                encoded_key,
                session["user_id"]
            )

            # Delete original unencrypted file

            os.remove(
                original_path
            )

            flash(
                "File uploaded and encrypted successfully!",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Please select a file.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "upload.html"
    )


# ============================================================
# SHARE FILE
# ============================================================

@app.route("/share", methods=["GET", "POST"])
def share_file():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    files = get_user_files(
        session["user_id"]
    )

    users = get_other_users(
        session["user_id"]
    )

    if request.method == "POST":

        file_id = request.form["file_id"]

        shared_with_id = request.form[
            "shared_with_id"
        ]

        permission = request.form[
            "permission"
        ]

        duration = int(
            request.form["duration"]
        )

        selected_file = get_file(
            file_id,
            session["user_id"]
        )

        if not selected_file:

            flash(
                "Invalid file or access denied.",
                "error"
            )

            return redirect(
                url_for("dashboard")
            )

        save_share(
            file_id,
            session["user_id"],
            shared_with_id,
            permission,
            duration
        )

        flash(
            "File shared successfully!",
            "success"
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "share.html",
        files=files,
        users=users
    )


# ============================================================
# OWNER FILE DOWNLOAD
# ============================================================

@app.route("/download/<int:file_id>")
def download_file(file_id):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    file = get_file(
        file_id,
        session["user_id"]
    )

    if not file:

        log_access(
            session["user_id"],
            file_id,
            "DOWNLOAD",
            "DENIED",
            0,
            request.remote_addr
        )

        flash(
            "File not found or access denied.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    risk_score = calculate_risk_score(
        session["user_id"],
        file_id
    )

    # HIGH RISK

    if risk_score > 60:

        log_access(
            session["user_id"],
            file_id,
            "DOWNLOAD",
            "DENIED",
            risk_score,
            request.remote_addr
        )

        flash(
            "Access denied: high risk detected.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    # MEDIUM RISK

    elif risk_score > 30:

        return redirect(
            url_for(
                "verify_access",
                file_id=file_id
            )
        )

    filename = file[1]

    encrypted_filename = file[2]

    encoded_key = file[3]

    key = base64.b64decode(
        encoded_key
    )

    encrypted_path = os.path.join(
        "uploads",
        encrypted_filename
    )

    decrypted_path = os.path.join(
        "uploads",
        "download_" + filename
    )

    try:

        if not os.path.exists(
            encrypted_path
        ):

            log_access(
                session["user_id"],
                file_id,
                "DOWNLOAD",
                "DENIED",
                0,
                request.remote_addr
            )

            flash(
                "Encrypted file not found.",
                "error"
            )

            return redirect(
                url_for("dashboard")
            )

        decrypt_file(
            encrypted_path,
            decrypted_path,
            key
        )

        log_access(
            session["user_id"],
            file_id,
            "DOWNLOAD",
            "ALLOWED",
            risk_score,
            request.remote_addr
        )

        response = send_file(
            decrypted_path,
            as_attachment=True,
            download_name=filename
        )

        @response.call_on_close
        def remove_decrypted_file():

            if os.path.exists(
                decrypted_path
            ):

                os.remove(
                    decrypted_path
                )

        return response

    except Exception as e:

        print(
            "Download Error:",
            e
        )

        log_access(
            session["user_id"],
            file_id,
            "DOWNLOAD",
            "DENIED",
            0,
            request.remote_addr
        )

        flash(
            "Unable to decrypt the file.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )


# ============================================================
# DELETE OWNER FILE
# ============================================================

@app.route(
    "/delete-file/<int:file_id>",
    methods=["POST"]
)
def delete_file_route(file_id):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    file = get_file(
        file_id,
        user_id
    )

    if not file:

        flash(
            "File not found or you are not the owner.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    encrypted_filename = file[2]

    encrypted_path = os.path.join(
        "uploads",
        encrypted_filename
    )

    deleted = delete_file(
        file_id,
        user_id
    )

    if deleted:

        if os.path.exists(
            encrypted_path
        ):

            try:

                os.remove(
                    encrypted_path
                )

            except OSError as e:

                print(
                    "Encrypted file deletion error:",
                    e
                )

        flash(
            "File deleted successfully!",
            "success"
        )

    else:

        flash(
            "Unable to delete the file.",
            "error"
        )

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# SHARED FILES
# ============================================================

@app.route("/shared-files")
def shared_files():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    files = get_shared_files(
        session["user_id"]
    )

    return render_template(
        "shared_files.html",
        shared_files=files
    )


# ============================================================
# MY SHARED FILES
# ============================================================

@app.route("/my-shared-files")
def my_shared_files():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    files = get_my_shared_files(
        session["user_id"]
    )

    return render_template(
        "my_shared_files.html",
        shared_files=files
    )


# ============================================================
# SHARED FILE DOWNLOAD
# ============================================================

@app.route("/shared-download/<int:file_id>")
def shared_download(file_id):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    file = get_shared_file(
        file_id,
        user_id
    )

    if not file:

        log_access(
            user_id,
            file_id,
            "SHARED_DOWNLOAD",
            "DENIED",
            0,
            request.remote_addr
        )

        flash(
            "Access denied or file not found.",
            "error"
        )

        return redirect(
            url_for("shared_files")
        )

    filename = file[1]

    encrypted_filename = file[2]

    encoded_key = file[3]

    permission = file[4]

    expires_at = file[5]

    # Check permission

    if permission != "read":

        log_access(
            user_id,
            file_id,
            "SHARED_DOWNLOAD",
            "DENIED",
            0,
            request.remote_addr
        )

        flash(
            "You do not have permission to download this file.",
            "error"
        )

        return redirect(
            url_for("shared_files")
        )

    # Check expiry

    if expires_at:

        expiry_time = datetime.fromisoformat(
            expires_at
        )

        if datetime.now() > expiry_time:

            log_access(
                user_id,
                file_id,
                "SHARED_DOWNLOAD",
                "EXPIRED",
                0,
                request.remote_addr
            )

            flash(
                "Access denied: file sharing has expired.",
                "error"
            )

            return redirect(
                url_for("shared_files")
            )

    # Calculate adaptive risk

    risk_score = calculate_risk_score(
        user_id,
        file_id
    )

    # HIGH RISK

    if risk_score > 60:

        log_access(
            user_id,
            file_id,
            "SHARED_DOWNLOAD",
            "DENIED",
            risk_score,
            request.remote_addr
        )

        flash(
            "Access denied: high risk detected.",
            "error"
        )

        return redirect(
            url_for("shared_files")
        )

    # MEDIUM RISK

    if risk_score > 30:

        if session.get(
            "verified_file_id"
        ) != file_id:

            return redirect(
                url_for(
                    "verify_access",
                    file_id=file_id
                )
            )

        session.pop(
            "verified_file_id",
            None
        )

    key = base64.b64decode(
        encoded_key
    )

    encrypted_path = os.path.join(
        "uploads",
        encrypted_filename
    )

    decrypted_path = os.path.join(
        "uploads",
        "shared_download_" + filename
    )

    try:

        if not os.path.exists(
            encrypted_path
        ):

            log_access(
                user_id,
                file_id,
                "SHARED_DOWNLOAD",
                "DENIED",
                risk_score,
                request.remote_addr
            )

            flash(
                "Encrypted file not found.",
                "error"
            )

            return redirect(
                url_for("shared_files")
            )

        decrypt_file(
            encrypted_path,
            decrypted_path,
            key
        )

        log_access(
            user_id,
            file_id,
            "SHARED_DOWNLOAD",
            "ALLOWED",
            risk_score,
            request.remote_addr
        )

        response = send_file(
            decrypted_path,
            as_attachment=True,
            download_name=filename
        )

        @response.call_on_close
        def remove_decrypted_file():

            if os.path.exists(
                decrypted_path
            ):

                os.remove(
                    decrypted_path
                )

        return response

    except Exception as e:

        print(
            "Shared Download Error:",
            e
        )

        log_access(
            user_id,
            file_id,
            "SHARED_DOWNLOAD",
            "DENIED",
            risk_score,
            request.remote_addr
        )

        flash(
            "Unable to decrypt the shared file.",
            "error"
        )

        return redirect(
            url_for("shared_files")
        )


# ============================================================
# REVOKE FILE ACCESS
# ============================================================

@app.route(
    "/revoke-share/<int:file_id>/<int:shared_with_id>"
)
def revoke_file_share(
    file_id,
    shared_with_id
):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    revoke_share(
        file_id,
        session["user_id"],
        shared_with_id
    )

    flash(
        "File access revoked successfully!",
        "success"
    )

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# ACCESS LOGS
# ============================================================

@app.route("/access-logs")
def access_logs():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    logs = get_access_logs(
        session["user_id"]
    )

    return render_template(
        "access_logs.html",
        logs=logs
    )


# ============================================================
# VERIFY ACCESS
# ============================================================

@app.route("/verify-access/<int:file_id>")
def verify_access(file_id):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    file = get_shared_file(
        file_id,
        session["user_id"]
    )

    if not file:

        flash(
            "Access denied or file not found.",
            "error"
        )

        return redirect(
            url_for("shared_files")
        )

    filename = file[1]

    session["verified_file_id"] = file_id

    return render_template(
        "verify_access.html",
        file_id=file_id,
        filename=filename,
        download_url=url_for(
            "shared_download",
            file_id=file_id
        )
    )


# ============================================================
# DELETE MY ACCOUNT
# ============================================================

@app.route(
    "/delete-account",
    methods=["POST"]
)
def delete_account():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    try:

        deleted, owned_files = delete_user_account(
            user_id
        )

        if not deleted:

            flash(
                "Unable to delete your account.",
                "error"
            )

            return redirect(
                url_for("dashboard")
            )

        # ----------------------------------------------------
        # Delete encrypted files from physical storage
        # ----------------------------------------------------

        for file in owned_files:

            encrypted_filename = file[1]

            encrypted_path = os.path.join(
                "uploads",
                encrypted_filename
            )

            if os.path.exists(
                encrypted_path
            ):

                try:

                    os.remove(
                        encrypted_path
                    )

                except OSError as e:

                    print(
                        "Account file deletion error:",
                        e
                    )

        # ----------------------------------------------------
        # Clear session
        # ----------------------------------------------------

        session.clear()

        flash(
            "Your account and associated data have been permanently deleted.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    except Exception as e:

        print(
            "Account deletion error:",
            e
        )

        flash(
            "An error occurred while deleting your account.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=False
    )