from flask import Flask, request, jsonify, g
import mariadb
import database_logic
import jwt
import datetime
import functools  # For creating decorators
import secrets  # For flask secret_key, though better from env var

app = Flask(__name__)

# IMPORTANT: Change this to a long, random, secret string in a production environment!
# Load from an environment variable for better security.
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generates a new random key each time app starts
# For consistent JWTs across restarts, set a fixed value from env.

# --- One-time setup: Create tables when app starts (for development convenience) ---
try:
    cnx_init = database_logic.get_db_connection()
    cursor_init = cnx_init.cursor()
    database_logic.create_tables_if_not_exist(cursor_init)
    cursor_init.close()
    cnx_init.close()
except mariadb.Error as db_init_err:
    print(f"CRITICAL: Could not initialize database tables: {db_init_err}")


# --- JWT Token Required Decorator ---
def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({"message": "Malformed token. Use Bearer scheme."}), 400

        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            g.current_user_id = data['user_id']  # Store user_id in g for the request context
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token is invalid!"}), 401

        return f(*args, **kwargs)

    return decorated


# --- User Authentication Routes ---
@app.route('/register', methods=['POST'])
def api_register_user():
    cnx = None;
    cursor = None
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        required_fields = ['username', 'email', 'password']
        if not data or not all(field in data for field in required_fields):
            return jsonify({"error": "Username, email, and password are required"}), 400

        username = data['username']
        email = data['email']
        password = data['password']

        # Basic validation (can be more complex)
        if not username or len(username) < 3:
            return jsonify({"error": "Username must be at least 3 characters long"}), 400
        if not email or '@' not in email:  # Very basic email check
            return jsonify({"error": "Invalid email format"}), 400
        if not password or len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters long"}), 400

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()

        user_id = database_logic.add_user(cursor, cnx, username, email, password)
        return jsonify({"message": "User registered successfully", "user_id": user_id}), 201

    except database_logic.UserExistsError as uee:
        return jsonify({"error": str(uee)}), 409
    except ValueError as ve:
        return jsonify({"error": "Invalid data provided", "details": str(ve)}), 400
    except mariadb.Error as dbe:
        app.logger.error(f"Database error during registration: {dbe}")
        return jsonify({"error": "Database operation failed"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error during registration: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/login', methods=['POST'])
def api_login_user():
    cnx = None;
    cursor = None
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Username and password are required"}), 400

        username = data['username']
        password = data['password']

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        user = database_logic.get_user_by_username(cursor, username)

        if user and database_logic.verify_password(password, user['password_hash']):
            token_payload = {
                'user_id': user['id'],
                'username': user['username'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)  # Token expires in 24 hours
            }
            token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")

            return jsonify({
                "message": "Login successful",
                "token": token,
                "user": {"id": user['id'], "username": user['username'], "email": user.get('email')}
            }), 200
        else:
            return jsonify({"error": "Invalid username or password"}), 401

    except mariadb.Error as dbe:
        app.logger.error(f"Database error during login: {dbe}")
        return jsonify({"error": "Database operation failed"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error during login: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


# --- User Profile Routes ---
@app.route('/profile', methods=['GET'])
@token_required
def api_get_profile():
    current_user_id = g.current_user_id
    cnx = None;
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        user_profile = database_logic.get_user_by_id(cursor, current_user_id)
        if not user_profile:
            return jsonify({"error": "User profile not found"}), 404  # Should not happen if token is valid
        return jsonify(user_profile), 200
    except mariadb.Error as dbe:
        app.logger.error(f"Database error fetching profile: {dbe}")
        return jsonify({"error": "Could not fetch profile"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error fetching profile: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/profile', methods=['PUT'])
@token_required
def api_update_profile():
    current_user_id = g.current_user_id
    cnx = None;
    cursor = None
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()

        new_email = data.get('email')
        new_password = data.get('password')

        if not new_email and not new_password:
            return jsonify({"error": "No fields provided for update (email or password)"}), 400

        # Validate new email if provided
        if new_email and ('@' not in new_email or len(new_email) < 5):  # Basic validation
            return jsonify({"error": "Invalid email format provided"}), 400

        # Validate new password if provided
        if new_password and len(new_password) < 6:
            return jsonify({"error": "New password must be at least 6 characters long"}), 400

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()

        success = database_logic.update_user_profile(cursor, cnx, current_user_id,
                                                     email=new_email, new_password=new_password)
        if success:
            updated_profile = database_logic.get_user_by_id(cursor, current_user_id)
            return jsonify({"message": "Profile updated successfully", "profile": updated_profile}), 200
        else:
            # This else might not be reached if errors are raised in update_user_profile
            return jsonify({"error": "Profile update failed or no changes made"}), 400

    except database_logic.UserExistsError as uee:  # For email conflict
        return jsonify({"error": str(uee)}), 409
    except ValueError as ve:  # For "No fields provided"
        return jsonify({"error": str(ve)}), 400
    except mariadb.Error as dbe:
        app.logger.error(f"Database error updating profile: {dbe}")
        return jsonify({"error": "Database update failed"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error updating profile: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


# --- Password Reset Routes ---
@app.route('/forgot-password', methods=['POST'])
def api_forgot_password():
    cnx = None;
    cursor = None
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({"error": "Email is required"}), 400

        email = data['email']
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        user = database_logic.get_user_by_email(cursor, email)

        if user:
            reset_token = database_logic.set_password_reset_token_for_user(cursor, cnx, user['id'])
            # !!! IMPORTANT: SEND EMAIL TO USER HERE !!!
            # This part requires an email sending setup (e.g., Flask-Mail and an SMTP server).
            # The email should contain a link like:
            # reset_url = f"https://yourfrontenddomain.com/reset-password?token={reset_token}"
            # For now, we'll just return the token in the response for testing.
            # In production, NEVER return the token directly in the API response here.
            app.logger.info(f"Password reset token for {email} (user_id {user['id']}): {reset_token}")
            app.logger.info(f"Simulated email sent to {email} with reset token.")
            # mail_service.send_password_reset_email(user['email'], reset_token) # Placeholder
            return jsonify({
                "message": "If an account with that email exists, a password reset link has been (simulated) sent.",
                "_development_reset_token": reset_token  # For testing ONLY, remove in production
            }), 200
        else:
            # Still return a generic message to prevent email enumeration
            app.logger.info(f"Password reset requested for non-existent email: {email}")
            return jsonify({
                               "message": "If an account with that email exists, a password reset link has been (simulated) sent."}), 200

    except mariadb.Error as dbe:
        app.logger.error(f"Database error on forgot password: {dbe}")
        return jsonify({"error": "Database operation failed"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error on forgot password: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/reset-password', methods=['POST'])
def api_reset_password():
    cnx = None;
    cursor = None
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        required_fields = ['token', 'new_password']
        if not data or not all(field in data for field in required_fields):
            return jsonify({"error": "Token and new_password are required"}), 400

        token = data['token']
        new_password = data['new_password']

        if not new_password or len(new_password) < 6:
            return jsonify({"error": "New password must be at least 6 characters long"}), 400

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        user = database_logic.get_user_by_reset_token(cursor, token)

        if user:
            success = database_logic.reset_user_password(cursor, cnx, user['id'], new_password)
            if success:
                return jsonify({"message": "Password has been reset successfully."}), 200
            else:
                return jsonify({"error": "Password reset failed."}), 500  # Should not happen if token was valid
        else:
            return jsonify({"error": "Invalid or expired reset token."}), 400

    except mariadb.Error as dbe:
        app.logger.error(f"Database error on reset password: {dbe}")
        return jsonify({"error": "Database operation failed"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error on reset password: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


# --- Crushes Routes (Now protected and user-specific) ---
@app.route('/crushes', methods=['POST'])
@token_required
def api_create_crush():
    current_user_id = g.current_user_id
    cnx = None;
    cursor = None
    try:
        if not request.is_json: return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if not data: return jsonify({"error": "Request body cannot be empty"}), 400

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        new_crush_id = database_logic.create_new_crush_for_user(cursor, cnx, data, current_user_id)
        created_crush = database_logic.get_crush_details_for_user(cursor, new_crush_id, current_user_id)
        return jsonify(created_crush), 201
    except ValueError as ve:
        return jsonify({"error": "Invalid data provided", "details": str(ve)}), 400
    except database_logic.UnauthorizedError as ue:
        return jsonify({"error": str(ue)}), 403
    except mariadb.Error as dbe:
        app.logger.error(f"Database error in api_create_crush: {dbe}")
        return jsonify({"error": "Database operation failed"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error in api_create_crush: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes', methods=['GET'])
@token_required
def api_get_all_crushes():
    current_user_id = g.current_user_id
    cnx = None;
    cursor = None
    try:
        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 10, type=int)
        if page < 1: page = 1
        if limit < 1: limit = 1
        if limit > 100: limit = 100  # Max limit

        # Sorting parameters
        sort_by = request.args.get('sort_by', 'id')  # Default sort by id
        sort_order = request.args.get('sort_order', 'asc').lower()
        if sort_order not in ['asc', 'desc']:
            sort_order = 'asc'

        # Filtering parameters
        filters = {}
        if 'gender' in request.args:
            filters['gender'] = request.args.get('gender')
        if 'name_contains' in request.args:
            filters['name_contains'] = request.args.get('name_contains')
        # Add more filters here as needed from request.args

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        crushes, total_count = database_logic.list_all_crushes_for_user(
            cursor, current_user_id, page, limit, sort_by, sort_order, filters
        )
        return jsonify({
            "crushes": crushes,
            "page": page,
            "limit": limit,
            "total_count": total_count,
            "total_pages": (total_count + limit - 1) // limit  # Calculate total pages
        }), 200
    except mariadb.Error as dbe:
        app.logger.error(f"Database error in api_get_all_crushes: {dbe}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error in api_get_all_crushes: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes/<int:crush_id>', methods=['GET'])
@token_required
def api_get_crush(crush_id):
    current_user_id = g.current_user_id
    cnx = None;
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        crush = database_logic.get_crush_details_for_user(cursor, crush_id, current_user_id)
        return jsonify(crush), 200
    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except mariadb.Error as dbe:
        app.logger.error(f"Database error in api_get_crush: {dbe}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error in api_get_crush: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes/<int:crush_id>', methods=['PUT'])
@token_required
def api_update_crush(crush_id):
    current_user_id = g.current_user_id
    cnx = None;
    cursor = None
    try:
        if not request.is_json: return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if not data: return jsonify({"error": "No update data provided"}), 400

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        database_logic.update_existing_crush_for_user(cursor, cnx, crush_id, current_user_id, data)
        updated_crush = database_logic.get_crush_details_for_user(cursor, crush_id, current_user_id)
        return jsonify(updated_crush), 200

    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except database_logic.UnauthorizedError as ue:
        return jsonify({"error": str(ue)}), 403
    except ValueError as ve:
        return jsonify({"error": "Invalid data for update", "details": str(ve)}), 400
    except mariadb.Error as dbe:
        app.logger.error(f"Database error in api_update_crush: {dbe}")
        return jsonify({"error": "Database error during update"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error in api_update_crush: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes/<int:crush_id>', methods=['DELETE'])
@token_required
def api_delete_crush(crush_id):
    current_user_id = g.current_user_id
    cnx = None;
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        database_logic.delete_existing_crush_for_user(cursor, cnx, crush_id, current_user_id)
        return jsonify({"message": f"Crush with ID {crush_id} deleted successfully by user {current_user_id}."}), 200
    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except mariadb.Error as dbe:
        app.logger.error(f"Database error in api_delete_crush: {dbe}")
        return jsonify({"error": "Database error during deletion"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error in api_delete_crush: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)