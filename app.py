from flask import Flask, request, jsonify, g
import mariadb
import database_logic
import jwt  # For JWT token generation and decoding
import datetime
import functools  # For creating decorators

app = Flask(__name__)

# IMPORTANT: Change this to a long, random, secret string in a production environment!
# Consider loading from an environment variable.
app.config['SECRET_KEY'] = 'your-super-secret-and-long-random-string-here'  # REPLACE THIS!

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
                # Expecting "Bearer <token>"
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({"message": "Malformed token. Use Bearer scheme."}), 400

        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            # Decode the token using the app's SECRET_KEY
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            # Store current user's ID in Flask's g object for this request context
            g.current_user_id = data['user_id']
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
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Username and password are required"}), 400

        username = data['username']
        password = data['password']

        if not username or len(username) < 3:
            return jsonify({"error": "Username must be at least 3 characters long"}), 400
        if not password or len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters long"}), 400

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()

        user_id = database_logic.add_user(cursor, cnx, username, password)
        return jsonify({"message": "User registered successfully", "user_id": user_id}), 201

    except database_logic.UserExistsError as uee:
        return jsonify({"error": str(uee)}), 409
    except ValueError as ve:
        return jsonify({"error": "Invalid data provided", "details": str(ve)}), 400
    except mariadb.Error as dbe:
        return jsonify({"error": "Database operation failed", "details": str(dbe)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error during registration: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
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
            # Generate JWT token
            token_payload = {
                'user_id': user['id'],
                'username': user['username'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
            }
            token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")

            return jsonify({
                "message": "Login successful",
                "token": token,  # Return the token to the client
                "user": {"id": user['id'], "username": user['username']}
            }), 200
        else:
            return jsonify({"error": "Invalid username or password"}), 401

    except mariadb.Error as dbe:
        return jsonify({"error": "Database operation failed", "details": str(dbe)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error during login: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


# --- Crushes Routes (Now protected and user-specific) ---
@app.route('/crushes', methods=['POST'])
@token_required  # Protect this route
def api_create_crush():
    # g.current_user_id is available here from the @token_required decorator
    current_user_id = g.current_user_id
    cnx = None;
    cursor = None
    try:
        if not request.is_json: return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if not data: return jsonify({"error": "Request body cannot be empty"}), 400

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        # Pass current_user_id to the database function
        new_crush_id = database_logic.create_new_crush_for_user(cursor, cnx, data, current_user_id)
        # Fetch the created crush (ensure it belongs to the user, though create should handle it)
        created_crush = database_logic.get_crush_details_for_user(cursor, new_crush_id, current_user_id)
        return jsonify(created_crush), 201
    except ValueError as ve:
        return jsonify({"error": "Invalid data provided", "details": str(ve)}), 400
    except database_logic.UnauthorizedError as ue:  # Catch if somehow creation implies unauthorized state
        return jsonify({"error": str(ue)}), 403
    except mariadb.Error as dbe:
        return jsonify({"error": "Database operation failed", "details": str(dbe)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error in api_create_crush: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes', methods=['GET'])
@token_required  # Protect this route
def api_get_all_crushes():
    current_user_id = g.current_user_id
    cnx = None;
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        # Get crushes only for the logged-in user
        crushes = database_logic.list_all_crushes_for_user(cursor, current_user_id)
        return jsonify(crushes), 200
    except mariadb.Error as dbe:
        return jsonify({"error": "Database error", "details": str(dbe)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error in api_get_all_crushes: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes/<int:crush_id>', methods=['GET'])
@token_required  # Protect this route
def api_get_crush(crush_id):
    current_user_id = g.current_user_id
    cnx = None;
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        # Get crush details only if it belongs to the logged-in user
        crush = database_logic.get_crush_details_for_user(cursor, crush_id, current_user_id)
        return jsonify(crush), 200
    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except mariadb.Error as dbe:
        return jsonify({"error": "Database error", "details": str(dbe)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error in api_get_crush: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes/<int:crush_id>', methods=['PUT'])
@token_required  # Protect this route
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
        # Update only if the crush belongs to the logged-in user
        affected_rows = database_logic.update_existing_crush_for_user(cursor, cnx, crush_id, current_user_id, data)

        # affected_rows from update_existing_crush_for_user already considers ownership.
        # If 0, it could be "not found for this user" or "no actual change".
        # The function now raises NotFoundError or UnauthorizedError if applicable.
        updated_crush = database_logic.get_crush_details_for_user(cursor, crush_id, current_user_id)
        return jsonify(updated_crush), 200

    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except database_logic.UnauthorizedError as ue:
        return jsonify({"error": str(ue)}), 403  # 403 Forbidden
    except ValueError as ve:  # Catches "No valid fields provided for update"
        return jsonify({"error": "Invalid data for update", "details": str(ve)}), 400
    except mariadb.Error as dbe:
        return jsonify({"error": "Database error during update", "details": str(dbe)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error in api_update_crush: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes/<int:crush_id>', methods=['DELETE'])
@token_required  # Protect this route
def api_delete_crush(crush_id):
    current_user_id = g.current_user_id
    cnx = None;
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        # Delete only if the crush belongs to the logged-in user
        database_logic.delete_existing_crush_for_user(cursor, cnx, crush_id, current_user_id)
        return jsonify({"message": f"Crush with ID {crush_id} deleted successfully by user {current_user_id}."}), 200
    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except database_logic.UnauthorizedError as ue:  # Should not be hit if NotFoundError is comprehensive
        return jsonify({"error": str(ue)}), 403
    except mariadb.Error as dbe:
        return jsonify({"error": "Database error during deletion", "details": str(dbe)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error in api_delete_crush: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)