from flask import Flask, request, jsonify
import mariadb
import database_logic

app = Flask(__name__)

# --- One-time setup: Create tables when app starts (for development convenience) ---
# In a production environment, you'd typically manage schema with migration tools.
try:
    cnx_init = database_logic.get_db_connection()
    cursor_init = cnx_init.cursor()
    database_logic.create_tables_if_not_exist(cursor_init)
    cursor_init.close()
    cnx_init.close()
except mariadb.Error as db_init_err:
    print(f"CRITICAL: Could not initialize database tables: {db_init_err}")
    # Depending on policy, you might want to exit or log this severely.


# --- User Authentication Routes ---
@app.route('/register', methods=['POST'])
def api_register_user():
    # API endpoint to register a new user.
    cnx = None
    cursor = None
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Username and password are required"}), 400

        username = data['username']
        password = data['password']

        # Basic validation (you can add more complex rules)
        if not username or len(username) < 3:
            return jsonify({"error": "Username must be at least 3 characters long"}), 400
        if not password or len(password) < 6:  # Example: minimum password length
            return jsonify({"error": "Password must be at least 6 characters long"}), 400

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()

        user_id = database_logic.add_user(cursor, cnx, username, password)
        return jsonify({"message": "User registered successfully", "user_id": user_id}), 201

    except database_logic.UserExistsError as uee:
        return jsonify({"error": str(uee)}), 409  # 409 Conflict
    except ValueError as ve:
        return jsonify({"error": "Invalid data provided", "details": str(ve)}), 400
    except mariadb.Error as dbe:
        return jsonify({"error": "Database operation failed", "details": str(dbe)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error during registration: {e}")  # Log unexpected errors
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/login', methods=['POST'])
def api_login_user():
    # API endpoint for user login.
    cnx = None
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
            # Login successful.
            # For a real application, you would now generate a session token (e.g., JWT)
            # and return it to the client.
            return jsonify({
                "message": "Login successful",
                "user": {"id": user['id'], "username": user['username']}  # Don't return password_hash
            }), 200
        else:
            return jsonify({"error": "Invalid username or password"}), 401  # 401 Unauthorized

    except mariadb.Error as dbe:
        return jsonify({"error": "Database operation failed", "details": str(dbe)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error during login: {e}")  # Log unexpected errors
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


# --- Crushes Routes (from previous version, unchanged for this step) ---
@app.route('/crushes', methods=['POST'])
def api_create_crush():
    # NOTE: This endpoint is currently NOT protected by authentication.
    cnx = None;
    cursor = None
    try:
        if not request.is_json: return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if not data: return jsonify({"error": "Request body cannot be empty"}), 400

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        new_crush_id = database_logic.create_new_crush(cursor, cnx, data)
        created_crush = database_logic.get_crush_details(cursor, new_crush_id)
        return jsonify(created_crush), 201
    except ValueError as ve:
        return jsonify({"error": "Invalid data provided", "details": str(ve)}), 400
    except mariadb.Error as dbe:
        return jsonify({"error": "Database operation failed", "details": str(dbe)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes', methods=['GET'])
def api_get_all_crushes():
    # NOTE: This endpoint is currently NOT protected by authentication.
    cnx = None;
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        crushes = database_logic.list_all_crushes(cursor)
        return jsonify(crushes), 200
    except mariadb.Error as dbe:
        return jsonify({"error": "Database error", "details": str(dbe)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes/<int:crush_id>', methods=['GET'])
def api_get_crush(crush_id):
    # NOTE: This endpoint is currently NOT protected by authentication.
    cnx = None;
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        crush = database_logic.get_crush_details(cursor, crush_id)
        return jsonify(crush), 200
    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except mariadb.Error as dbe:
        return jsonify({"error": "Database error", "details": str(dbe)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes/<int:crush_id>', methods=['PUT'])
def api_update_crush(crush_id):
    # NOTE: This endpoint is currently NOT protected by authentication.
    cnx = None;
    cursor = None
    try:
        if not request.is_json: return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if not data: return jsonify({"error": "No update data provided"}), 400

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        affected_rows = database_logic.update_existing_crush(cursor, cnx, crush_id, data)

        if affected_rows > 0:
            updated_crush = database_logic.get_crush_details(cursor, crush_id)
            return jsonify(updated_crush), 200
        else:
            current_crush_details = database_logic.get_crush_details(cursor, crush_id)
            return jsonify({
                "message": "Crush found but no changes were made.",
                "crush": current_crush_details
            }), 200
    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except ValueError as ve:
        return jsonify({"error": "Invalid data for update", "details": str(ve)}), 400
    except mariadb.Error as dbe:
        return jsonify({"error": "Database error during update", "details": str(dbe)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes/<int:crush_id>', methods=['DELETE'])
def api_delete_crush(crush_id):
    # NOTE: This endpoint is currently NOT protected by authentication.
    cnx = None;
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        affected_rows = database_logic.delete_existing_crush(cursor, cnx, crush_id)
        if affected_rows > 0:
            return jsonify({"message": f"Crush with ID {crush_id} deleted successfully."}), 200
        else:  # Should be caught by NotFoundError in delete_existing_crush if it truly did not delete
            return jsonify({"error": f"Crush with ID {crush_id} processed but not deleted as expected."}), 500
    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except mariadb.Error as dbe:
        return jsonify({"error": "Database error during deletion", "details": str(dbe)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


if __name__ == '__main__':
    # Ensure to set debug=False for production environments
    app.run(debug=True, host='0.0.0.0', port=5000)