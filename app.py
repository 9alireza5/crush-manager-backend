from flask import Flask, request, jsonify, g
import mariadb
import database_logic
import jwt
import datetime
import functools
import secrets
import os
import google.generativeai as genai

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))

GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if not GEMINI_API_KEY:
    print("WARNING: GEMINI_API_KEY environment variable not set. AI features will be disabled.")
else:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        print("Gemini API configured successfully.")
    except Exception as e:
        print(f"Error configuring Gemini API: {e}")
        GEMINI_API_KEY = None

try:
    cnx_init = database_logic.get_db_connection()
    cursor_init = cnx_init.cursor()
    database_logic.create_tables_if_not_exist(cursor_init)
    cursor_init.close()
    cnx_init.close()
except mariadb.Error as db_init_err:
    print(f"CRITICAL: Could not initialize database tables: {db_init_err}")


def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({"error": "Malformed token. Use Bearer scheme."}), 400
        if not token:
            return jsonify({"error": "Token is missing!"}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            g.current_user_id = data['user_id']
            g.current_username = data.get('username', 'User')
            g.current_user_role = data.get('role', 'user')
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token is invalid!"}), 401
        return f(*args, **kwargs)

    return decorated


# RBAC Feature: New decorator to check for specific roles.
def role_required(required_roles):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if g.current_user_role not in required_roles:
                return jsonify({"error": "Forbidden: You do not have permission to access this resource."}), 403
            return f(*args, **kwargs)

        return token_required(decorated_function)

    return decorator


@app.route('/register', methods=['POST'])
def api_register_user():
    cnx = None;
    cursor = None
    try:
        if not request.is_json: return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        required_fields = ['username', 'email', 'password']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Username, email, and password are required"}), 400
        username = data['username']
        email = data['email']
        password = data['password']
        if not username or len(username) < 3:
            return jsonify({"error": "Username must be at least 3 characters long"}), 400
        if not email or '@' not in email or '.' not in email.split('@')[-1]:
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
        app.logger.error(f"Unexpected error during registration: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/login', methods=['POST'])
def api_login_user():
    cnx = None;
    cursor = None
    try:
        if not request.is_json: return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if 'username' not in data or 'password' not in data:
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
                'role': user['role'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }
            token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")
            return jsonify({
                "message": "Login successful",
                "token": token,
                "user": {"id": user['id'], "username": user['username'], "email": user.get('email'),
                         "role": user.get('role')}
            }), 200
        else:
            return jsonify({"error": "Invalid username or password"}), 401
    except mariadb.Error as dbe:
        app.logger.error(f"Database error during login: {dbe}")
        return jsonify({"error": "Database operation failed"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error during login: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/profile', methods=['GET'])
@token_required
def api_get_profile():
    cnx = None;
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        user_profile = database_logic.get_user_by_id(cursor, g.current_user_id)
        if not user_profile: return jsonify({"error": "User profile not found"}), 404
        return jsonify(user_profile), 200
    except mariadb.Error as dbe:
        app.logger.error(f"Database error fetching profile: {dbe}")
        return jsonify({"error": "Could not fetch profile"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error fetching profile: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/profile', methods=['PUT'])
@token_required
def api_update_profile():
    cnx = None;
    cursor = None
    try:
        if not request.is_json: return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        new_email = data.get('email')
        new_password = data.get('password')
        if not new_email and not new_password:
            return jsonify({"error": "No fields provided for update (email or password)"}), 400
        if new_email and ('@' not in new_email or '.' not in new_email.split('@')[-1] or len(new_email) < 5):
            return jsonify({"error": "Invalid email format provided"}), 400
        if new_password and len(new_password) < 6:
            return jsonify({"error": "New password must be at least 6 characters long"}), 400
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        success = database_logic.update_user_profile(cursor, cnx, g.current_user_id, email=new_email,
                                                     new_password=new_password)
        if success:
            updated_profile = database_logic.get_user_by_id(cursor, g.current_user_id)
            return jsonify({"message": "Profile updated successfully", "profile": updated_profile}), 200
        else:
            return jsonify({"error": "Profile update failed or no changes made"}), 400
    except database_logic.UserExistsError as uee:
        return jsonify({"error": str(uee)}), 409
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except mariadb.Error as dbe:
        app.logger.error(f"Database error updating profile: {dbe}")
        return jsonify({"error": "Database update failed"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error updating profile: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/forgot-password', methods=['POST'])
def api_forgot_password():
    cnx = None;
    cursor = None
    try:
        if not request.is_json: return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if not data or 'email' not in data: return jsonify({"error": "Email is required"}), 400
        email_address = data['email']
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        user = database_logic.get_user_by_email(cursor, email_address)
        if user:
            reset_token = database_logic.set_password_reset_token_for_user(cursor, cnx, user['id'])
            app.logger.info(f"Password reset token for {email_address} (user_id {user['id']}): {reset_token}")
            app.logger.info(f"Simulated: Email would be sent to {email_address} with reset token.")
            return jsonify({
                "message": "If an account with that email exists, a password reset link has been (simulated as) sent.",
                "_development_reset_token": reset_token
            }), 200
        else:
            app.logger.info(f"Password reset requested for non-existent email: {email_address}")
            return jsonify({
                               "message": "If an account with that email exists, a password reset link has been (simulated as) sent."}), 200
    except mariadb.Error as dbe:
        app.logger.error(f"Database error on forgot password: {dbe}")
        return jsonify({"error": "Database operation failed"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error on forgot password: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/reset-password', methods=['POST'])
def api_reset_password():
    cnx = None;
    cursor = None
    try:
        if not request.is_json: return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        required_fields = ['token', 'new_password']
        if not all(field in data for field in required_fields):
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
                return jsonify({"error": "Password reset failed."}), 500
        else:
            return jsonify({"error": "Invalid or expired reset token."}), 400
    except mariadb.Error as dbe:
        app.logger.error(f"Database error on reset password: {dbe}")
        return jsonify({"error": "Database operation failed"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error on reset password: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/ai/get-advice', methods=['POST'])
@token_required
def api_get_ai_advice():
    if not GEMINI_API_KEY:
        return jsonify({"error": "AI service is not configured."}), 503
    cnx = None;
    cursor = None
    try:
        if not request.is_json: return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        user_query = data.get('query')
        if not user_query:
            return jsonify({"error": "A 'query' field is required to ask for advice."}), 400
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()

        user_crush_data_summary = database_logic.get_crushes_summary_for_ai(cursor, g.current_user_id)
        chat_history = database_logic.get_chat_history(cursor, g.current_user_id)
        db_user = database_logic.get_user_by_id(cursor, g.current_user_id)
        ai_summary = db_user.get('ai_summary', 'No summary yet.')

        # AI Feature: Construct a detailed prompt for Gemini.
        # This prompt includes a system instruction, user data, AI's prior summary, and recent chat history.
        system_instruction = f"""
        You are "Crush Advisor AI," a specialized assistant for user '{g.current_username}'.
        Your role is to provide empathetic and constructive advice regarding their personal relationship dynamics.
        Your previous impression of this user is: "{ai_summary}"
        Use this impression, the chat history, and the user's current data summary to inform your response.

        **Strict Operational Guidelines:**
        1.  **Topic Adherence:** Confine your conversation strictly to relationship advice. If the user goes off-topic, politely decline and steer them back.
        2.  **Data Scope:** Base your advice ONLY on the provided user data, your prior impression, and the chat history. Do not invent details or use external knowledge.
        3.  **Privacy:** Do NOT repeat large sections of the raw data back to the user.
        4.  **Tone & Style:** Be supportive, respectful, empathetic, and concise.
        """

        full_prompt = f"""
        {system_instruction}

        **User's Crush Data Summary:**
        {user_crush_data_summary}

        **User's Current Query:**
        "{user_query}"
        """

        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        generation_config = genai.types.GenerationConfig(max_output_tokens=400, temperature=0.75)
        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        ]
        chat = model.start_chat(history=chat_history)
        response = chat.send_message(full_prompt, generation_config=generation_config, safety_settings=safety_settings)
        ai_advice = response.text

        database_logic.add_chat_history(cursor, cnx, g.current_user_id, user_query, ai_advice)

        # AI Feature: Second, asynchronous call to update the user summary.
        # In a production app, this should be moved to a background task (e.g., Celery) to not slow down the user's response time.
        summary_prompt = f"""
        Based on the user's existing summary, their latest query, and your latest response, provide an updated, concise summary of the user's personality, goals, and recurring themes.
        PREVIOUS SUMMARY: "{ai_summary}"
        LATEST CONVERSATION:
        User: "{user_query}"
        You: "{ai_advice}"
        UPDATED SUMMARY:
        """
        summary_response = model.generate_content(summary_prompt,
                                                  generation_config=genai.types.GenerationConfig(max_output_tokens=150))
        new_summary = summary_response.text
        database_logic.update_ai_summary_for_user(cursor, cnx, g.current_user_id, new_summary)

        return jsonify({"advice": ai_advice}), 200
    except Exception as e:
        app.logger.error(f"Error in AI advisor: {e}", exc_info=True)
        error_message_str = str(e).lower()
        if "api key not valid" in error_message_str:
            return jsonify({"error": "AI service authentication failed."}), 500
        if "quota" in error_message_str or "rate limit" in error_message_str or "resource has been exhausted" in error_message_str:
            return jsonify({"error": "AI service is temporarily unavailable due to high demand or usage limits."}), 429
        return jsonify({"error": "AI advisor could not process the request."}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


# RBAC Feature: Admin and Advisor routes for viewing data.
@app.route('/admin/users', methods=['GET'])
@role_required(required_roles=['admin'])
def api_admin_get_all_users():
    cnx = None;
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        users = database_logic.list_all_users(cursor)
        return jsonify(users), 200
    except mariadb.Error as dbe:
        app.logger.error(f"Database error in api_admin_get_all_users: {dbe}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error in api_admin_get_all_users: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/admin/users/<int:user_id>/role', methods=['PUT'])
@role_required(required_roles=['admin'])
def api_admin_update_user_role(user_id):
    cnx = None;
    cursor = None
    try:
        if not request.is_json: return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        new_role = data.get('role')
        if not new_role: return jsonify({"error": "'role' field is required"}), 400

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        database_logic.update_user_role(cursor, cnx, user_id, new_role)
        return jsonify({"message": f"User {user_id}'s role updated to '{new_role}'"}), 200
    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except mariadb.Error as dbe:
        app.logger.error(f"Database error in api_admin_update_user_role: {dbe}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error in api_admin_update_user_role: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes', methods=['POST'])
@token_required
def api_create_crush():
    cnx = None;
    cursor = None
    try:
        if not request.is_json: return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if not data: return jsonify({"error": "Request body cannot be empty"}), 400
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        new_crush_id = database_logic.create_new_crush_for_user(cursor, cnx, data, g.current_user_id)
        created_crush = database_logic.get_crush_details_for_user(cursor, new_crush_id, g.current_user_id)
        return jsonify(created_crush), 201
    except ValueError as ve:
        return jsonify({"error": "Invalid data provided", "details": str(ve)}), 400
    except Exception as e:
        app.logger.error(f"Unexpected error in api_create_crush: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes', methods=['GET'])
@token_required
def api_get_crushes():
    cnx = None;
    cursor = None
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 10, type=int)
        sort_by = request.args.get('sort_by', 'id')
        sort_order = request.args.get('sort_order', 'asc').lower()
        if sort_order not in ['asc', 'desc']: sort_order = 'asc'

        filters = {
            'gender': request.args.get('gender'),
            'name_contains': request.args.get('name_contains'),
            'min_age': request.args.get('min_age', type=int),
            'max_age': request.args.get('max_age', type=int),
            'acquaintance_date_after': request.args.get('acquaintance_date_after'),
            'acquaintance_date_before': request.args.get('acquaintance_date_before'),
            'interaction_level': request.args.get('interaction_level', type=int),
            'feelings_level': request.args.get('feelings_level', type=int)
        }
        filters = {k: v for k, v in filters.items() if v is not None}

        user_id_to_query = g.current_user_id
        # RBAC Feature: Admins and Advisors can see all crushes or filter by a specific user_id.
        if g.current_user_role in ['admin', 'advisor']:
            query_user_id = request.args.get('user_id', type=int)
            if query_user_id:
                user_id_to_query = query_user_id
            else:  # Admin/advisor getting all crushes
                user_id_to_query = None

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        crushes, total_count = database_logic.list_crushes(
            cursor, user_id_to_query, page, limit, sort_by, sort_order, filters
        )
        return jsonify({
            "crushes": crushes,
            "page": page,
            "limit": limit,
            "total_count": total_count,
            "total_pages": (total_count + limit - 1) // limit if limit > 0 else 0
        }), 200
    except Exception as e:
        app.logger.error(f"Unexpected error in api_get_crushes: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes/<int:crush_id>', methods=['GET'])
@token_required
def api_get_crush(crush_id):
    cnx = None;
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        crush = database_logic.get_crush_details(cursor, crush_id)
        # RBAC Feature: Check ownership for regular users.
        if g.current_user_role == 'user' and crush.get('user_id') != g.current_user_id:
            return jsonify({"error": "Forbidden: You do not own this resource."}), 403
        return jsonify(crush), 200
    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except Exception as e:
        app.logger.error(f"Unexpected error in api_get_crush: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes/<int:crush_id>', methods=['PUT'])
@token_required
def api_update_crush(crush_id):
    cnx = None;
    cursor = None
    try:
        if not request.is_json: return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if not data: return jsonify({"error": "No update data provided"}), 400
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        user_id_to_use = g.current_user_id
        # RBAC Feature: Admin can update any crush, but the ownership (user_id) doesn't change.
        # We need the original owner's ID for the update function if the user is an admin.
        if g.current_user_role == 'admin':
            crush_to_update = database_logic.get_crush_details(cursor, crush_id)
            user_id_to_use = crush_to_update['user_id']
        database_logic.update_existing_crush_for_user(cursor, cnx, crush_id, user_id_to_use, data)
        updated_crush = database_logic.get_crush_details(cursor, crush_id)
        return jsonify(updated_crush), 200
    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except database_logic.UnauthorizedError as ue:
        return jsonify({"error": str(ue)}), 403
    except ValueError as ve:
        return jsonify({"error": "Invalid data for update", "details": str(ve)}), 400
    except Exception as e:
        app.logger.error(f"Unexpected error in api_update_crush: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


@app.route('/crushes/<int:crush_id>', methods=['DELETE'])
@role_required(required_roles=['user', 'admin'])  # Advisors cannot delete
def api_delete_crush(crush_id):
    cnx = None;
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        user_id_to_use = g.current_user_id
        if g.current_user_role == 'admin':
            crush_to_delete = database_logic.get_crush_details(cursor, crush_id)
            user_id_to_use = crush_to_delete['user_id']
        database_logic.delete_existing_crush_for_user(cursor, cnx, crush_id, user_id_to_use)
        return jsonify({"message": f"Crush with ID {crush_id} deleted successfully."}), 200
    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except Exception as e:
        app.logger.error(f"Unexpected error in api_delete_crush: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


if __name__ == '__main__':
    if not os.getenv('FLASK_SECRET_KEY'):
        print("WARNING: FLASK_SECRET_KEY environment variable not set, using a temporary key for development.")
    if not GEMINI_API_KEY:
        print("WARNING: GEMINI_API_KEY environment variable not set. AI features will be disabled.")
    app.run(debug=True, host='0.0.0.0', port=5000)