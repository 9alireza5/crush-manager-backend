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
        GEMINI_API_KEY = None  # Disable AI if config fails

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
                return jsonify({"message": "Malformed token. Use Bearer scheme."}), 400

        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            g.current_user_id = data['user_id']
            g.current_username = data.get('username', 'User')
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token is invalid!"}), 401

        return f(*args, **kwargs)

    return decorated


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

        if not username or len(username) < 3:
            return jsonify({"error": "Username must be at least 3 characters long"}), 400
        if not email or '@' not in email:
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
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
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
        app.logger.error(f"Unexpected error during login: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


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
            return jsonify({"error": "User profile not found"}), 404
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

        if new_email and ('@' not in new_email or len(new_email) < 5):
            return jsonify({"error": "Invalid email format provided"}), 400

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
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({"error": "Email is required"}), 400

        email_address = data['email']
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        user = database_logic.get_user_by_email(cursor, email_address)

        if user:
            reset_token = database_logic.set_password_reset_token_for_user(cursor, cnx, user['id'])
            app.logger.info(f"Password reset token for {email_address} (user_id {user['id']}): {reset_token}")
            app.logger.info(f"Simulated: Email would be sent to {email_address} with reset token.")
            # In a real app, you would send an email here.
            # e.g., mail_service.send_password_reset_email(user['email'], reset_token)
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
    current_user_id = g.current_user_id
    current_username = g.current_username

    if not GEMINI_API_KEY:
        return jsonify({"error": "AI service is not configured."}), 503

    cnx = None;
    cursor = None
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        user_query = data.get('query')

        if not user_query:
            return jsonify({"error": "A 'query' field is required to ask for advice."}), 400

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()

        user_crush_data_summary = database_logic.get_crushes_summary_for_ai(cursor, current_user_id)

        system_instruction = f"""
        You are "Crush Advisor AI," a specialized assistant for user '{current_username}'.
        Your role is to provide empathetic and constructive advice regarding their personal relationship dynamics,
        based *solely* on the summary of their 'crush' information provided below and their specific query.

        **Strict Operational Guidelines:**
        1.  **Data Exclusivity:** Your advice MUST be based ONLY on the "User's Crush Data Summary" and "User's Query" provided in this prompt. Do NOT invent details, ask for unrelated personal information, or use any external knowledge or any_previous_chat_history.
        2.  **Topic Adherence:** Confine your conversation strictly to relationship advice pertaining to the provided data. If the user attempts to steer the conversation to unrelated topics (e.g., general chat, other life issues, current events, politics, coding help), you MUST politely decline and state that you can only offer advice related to their provided crush information. For example: "I can only provide advice based on the crush information you've shared. How can I help with that?"
        3.  **Privacy First:** Do NOT repeat large sections of the raw "User's Crush Data Summary" back to the user. You can refer to aspects of it generally to inform your advice but avoid echoing sensitive details.
        4.  **Tone & Style:** Maintain a supportive, respectful, empathetic, and non-judgmental tone. Keep responses concise, actionable, and focused. Avoid making definitive predictions or giving absolute commands.
        5.  **No External Actions:** You cannot access external websites, databases, or remember past interactions beyond the current prompt.
        6.  **Safety:** Do not generate harmful, unethical, biased, or inappropriate content.
        """

        prompt_for_gemini = f"""{system_instruction}

        **User's Crush Data Summary:**
        {user_crush_data_summary}

        **User's Query:**
        "{user_query}"

        **Advisor AI's Response (focused, empathetic, and actionable, respecting all guidelines):**
        """

        model = genai.GenerativeModel('gemini-1.5-flash-latest')

        generation_config = genai.types.GenerationConfig(
            max_output_tokens=350,
            temperature=0.75,
        )

        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        ]

        response = model.generate_content(
            prompt_for_gemini,
            generation_config=generation_config,
            safety_settings=safety_settings
        )

        ai_advice = response.text
        return jsonify({"advice": ai_advice}), 200

    except mariadb.Error as dbe:
        app.logger.error(f"Database error in AI advisor: {dbe}")
        return jsonify({"error": "Could not retrieve data for AI advice."}), 500
    except Exception as e:
        app.logger.error(f"Error in AI advisor: {e}", exc_info=True)
        error_message = str(e).lower()
        if "api key not valid" in error_message:
            return jsonify({"error": "AI service authentication failed. Please check configuration."}), 500
        if "quota" in error_message or "rate limit" in error_message:
            return jsonify(
                {"error": "AI service is temporarily unavailable due to high demand. Please try again later."}), 429
        return jsonify({"error": "AI advisor could not process the request."}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


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
        app.logger.error(f"Unexpected error in api_create_crush: {e}", exc_info=True)
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
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 10, type=int)
        if page < 1: page = 1
        if limit < 1: limit = 1
        if limit > 100: limit = 100

        sort_by = request.args.get('sort_by', 'id')
        sort_order = request.args.get('sort_order', 'asc').lower()
        if sort_order not in ['asc', 'desc']:
            sort_order = 'asc'

        filters = {}
        if 'gender' in request.args:
            filters['gender'] = request.args.get('gender')
        if 'name_contains' in request.args:
            filters['name_contains'] = request.args.get('name_contains')

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
            "total_pages": (total_count + limit - 1) // limit
        }), 200
    except mariadb.Error as dbe:
        app.logger.error(f"Database error in api_get_all_crushes: {dbe}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error in api_get_all_crushes: {e}", exc_info=True)
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
        app.logger.error(f"Unexpected error in api_get_crush: {e}", exc_info=True)
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
        app.logger.error(f"Unexpected error in api_update_crush: {e}", exc_info=True)
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
        app.logger.error(f"Unexpected error in api_delete_crush: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
        if cnx: cnx.close()


if __name__ == '__main__':
    if not os.getenv('FLASK_SECRET_KEY'):
        print("WARNING: FLASK_SECRET_KEY environment variable not set, using a temporary key for development.")
    if not GEMINI_API_KEY:
        print(
            "WARNING: GEMINI_API_KEY environment variable not set. AI features will be disabled if not caught earlier.")
    app.run(debug=True, host='0.0.0.0', port=5000)